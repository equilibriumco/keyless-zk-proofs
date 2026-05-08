use std::{collections::HashSet, sync::Arc};

use aptos_keyless_common::{
    observability::mark_handler_ran,
    rate_limit::{IpLimiter, SubLimiter},
    JwkCache,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use zeroize::Zeroizing;

use crate::{
    pepper::derive_pepper,
    types::{ErrorResponse, PepperRequest, PepperResponse},
    verify::verify_jwt,
};

#[derive(Clone)]
pub struct AppState {
    /// HMAC key for pepper derivation. The `Zeroizing` wrapper ensures the
    /// key bytes are zeroed when the last `Arc` reference drops (process
    /// shutdown / test teardown). The `hmac` crate's per-call ipad/opad
    /// expansion is not zeroized but its lifetime is bounded by each
    /// `pepper_inner` call.
    pub secret: Arc<Zeroizing<Vec<u8>>>,
    pub jwk_cache: JwkCache,
    pub allowed_iss: Arc<HashSet<String>>,
    /// Per-IP rate limiter. `None` disables the dimension.
    pub ip_limiter: Option<Arc<IpLimiter>>,
    /// Per-`(iss, sub)` rate limiter. `None` disables the dimension.
    pub sub_limiter: Option<Arc<SubLimiter>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PepperError {
    #[error("rate limit exceeded (per-sub); retry after {retry_after_secs}s")]
    RateLimitedSub { retry_after_secs: u32 },

    /// JWT-shape client fault — wire body is constant `"invalid or expired JWT"`.
    #[error("{0:#}")]
    BadRequest(#[source] anyhow::Error),

    /// Transient upstream failure (JWKS endpoint). Wire body is constant
    /// `"service temporarily unavailable"`.
    #[error("upstream unavailable")]
    UpstreamUnavailable {
        retry_after_secs: Option<u32>,
        #[source]
        source: anyhow::Error,
    },

    /// Server bug (HMAC crash, etc). Wire body is constant `"internal error"`.
    #[error("{0:#}")]
    Internal(#[from] anyhow::Error),
}

/// Rate-limit gate for the pepper handler.
///
/// Must be called only after `verify_jwt` has succeeded, so that
/// `(iss, sub)` is a verified identity and cannot be used by a forged
/// JWT to drain a real user's bucket.
///
/// # Errors
///
/// Returns [`PepperError::RateLimitedSub`] when the `(iss, sub)` pair has
/// exceeded its configured per-minute quota.
pub fn gate(state: &AppState, iss: &str, sub: &str) -> Result<(), PepperError> {
    let skey = aptos_keyless_common::rate_limit::sub_key(iss, sub);
    if let Err(aptos_keyless_common::rate_limit::Denied::TooFast { retry_after_secs }) =
        aptos_keyless_common::rate_limit::check_sub(state.sub_limiter.as_deref(), skey)
    {
        tracing::warn!(
            error_kind = "rate_limited_sub",
            key = %hex::encode(skey),
            retry_after_secs,
            "denied",
        );
        return Err(PepperError::RateLimitedSub { retry_after_secs });
    }
    Ok(())
}

#[allow(clippy::unused_async)]
pub async fn health() -> &'static str {
    "ok"
}

async fn pepper_inner(
    state: &AppState,
    body: &PepperRequest,
) -> Result<PepperResponse, PepperError> {
    let parsed = aptos_keyless_common::parse_jwt(&body.jwt).map_err(PepperError::BadRequest)?;

    verify_jwt(&state.jwk_cache, &state.allowed_iss, &parsed, &body.jwt)
        .await
        .map_err(|e| match e {
            crate::verify::VerifyJwtError::JwksUnavailable(inner) => {
                PepperError::UpstreamUnavailable {
                    retry_after_secs: None,
                    source: inner,
                }
            }
            other @ (crate::verify::VerifyJwtError::KidNotFound(_)
            | crate::verify::VerifyJwtError::BadJwt(_)) => {
                PepperError::BadRequest(anyhow::Error::new(other))
            }
        })?;

    // Per-`(iss, sub)` rate limit, now that `sub` is trusted.
    gate(state, &parsed.payload.iss, &parsed.payload.sub)?;

    let pepper = derive_pepper(&state.secret, &parsed.payload.sub, &parsed.payload.aud)
        .map_err(PepperError::Internal)?;
    Ok(PepperResponse {
        pepper: hex::encode(pepper),
    })
}

impl PepperError {
    /// Stable taxonomy label used as the `error_kind` span field.
    /// Pepper-service collapses JWT parse + signature/kid lookup failures
    /// into a single `bad_request` variant by design (matching the constant
    /// wire body `"invalid or expired JWT"`), so there is no separate
    /// `bad_jwt` label on this service.
    #[must_use]
    pub fn error_kind(&self) -> &'static str {
        match self {
            PepperError::BadRequest(_) => "bad_request",
            PepperError::RateLimitedSub { .. } => "rate_limited_sub",
            PepperError::UpstreamUnavailable { .. } => "upstream_unavailable",
            PepperError::Internal(_) => "internal",
        }
    }
}

impl PepperError {
    /// Render this error as an HTTP response. Same-file submodule tests
    /// call this directly; no public wrapper needed.
    pub(crate) fn into_response_inner(self) -> axum::response::Response {
        use axum::http::StatusCode;
        match self {
            PepperError::RateLimitedSub { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_after_secs.to_string())],
                Json(ErrorResponse {
                    error: "rate limit exceeded".into(),
                }),
            )
                .into_response(),
            PepperError::BadRequest(err) => {
                tracing::info!(error_kind = "bad_request", err = %format!("{err:#}"), "rejected");
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid or expired JWT".into(),
                    }),
                )
                    .into_response()
            }
            PepperError::UpstreamUnavailable {
                retry_after_secs,
                source,
            } => {
                tracing::warn!(
                    error_kind = "upstream_unavailable",
                    err = %format!("{source:#}"),
                    "upstream failure"
                );
                let mut resp = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "service temporarily unavailable".into(),
                    }),
                )
                    .into_response();
                if let Some(secs) = retry_after_secs {
                    resp.headers_mut().insert(
                        "retry-after",
                        axum::http::HeaderValue::from_str(&secs.to_string()).unwrap(),
                    );
                }
                resp
            }
            PepperError::Internal(err) => {
                tracing::error!(error_kind = "internal", err = %format!("{err:#}"), "pepper handler bug");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "internal error".into(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

pub async fn pepper(
    State(state): State<AppState>,
    Json(body): Json<PepperRequest>,
) -> axum::response::Response {
    let mut resp = match pepper_inner(&state, &body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            tracing::Span::current().record("error_kind", e.error_kind());
            e.into_response_inner()
        }
    };
    mark_handler_ran(&mut resp);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_state() -> AppState {
        AppState {
            secret: Arc::new(zeroize::Zeroizing::new(vec![0u8; 32])),
            jwk_cache: JwkCache::new().unwrap(),
            allowed_iss: Arc::new(HashSet::new()),
            ip_limiter: None,
            sub_limiter: None,
        }
    }

    #[tokio::test]
    async fn gate_denies_second_call_for_same_iss_sub() {
        let mut state = test_state();
        state.sub_limiter = aptos_keyless_common::rate_limit::build_sub_limiter(60, 1).unwrap();
        gate(&state, "https://accounts.google.com", "user-123").expect("first call passes");
        match gate(&state, "https://accounts.google.com", "user-123") {
            Err(PepperError::RateLimitedSub { retry_after_secs }) => {
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected RateLimitedSub, got {other:?}"),
        }
    }

    #[test]
    fn gate_distinct_subs_do_not_share_buckets() {
        let mut state = test_state();
        state.sub_limiter = aptos_keyless_common::rate_limit::build_sub_limiter(60, 1).unwrap();
        gate(&state, "iss", "a").expect("sub=a");
        gate(&state, "iss", "b").expect("sub=b");
    }

    /// Security invariant: a forged JWT that fails signature verification
    /// must NOT charge the victim's `(iss, sub)` rate-limit bucket. This is
    /// the central reason `gate()` runs after `verify_jwt()` rather than
    /// before it — otherwise an attacker could lock out any target user by
    /// sending JWTs with that user's `sub`.
    ///
    /// We use an `alg=HS256` header, which `verify_jwt` rejects before any
    /// JWK lookup (so the test needs no network).
    #[tokio::test]
    async fn forged_jwt_does_not_charge_sub_bucket() {
        use base64::URL_SAFE_NO_PAD;

        let mut state = test_state();
        state.sub_limiter = aptos_keyless_common::rate_limit::build_sub_limiter(60, 1).unwrap();
        state.allowed_iss = Arc::new(HashSet::from(["https://accounts.google.com".to_string()]));

        let iss = "https://accounts.google.com";
        let sub = "victim-user-123";
        let header = base64::encode_config(
            r#"{"alg":"HS256","kid":"fake","typ":"JWT"}"#,
            URL_SAFE_NO_PAD,
        );
        let payload = base64::encode_config(
            format!(
                r#"{{"iss":"{iss}","sub":"{sub}","aud":"some-client","nonce":"n","iat":1,"exp":9999999999}}"#
            ),
            URL_SAFE_NO_PAD,
        );
        let sig = base64::encode_config("fake", URL_SAFE_NO_PAD);
        let forged = format!("{header}.{payload}.{sig}");

        let request = PepperRequest { jwt: forged };
        let result = pepper_inner(&state, &request).await;
        assert!(
            matches!(result, Err(PepperError::BadRequest(_))),
            "forged JWT must be rejected, got {result:?}",
        );

        // The bucket must still have its burst intact: the first real call
        // for the same (iss, sub) must succeed. If the forged attempt had
        // charged the bucket, this would fail with RateLimitedSub.
        gate(&state, iss, sub).expect(
            "forged request must not have charged the sub bucket — gate() should still admit the \
             first real call",
        );
    }

    #[test]
    fn error_kind_covers_all_variants() {
        let cases: Vec<(PepperError, &'static str)> = vec![
            (PepperError::BadRequest(anyhow::anyhow!("x")), "bad_request"),
            (
                PepperError::RateLimitedSub {
                    retry_after_secs: 1,
                },
                "rate_limited_sub",
            ),
            (
                PepperError::UpstreamUnavailable {
                    retry_after_secs: None,
                    source: anyhow::anyhow!("x"),
                },
                "upstream_unavailable",
            ),
            (PepperError::Internal(anyhow::anyhow!("x")), "internal"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.error_kind(), expected, "variant {err:?}");
        }
    }

    #[cfg(test)]
    mod handler_mapping_tests {
        use super::*;
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

        fn router(state: AppState) -> axum::Router {
            axum::Router::new()
                .route("/pepper", axum::routing::post(pepper))
                .with_state(state)
        }

        async fn post_pepper(
            router: axum::Router,
            jwt: &str,
        ) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
            let body = serde_json::to_vec(&serde_json::json!({"jwt": jwt})).unwrap();
            let req = Request::builder()
                .method("POST")
                .uri("/pepper")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec();
            (status, body, headers)
        }

        async fn parts(
            resp: axum::response::Response,
        ) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = axum::body::to_bytes(resp.into_body(), 4096)
                .await
                .unwrap()
                .to_vec();
            (status, body, headers)
        }

        #[tokio::test]
        async fn forged_jwt_returns_400_with_constant_body() {
            use base64::URL_SAFE_NO_PAD;
            let mut state = test_state();
            state.allowed_iss =
                Arc::new(HashSet::from(["https://accounts.google.com".to_string()]));

            // HS256 header forces verify_jwt to reject before any JWK lookup.
            let header = base64::encode_config(
                r#"{"alg":"HS256","kid":"fake","typ":"JWT"}"#,
                URL_SAFE_NO_PAD,
            );
            let payload = base64::encode_config(
                r#"{"iss":"https://accounts.google.com","sub":"s","aud":"a","nonce":"n","iat":1,"exp":9999999999}"#,
                URL_SAFE_NO_PAD,
            );
            let sig = base64::encode_config("fake", URL_SAFE_NO_PAD);
            let forged = format!("{header}.{payload}.{sig}");

            let (status, body, _) = post_pepper(router(state), &forged).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, br#"{"error":"invalid or expired JWT"}"#);
        }

        #[tokio::test]
        async fn jwks_500_returns_503_with_constant_body() {
            use base64::URL_SAFE_NO_PAD;
            let jwks_server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&jwks_server)
                .await;

            let mut state = test_state();
            state.jwk_cache = JwkCache::with_url(&jwks_server.uri()).unwrap();
            state.allowed_iss =
                Arc::new(HashSet::from(["https://accounts.google.com".to_string()]));

            // RS256 header reaches the JWK lookup, which fails with Unavailable.
            let header = base64::encode_config(
                r#"{"alg":"RS256","kid":"any","typ":"JWT"}"#,
                URL_SAFE_NO_PAD,
            );
            let payload = base64::encode_config(
                r#"{"iss":"https://accounts.google.com","sub":"s","aud":"a","nonce":"n","iat":1,"exp":9999999999}"#,
                URL_SAFE_NO_PAD,
            );
            let sig = base64::encode_config(vec![0u8; 256], URL_SAFE_NO_PAD);
            let jwt = format!("{header}.{payload}.{sig}");

            let (status, body, _) = post_pepper(router(state), &jwt).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, br#"{"error":"service temporarily unavailable"}"#);
        }

        #[tokio::test]
        async fn internal_variant_renders_500() {
            // Submodule tests can call the crate-private `into_response_inner`
            // directly — no `pub` helper needed on the error type.
            let resp = PepperError::Internal(anyhow::anyhow!("boom")).into_response_inner();
            let (status, body, _) = parts(resp).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(body, br#"{"error":"internal error"}"#);
        }
    }
}

#[cfg(test)]
mod request_id_tests {
    use super::*;
    use aptos_keyless_common::observability::{http_trace_layer, request_id_layers};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::URL_SAFE_NO_PAD;
    use tower::ServiceExt;
    use tower_http::request_id::MakeRequestUuid;

    fn router_with_layers(state: AppState) -> axum::Router {
        let (set_id, propagate_id) = request_id_layers(MakeRequestUuid);
        axum::Router::new()
            .route("/pepper", axum::routing::post(pepper))
            .layer(propagate_id)
            .layer(http_trace_layer())
            .layer(set_id)
            .with_state(state)
    }

    fn test_state() -> AppState {
        AppState {
            secret: Arc::new(zeroize::Zeroizing::new(vec![0u8; 32])),
            jwk_cache: JwkCache::new().unwrap(),
            allowed_iss: Arc::new(HashSet::from(["https://accounts.google.com".into()])),
            ip_limiter: None,
            sub_limiter: None,
        }
    }

    #[tokio::test]
    async fn pepper_service_honours_inbound_x_request_id() {
        let header = base64::encode_config(
            r#"{"alg":"HS256","kid":"fake","typ":"JWT"}"#,
            URL_SAFE_NO_PAD,
        );
        let payload = base64::encode_config(
            r#"{"iss":"https://accounts.google.com","sub":"s","aud":"a","nonce":"n","iat":1,"exp":9999999999}"#,
            URL_SAFE_NO_PAD,
        );
        let sig = base64::encode_config("fake", URL_SAFE_NO_PAD);
        let forged = format!("{header}.{payload}.{sig}");

        let body = serde_json::to_vec(&serde_json::json!({"jwt": forged})).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/pepper")
            .header("content-type", "application/json")
            .header("x-request-id", "caller-chosen-id")
            .body(Body::from(body))
            .unwrap();

        let resp = router_with_layers(test_state()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers().get("x-request-id").unwrap(),
            "caller-chosen-id",
            "pepper-service must honour inbound x-request-id",
        );
    }

    #[tokio::test]
    async fn pepper_service_generates_x_request_id_when_absent() {
        let header = base64::encode_config(
            r#"{"alg":"HS256","kid":"fake","typ":"JWT"}"#,
            URL_SAFE_NO_PAD,
        );
        let payload = base64::encode_config(
            r#"{"iss":"https://accounts.google.com","sub":"s","aud":"a","nonce":"n","iat":1,"exp":9999999999}"#,
            URL_SAFE_NO_PAD,
        );
        let sig = base64::encode_config("fake", URL_SAFE_NO_PAD);
        let forged = format!("{header}.{payload}.{sig}");

        let body = serde_json::to_vec(&serde_json::json!({"jwt": forged})).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/pepper")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = router_with_layers(test_state()).oneshot(req).await.unwrap();
        let id = resp
            .headers()
            .get("x-request-id")
            .expect("should be present")
            .to_str()
            .unwrap();
        let parsed = uuid::Uuid::parse_str(id).expect("id must parse as UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "MakeRequestUuid must emit UUIDv4, got {id:?}",
        );
    }
}
