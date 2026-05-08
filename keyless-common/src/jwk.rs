//! JWK fetching + in-process cache for Google OIDC public keys.
//!
//! Google rotates its JWKs every few weeks and advertises the expected
//! freshness via a `Cache-Control: max-age=...` header on the JWKS
//! response. Without caching we'd hit `googleapis.com/oauth2/v3/certs`
//! on every `/prove` request — several hundred ms of latency (TLS +
//! round-trip to Google) per proof, and a small `DoS` surface if Google
//! rate-limits us.
//!
//! The cache is in-memory, keyed by `kid`, and populated from the full
//! JWKS response (Google returns all currently-active keys on every
//! fetch, so populating them all at once keeps subsequent lookups cheap).
//! Entries carry the response's stated expiry; a lookup for a missing
//! or expired kid triggers a full refetch. If the refetch fails but a
//! stale entry exists, we serve it and log a warning — staleness is
//! better than failing the user's send on a transient Google blip.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use reqwest::header::CACHE_CONTROL;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Default cache TTL when Google's response doesn't expose a usable
/// `Cache-Control: max-age=...`. One hour is well under Google's
/// rotation cadence but high enough to batch proof bursts.
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

/// Upper bound on the cache TTL, regardless of what the server sends.
/// Google has occasionally advertised max-age values in the tens of
/// thousands of seconds; capping keeps us honest about rotating.
const MAX_TTL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    kty: String,
}

#[derive(Debug, Clone)]
struct CachedKey {
    modulus_b64: String,
    expires_at: Instant,
}

/// Errors surfaced by [`JwkCache::get_modulus`].
///
/// `Unavailable` is a transient upstream condition — the JWKS endpoint
/// was unreachable, returned non-2xx, or replied with an unparseable
/// body. Callers should map this to a 503 (service temporarily
/// unavailable) with optional `Retry-After`.
///
/// `KidNotFound` means the JWKS endpoint is healthy and served a valid
/// response, but the requested `kid` isn't in it. That's a client-shape
/// failure — the JWT header pointed at a non-existent key. Callers map
/// to a 400.
#[derive(Debug, Error)]
pub enum JwkError {
    #[error("JWKS endpoint unavailable: {0}")]
    Unavailable(#[source] anyhow::Error),
    #[error("kid {0:?} not found in JWKS")]
    KidNotFound(String),
}

/// In-process JWK cache. Cheap to clone (the backing map is behind an
/// `Arc`), so hand one to every request handler via `AppState`.
#[derive(Clone)]
pub struct JwkCache {
    client: reqwest::Client,
    url: String,
    cache: Arc<RwLock<HashMap<String, CachedKey>>>,
}

impl JwkCache {
    /// Construct a cache pointing at Google's live JWKS endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error only if the underlying HTTP client fails to build.
    pub fn new() -> Result<Self> {
        Self::with_url(GOOGLE_JWKS_URL)
    }

    /// Construct a cache pointing at an arbitrary JWKS URL. Intended for
    /// unit tests that front a mock HTTP server; production always calls
    /// [`JwkCache::new`].
    ///
    /// # Errors
    ///
    /// Returns an error only if the underlying HTTP client fails to build.
    pub fn with_url(url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            client,
            url: url.to_string(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Populate the cache eagerly at startup so the first `/prove`
    /// doesn't pay the JWKS round-trip. A failure here is non-fatal.
    pub async fn prewarm(&self) {
        match self.refresh().await {
            Ok(()) => {
                let n = self.cache.read().await.len();
                tracing::info!(entries = n, "JWK cache prewarmed");
            }
            Err(e) => tracing::warn!(
                err = %format!("{e:#}"),
                "JWK cache prewarm failed; first request will refresh lazily",
            ),
        }
    }

    /// Fetch the base64url-encoded RSA modulus for the given kid,
    /// serving from cache when possible.
    ///
    /// # Errors
    ///
    /// See [`JwkError`].
    pub async fn get_modulus(&self, kid: &str) -> Result<String, JwkError> {
        if let Some(hit) = self.fresh_cached(kid).await {
            return Ok(hit);
        }

        match self.refresh().await {
            Ok(()) => {
                if let Some(hit) = self.fresh_cached(kid).await {
                    Ok(hit)
                } else {
                    Err(JwkError::KidNotFound(kid.to_string()))
                }
            }
            Err(e) => {
                // Refresh failed — fall back to a stale entry if we have one.
                if let Some(hit) = self.any_cached(kid).await {
                    tracing::warn!(
                        kid = %kid,
                        err = %format!("{e:#}"),
                        "JWK refresh failed; serving stale cached modulus",
                    );
                    Ok(hit)
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn fresh_cached(&self, kid: &str) -> Option<String> {
        let guard = self.cache.read().await;
        let entry = guard.get(kid)?;
        if entry.expires_at > Instant::now() {
            Some(entry.modulus_b64.clone())
        } else {
            None
        }
    }

    async fn any_cached(&self, kid: &str) -> Option<String> {
        let guard = self.cache.read().await;
        guard.get(kid).map(|e| e.modulus_b64.clone())
    }

    /// Test-only: force every cached entry to be expired. Used by the
    /// stale-serve regression test to drive `fresh_cached` down the
    /// expired branch without having to wait real wall-clock time.
    ///
    /// # Panics
    ///
    /// Panics if `Instant::now()` is somehow less than 1 second past the
    /// monotonic epoch, which is not reachable in practice.
    #[cfg(test)]
    pub async fn expire_all_for_test(&self) {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("Instant::now() is always past the epoch by more than 1s");
        let mut guard = self.cache.write().await;
        for v in guard.values_mut() {
            v.expires_at = past;
        }
    }

    async fn refresh(&self) -> Result<(), JwkError> {
        let response = self.client.get(&self.url).send().await.map_err(|e| {
            JwkError::Unavailable(anyhow::Error::from(e).context("failed to reach JWKS endpoint"))
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(JwkError::Unavailable(anyhow::anyhow!(
                "JWKS endpoint returned HTTP {status}"
            )));
        }

        let ttl = parse_max_age(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
        )
        .unwrap_or(DEFAULT_TTL)
        .min(MAX_TTL);
        let expires_at = Instant::now() + ttl;

        let jwks: JwkSet = response.json().await.map_err(|e| {
            JwkError::Unavailable(
                anyhow::Error::from(e).context("failed to parse JWKS response body"),
            )
        })?;

        let mut guard = self.cache.write().await;
        guard.clear();
        for jwk in jwks.keys {
            if jwk.kty == "RSA" {
                guard.insert(
                    jwk.kid,
                    CachedKey {
                        modulus_b64: jwk.n,
                        expires_at,
                    },
                );
            }
        }
        tracing::debug!(
            entries = guard.len(),
            ttl_secs = ttl.as_secs(),
            "refreshed JWK cache",
        );
        Ok(())
    }
}

/// Extract the `max-age` directive from a `Cache-Control` header value.
/// Returns `None` if the header is missing, malformed, or contains
/// `no-store` / `no-cache` (we treat those as "don't cache").
fn parse_max_age(header: Option<&str>) -> Option<Duration> {
    let header = header?;
    let mut max_age: Option<Duration> = None;
    for directive in header.split(',') {
        let directive = directive.trim();
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return None;
        }
        if let Some(value) = lower.strip_prefix("max-age=") {
            if let Ok(secs) = value.trim().parse::<u64>() {
                max_age = Some(Duration::from_secs(secs));
            }
        }
    }
    max_age
}

#[cfg(test)]
mod tests {
    use base64::URL_SAFE_NO_PAD;

    use super::*;

    #[test]
    fn parse_max_age_handles_typical_header() {
        assert_eq!(
            parse_max_age(Some("public, max-age=3600, must-revalidate")),
            Some(Duration::from_secs(60 * 60)),
        );
    }

    #[test]
    fn parse_max_age_returns_none_for_no_store() {
        assert_eq!(
            parse_max_age(Some("no-store, max-age=3600")),
            None,
            "no-store short-circuits caching",
        );
    }

    #[test]
    fn parse_max_age_tolerates_missing_header() {
        assert_eq!(parse_max_age(None), None);
        assert_eq!(parse_max_age(Some("public")), None);
    }

    #[tokio::test]
    #[ignore = "hits network"]
    async fn cache_returns_valid_modulus_for_live_kid() {
        // Pull a real kid from Google live first.
        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .get(GOOGLE_JWKS_URL)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let kid = resp["keys"][0]["kid"].as_str().unwrap();

        let cache = JwkCache::new().unwrap();
        let m1 = cache.get_modulus(kid).await.unwrap();
        // Second call should hit cache — same result, no panic.
        let m2 = cache.get_modulus(kid).await.unwrap();
        assert_eq!(m1, m2);

        let bytes = base64::decode_config(&m1, URL_SAFE_NO_PAD).unwrap();
        assert!(
            bytes.len() >= 256,
            "RSA-2048 modulus should be >= 256 bytes"
        );
    }

    #[tokio::test]
    #[ignore = "hits network"]
    async fn cache_errors_for_unknown_kid() {
        let cache = JwkCache::new().unwrap();
        let result = cache.get_modulus("nonexistent-kid-12345").await;
        assert!(matches!(
            result,
            Err(JwkError::KidNotFound(_) | JwkError::Unavailable(_))
        ));
    }
}

#[cfg(test)]
mod typed_error_tests {
    use super::*;
    use base64::URL_SAFE_NO_PAD;
    use serde_json::json;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    /// Produce a JWKS response body with one RSA entry for the given kid.
    fn jwks_with_kid(kid: &str) -> serde_json::Value {
        // A dummy 2048-bit modulus (base64url of 256 zero bytes is fine; the
        // cache doesn't verify the math, only the shape).
        let modulus = base64::encode_config(vec![0u8; 256], URL_SAFE_NO_PAD);
        json!({
            "keys": [
                { "kty": "RSA", "kid": kid, "n": modulus, "e": "AQAB", "alg": "RS256", "use": "sig" }
            ]
        })
    }

    #[tokio::test]
    async fn upstream_500_maps_to_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let cache = JwkCache::with_url(&server.uri()).unwrap();
        match cache.get_modulus("any-kid").await {
            Err(JwkError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_refused_maps_to_unavailable() {
        // Bind a listener, note the URL, then drop it so the port is dead.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let cache = JwkCache::with_url(&url).unwrap();
        match cache.get_modulus("any-kid").await {
            Err(JwkError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_body_maps_to_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let cache = JwkCache::with_url(&server.uri()).unwrap();
        match cache.get_modulus("any-kid").await {
            Err(JwkError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_kid_maps_to_kid_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with_kid("other-kid")))
            .mount(&server)
            .await;

        let cache = JwkCache::with_url(&server.uri()).unwrap();
        match cache.get_modulus("wanted-kid").await {
            Err(JwkError::KidNotFound(kid)) => assert_eq!(kid, "wanted-kid"),
            other => panic!("expected KidNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn present_kid_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_with_kid("wanted-kid")))
            .mount(&server)
            .await;

        let cache = JwkCache::with_url(&server.uri()).unwrap();
        let m = cache
            .get_modulus("wanted-kid")
            .await
            .expect("should resolve");
        assert_eq!(m, base64::encode_config(vec![0u8; 256], URL_SAFE_NO_PAD));
    }

    #[tokio::test]
    async fn stale_entry_served_when_refresh_fails() {
        // Populate cache with a regular max-age so the first call returns Ok
        // via the normal path (not stale-serve). Then force all entries to
        // be marked expired via the test-only `expire_all_for_test()` seam,
        // swap the mock to 500, and the next lookup will trigger refresh →
        // fail → fall through to any_cached and return the stale modulus.
        let server = MockServer::start().await;
        let first_mock = Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("cache-control", "max-age=3600")
                    .set_body_json(jwks_with_kid("stale-kid")),
            )
            .up_to_n_times(1)
            .mount_as_scoped(&server)
            .await;

        let cache = JwkCache::with_url(&server.uri()).unwrap();
        let first = cache
            .get_modulus("stale-kid")
            .await
            .expect("first hit fills cache");

        // Mark the cached entry stale, then drop the 200 mock and serve 500
        // for subsequent requests.
        cache.expire_all_for_test().await;
        drop(first_mock);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let second = cache
            .get_modulus("stale-kid")
            .await
            .expect("stale-serve must succeed");
        assert_eq!(first, second);
    }
}
