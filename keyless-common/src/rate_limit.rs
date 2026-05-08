//! Rate limiting primitives shared by the prover and pepper-service.

use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{
    clock::{Clock as _, DefaultClock},
    state::keyed::DashMapStateStore,
    NotUntil, Quota, RateLimiter,
};
use ipnet::IpNet;
use sha2::{Digest, Sha256};

/// Stable 32-byte bucket key for the `(iss, sub)` pair.
///
/// Hashing (a) bounds `DashMap` memory to 32 bytes per bucket regardless of
/// attacker-controlled JWT content, (b) keeps raw PII out of logs, and (c)
/// isolates buckets across issuers (prevents `sub=123` from issuer A
/// sharing state with `sub=123` from issuer B).
#[must_use]
pub fn sub_key(iss: &str, sub: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(iss.as_bytes());
    hasher.update([0u8]);
    hasher.update(sub.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod sub_key_tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(sub_key("iss", "sub"), sub_key("iss", "sub"));
    }

    #[test]
    fn issuer_isolation() {
        assert_ne!(
            sub_key("https://accounts.google.com", "123"),
            sub_key("https://appleid.apple.com", "123"),
        );
    }

    #[test]
    fn sub_isolation() {
        assert_ne!(sub_key("iss", "a"), sub_key("iss", "b"));
    }

    #[test]
    fn separator_defeats_concat_collision() {
        assert_ne!(sub_key("ab", "c"), sub_key("a", "bc"));
    }
}

pub type IpLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;
pub type SubLimiter = RateLimiter<[u8; 32], DashMapStateStore<[u8; 32]>, DefaultClock>;

type DefaultInstant = <DefaultClock as governor::clock::Clock>::Instant;

/// Reason a rate-limit check denied a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    TooFast { retry_after_secs: u32 },
}

fn quota_from(per_minute: u32, burst: u32) -> Result<Quota, String> {
    if per_minute == 0 {
        return Err("per_minute must be > 0 (use None to disable)".into());
    }
    if burst == 0 {
        return Err("burst must be > 0 when per_minute > 0".into());
    }
    let min_burst = per_minute.div_ceil(60);
    if burst < min_burst {
        return Err(format!(
            "burst {burst} < ceil(per_minute/60) = {min_burst}; single-shot usage would be rate-limited",
        ));
    }
    let pm = NonZeroU32::new(per_minute).expect("checked > 0 above");
    let b = NonZeroU32::new(burst).expect("checked > 0 above");
    Ok(Quota::per_minute(pm).allow_burst(b))
}

/// Build an IP-keyed limiter. Returns `Ok(None)` when `per_minute == 0`.
///
/// # Errors
///
/// See [`quota_from`] for validation rules.
pub fn build_ip_limiter(per_minute: u32, burst: u32) -> Result<Option<Arc<IpLimiter>>, String> {
    if per_minute == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(RateLimiter::dashmap(quota_from(
        per_minute, burst,
    )?))))
}

/// Build a sub-keyed limiter. Returns `Ok(None)` when `per_minute == 0`.
///
/// # Errors
///
/// See [`quota_from`].
pub fn build_sub_limiter(per_minute: u32, burst: u32) -> Result<Option<Arc<SubLimiter>>, String> {
    if per_minute == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(RateLimiter::dashmap(quota_from(
        per_minute, burst,
    )?))))
}

fn wait_secs(nu: &NotUntil<DefaultInstant>) -> u32 {
    let d = nu.wait_time_from(DefaultClock::default().now());
    u32::try_from(d.as_secs().max(1)).unwrap_or(u32::MAX)
}

/// Check whether a request from the given IP is allowed by the limiter.
///
/// # Errors
///
/// Returns [`Denied::TooFast`] with the number of seconds to wait if the
/// rate limit has been exceeded.
pub fn check_ip(limiter: Option<&IpLimiter>, ip: IpAddr) -> Result<(), Denied> {
    let Some(limiter) = limiter else {
        return Ok(());
    };
    match limiter.check_key(&ip) {
        Ok(()) => Ok(()),
        Err(nu) => Err(Denied::TooFast {
            retry_after_secs: wait_secs(&nu),
        }),
    }
}

/// Check whether a request from the given subscriber key is allowed by the limiter.
///
/// # Errors
///
/// Returns [`Denied::TooFast`] with the number of seconds to wait if the
/// rate limit has been exceeded.
pub fn check_sub(limiter: Option<&SubLimiter>, key: [u8; 32]) -> Result<(), Denied> {
    let Some(limiter) = limiter else {
        return Ok(());
    };
    match limiter.check_key(&key) {
        Ok(()) => Ok(()),
        Err(nu) => Err(Denied::TooFast {
            retry_after_secs: wait_secs(&nu),
        }),
    }
}

#[cfg(test)]
mod limiter_tests {
    use super::*;

    #[test]
    fn per_min_zero_returns_none() {
        assert!(build_ip_limiter(0, 5).unwrap().is_none());
        assert!(build_sub_limiter(0, 5).unwrap().is_none());
    }

    #[test]
    fn burst_zero_rejected() {
        assert!(build_ip_limiter(10, 0).is_err());
        assert!(build_sub_limiter(10, 0).is_err());
    }

    #[test]
    fn burst_too_small_rejected() {
        assert!(build_ip_limiter(120, 1).is_err()); // 120/min = 2/s → burst must be >= 2.
        assert!(build_ip_limiter(120, 2).is_ok());
    }

    #[test]
    fn ip_limiter_allows_burst_and_denies_next() {
        let limiter = build_ip_limiter(60, 3).unwrap().unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(check_ip(Some(&limiter), ip).is_ok());
        }
        match check_ip(Some(&limiter), ip) {
            Err(Denied::TooFast { retry_after_secs }) => assert!(retry_after_secs >= 1),
            other => panic!("expected TooFast, got {other:?}"),
        }
    }

    #[test]
    fn distinct_keys_do_not_share_buckets() {
        let limiter = build_sub_limiter(60, 1).unwrap().unwrap();
        let k1 = sub_key("iss", "a");
        let k2 = sub_key("iss", "b");
        assert!(check_sub(Some(&limiter), k1).is_ok());
        assert!(check_sub(Some(&limiter), k2).is_ok());
    }

    #[test]
    fn none_limiter_always_passes() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..100 {
            assert!(check_ip(None, ip).is_ok());
        }
    }
}

/// Parse a comma-separated CIDR list. Empty string → empty vec.
///
/// # Errors
///
/// Returns the first malformed entry with its index.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpNet>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(i, s)| {
            s.parse::<IpNet>()
                .map_err(|e| format!("entry {i} ({s:?}): {e}"))
        })
        .collect()
}

fn is_trusted(trusted: &[IpNet], ip: IpAddr) -> bool {
    trusted.iter().any(|n| n.contains(&ip))
}

/// Resolve the "real" client IP for rate-limiting.
///
/// * `trusted_proxies` empty → always return `peer`.
/// * `peer` outside every trusted CIDR → return `peer` (defence against
///   a client that forges XFF when no proxy sits in front).
/// * Otherwise walk `xff_header` right-to-left, skipping trusted entries,
///   return first untrusted. All entries trusted / header absent / garbage
///   → return `peer`.
#[must_use]
pub fn resolve_client_ip(
    peer: IpAddr,
    trusted_proxies: &[IpNet],
    xff_header: Option<&str>,
) -> IpAddr {
    if trusted_proxies.is_empty() || !is_trusted(trusted_proxies, peer) {
        return peer;
    }
    let Some(header) = xff_header else {
        return peer;
    };
    for entry in header.split(',').rev().map(str::trim) {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            if !is_trusted(trusted_proxies, ip) {
                return ip;
            }
        }
    }
    peer
}

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// State carried by the IP-limit middleware layer.
#[must_use]
#[derive(Clone)]
pub struct IpLimitState {
    /// Optional per-IP rate limiter; `None` disables IP limiting.
    pub limiter: Option<Arc<IpLimiter>>,
    /// CIDRs whose `X-Forwarded-For` headers are trusted for IP resolution.
    pub trusted_proxies: Arc<Vec<IpNet>>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

/// Axum middleware that enforces per-IP rate limits.
///
/// Resolves the real client IP using `X-Forwarded-For` when the peer is a
/// trusted proxy, then checks it against the shared [`IpLimiter`]. Returns
/// `429 Too Many Requests` with a `retry-after` header when the limit is
/// exceeded. Passes the request through unchanged when `limiter` is `None`.
///
/// # Panics
///
/// Never panics in practice — the internal `.unwrap()` on `HeaderValue::from_str`
/// is unreachable because a `u32` decimal string is always valid ASCII.
pub async fn ip_limit_middleware(
    axum::extract::State(state): axum::extract::State<IpLimitState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ip = resolve_client_ip(peer.ip(), &state.trusted_proxies, xff.as_deref());
    match check_ip(state.limiter.as_deref(), ip) {
        Ok(()) => next.run(request).await,
        Err(Denied::TooFast { retry_after_secs }) => {
            tracing::Span::current().record("error_kind", "rate_limited_ip");
            tracing::warn!(
                error_kind = "rate_limited_ip",
                key = %ip,
                retry_after_secs,
                "denied",
            );
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorBody {
                    error: "rate limit exceeded",
                }),
            )
                .into_response();
            resp.headers_mut().insert(
                "retry-after",
                HeaderValue::from_str(&retry_after_secs.to_string()).unwrap(),
            );
            resp
        }
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_empty() {
        assert!(parse_trusted_proxies("").unwrap().is_empty());
        assert!(parse_trusted_proxies("  ").unwrap().is_empty());
    }

    #[test]
    fn parses_list() {
        assert_eq!(
            parse_trusted_proxies("10.0.0.0/8, 192.168.1.1/32")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_trusted_proxies("not-a-cidr").is_err());
    }

    #[test]
    fn empty_trusted_returns_peer() {
        let r = resolve_client_ip(ip("1.2.3.4"), &[], Some("5.6.7.8"));
        assert_eq!(r, ip("1.2.3.4"));
    }

    #[test]
    fn peer_outside_trusted_ignores_xff() {
        let trusted = parse_trusted_proxies("10.0.0.0/8").unwrap();
        let r = resolve_client_ip(ip("1.2.3.4"), &trusted, Some("5.6.7.8"));
        assert_eq!(r, ip("1.2.3.4"));
    }

    #[test]
    fn peer_in_trusted_returns_first_untrusted_from_xff() {
        let trusted = parse_trusted_proxies("10.0.0.0/8").unwrap();
        let r = resolve_client_ip(ip("10.0.0.1"), &trusted, Some("1.2.3.4, 10.0.0.2"));
        assert_eq!(r, ip("1.2.3.4"));
    }

    #[test]
    fn all_xff_trusted_returns_peer() {
        let trusted = parse_trusted_proxies("10.0.0.0/8").unwrap();
        let r = resolve_client_ip(ip("10.0.0.1"), &trusted, Some("10.0.0.2, 10.0.0.3"));
        assert_eq!(r, ip("10.0.0.1"));
    }

    #[test]
    fn garbage_xff_returns_peer() {
        let trusted = parse_trusted_proxies("10.0.0.0/8").unwrap();
        let r = resolve_client_ip(ip("10.0.0.1"), &trusted, Some("garbage"));
        assert_eq!(r, ip("10.0.0.1"));
    }
}

#[cfg(test)]
mod middleware_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn test_app(state: IpLimitState) -> Router {
        Router::new()
            .route("/t", get(ok))
            .layer(middleware::from_fn_with_state(state, ip_limit_middleware))
    }

    fn req_from(ip: IpAddr) -> Request<Body> {
        let addr = SocketAddr::new(ip, 65000);
        let mut r = Request::builder().uri("/t").body(Body::empty()).unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    }

    #[tokio::test]
    async fn allows_within_burst_and_429s_after() {
        let state = IpLimitState {
            limiter: build_ip_limiter(60, 2).unwrap(),
            trusted_proxies: Arc::new(vec![]),
        };
        let app = test_app(state);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..2 {
            let r = app.clone().oneshot(req_from(ip)).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }
        let r = app.oneshot(req_from(ip)).await.unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.headers().contains_key("retry-after"));

        // Body must NOT leak the bucketing dimension.
        let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), br#"{"error":"rate limit exceeded"}"#);
    }

    #[tokio::test]
    async fn none_limiter_passes_everything() {
        let state = IpLimitState {
            limiter: None,
            trusted_proxies: Arc::new(vec![]),
        };
        let app = test_app(state);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..100 {
            let r = app.clone().oneshot(req_from(ip)).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }
    }
}
