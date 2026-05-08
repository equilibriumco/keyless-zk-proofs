use std::{collections::HashSet, env, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use aptos_keyless_common::{
    observability::{http_trace_layer, request_id_layers},
    rate_limit::{self, IpLimitState},
    JwkCache,
};
use axum::{extract::DefaultBodyLimit, middleware, routing, Router};
use pepper_service::{
    api::{self, AppState},
    secret::load_secret,
};
use tower_http::request_id::MakeRequestUuid;

fn env_or<T: FromStr>(name: &str, default: T) -> T
where
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(raw) => raw.parse().unwrap_or_else(|e| {
            panic!("{name}={raw:?} failed to parse: {e}");
        }),
        Err(_) => default,
    }
}

#[tokio::main]
async fn main() {
    aptos_keyless_common::observability::init();

    let addr = env::var("PEPPER_ADDR").unwrap_or_else(|_| "0.0.0.0:3002".to_string());

    let loaded = load_secret().expect("failed to load pepper secret");
    tracing::info!(
        "pepper secret loaded ({} bytes) from: {}",
        loaded.bytes.len(),
        loaded.source,
    );

    let jwk_cache = JwkCache::new().expect("failed to build JWK cache HTTP client");
    jwk_cache.prewarm().await;

    let allowed_iss_raw = env::var("PEPPER_ALLOWED_ISS")
        .unwrap_or_else(|_| "https://accounts.google.com".to_string());
    let allowed_iss: HashSet<String> = allowed_iss_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed_iss.is_empty() {
        tracing::warn!("PEPPER_ALLOWED_ISS is empty — accepting JWTs from ANY issuer.");
    } else {
        tracing::info!(issuers = ?allowed_iss, "JWT issuer allowlist loaded");
    }

    let ip_per_min: u32 = env_or("PEPPER_RL_IP_PER_MIN", 30);
    let ip_burst: u32 = env_or("PEPPER_RL_IP_BURST", 10);
    let sub_per_min: u32 = env_or("PEPPER_RL_SUB_PER_MIN", 10);
    let sub_burst: u32 = env_or("PEPPER_RL_SUB_BURST", 5);
    let body_limit_bytes: usize = env_or("PEPPER_BODY_LIMIT_BYTES", 8192);

    let ip_limiter = rate_limit::build_ip_limiter(ip_per_min, ip_burst)
        .unwrap_or_else(|e| panic!("invalid PEPPER_RL_IP_*: {e}"));
    let sub_limiter = rate_limit::build_sub_limiter(sub_per_min, sub_burst)
        .unwrap_or_else(|e| panic!("invalid PEPPER_RL_SUB_*: {e}"));
    if ip_limiter.is_none() {
        tracing::warn!("PEPPER_RL_IP_PER_MIN=0 — per-IP rate limit disabled");
    }
    if sub_limiter.is_none() {
        tracing::warn!("PEPPER_RL_SUB_PER_MIN=0 — per-sub rate limit disabled");
    }

    let trusted = rate_limit::parse_trusted_proxies(
        &env::var("PEPPER_TRUSTED_PROXY_CIDRS").unwrap_or_default(),
    )
    .unwrap_or_else(|e| panic!("invalid PEPPER_TRUSTED_PROXY_CIDRS: {e}"));
    if trusted.is_empty() {
        tracing::warn!(
            "PEPPER_TRUSTED_PROXY_CIDRS is empty — per-IP limit uses peer address. \
             Set this if deployed behind an L7 proxy."
        );
    }

    let state = AppState {
        secret: Arc::new(loaded.bytes),
        jwk_cache,
        allowed_iss: Arc::new(allowed_iss),
        ip_limiter: ip_limiter.clone(),
        sub_limiter: sub_limiter.clone(),
    };

    let ip_for_gc = ip_limiter.clone();
    let sub_for_gc = sub_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
            if let Some(l) = &ip_for_gc {
                l.retain_recent();
            }
            if let Some(l) = &sub_for_gc {
                l.retain_recent();
            }
        }
    });

    let ip_state = IpLimitState {
        limiter: ip_limiter,
        trusted_proxies: Arc::new(trusted),
    };

    let protected = Router::new()
        .route("/pepper", routing::post(api::pepper))
        .layer(middleware::from_fn_with_state(
            ip_state,
            rate_limit::ip_limit_middleware,
        ))
        .layer(DefaultBodyLimit::max(body_limit_bytes));

    // No CORS layer — pepper-service is internal-only (the prover talks to
    // it server-to-server over the docker-compose network; no host port
    // mapping). Cross-origin browser callers shouldn't be reaching this
    // service in the first place.
    let (set_request_id, propagate_request_id) = request_id_layers(MakeRequestUuid);
    let app = Router::new()
        .route("/health", routing::get(api::health))
        .merge(protected)
        .layer(propagate_request_id)
        .layer(http_trace_layer())
        .layer(set_request_id)
        .with_state(state);

    tracing::info!("pepper-service listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind listener");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}
