// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use aptos_keyless_common::rate_limit::{self, ip_limit_middleware, IpLimitState, IpLimiter};
use aptos_logger::{error, info, warn};
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use prover_service::external_resources::prover_config::ProverServiceConfig;
use prover_service::external_resources::{jwk_fetcher, prover_config};
use prover_service::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use prover_service::request_handler::{deployment_information, handler, prover_handler};
use prover_service::*;
use std::time::Instant;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The prover service config file path
    #[arg(long)]
    config_file_path: String,

    /// The training wheels private key file path
    #[arg(long)]
    training_wheels_private_key_file_path: String,
}

#[tokio::main]
async fn main() {
    // Fetch the command line arguments
    let args = Args::parse();

    // Start the Aptos logger
    aptos_logger::Logger::new().init();
    info!("Starting the Prover service...");

    // Load the training wheels key pair
    let training_wheels_key_pair =
        load_training_wheels_key_pair(&args.training_wheels_private_key_file_path);

    // Load the prover service config
    let prover_service_config = prover_config::load_prover_service_config(&args.config_file_path);

    // Get the deployment information
    let deployment_information = deployment_information::get_deployment_information(
        training_wheels_key_pair.verification_key(),
    );

    // Start the JWK fetchers
    let (jwk_cache, federated_jwks) = jwk_fetcher::start_jwk_fetchers(
        prover_service_config.jwk_issuers.clone(),
        Duration::from_secs(prover_service_config.jwk_refresh_rate_secs),
    );

    // Create the prover service state
    let prover_service_state = Arc::new(ProverServiceState::init(
        training_wheels_key_pair,
        prover_service_config.clone(),
        deployment_information,
        jwk_cache,
        federated_jwks,
    ));

    // Load the verification key
    load_verification_key(prover_service_config.clone());

    // Start the metrics server
    metrics::start_metrics_server(prover_service_config.clone());

    // Start the prover service
    start_prover_service(prover_service_config.port, prover_service_state).await;
}

/// Loads and logs the verification key from the prover service config
fn load_verification_key(prover_service_config: Arc<ProverServiceConfig>) {
    let verification_key_file_path = prover_service_config.verification_key_file_path();
    let verification_key = utils::read_string_from_file_path(&verification_key_file_path);
    info!("Loaded default verifying Key: {}", verification_key);
}

/// Loads the training wheels key pair from the specified private key file path.
/// If the file cannot be read or the key cannot be parsed, this function will panic.
fn load_training_wheels_key_pair(
    training_wheels_private_key_file_path: &str,
) -> TrainingWheelsKeyPair {
    info!(
        "Loading the training wheels private key from the path: {}",
        training_wheels_private_key_file_path
    );

    // Read the private key file contents (hex encoded)
    let private_key_hex = utils::read_string_from_file_path(training_wheels_private_key_file_path);

    // Parse the private key from the hex string and create the key pair
    match Ed25519PrivateKey::from_encoded_string(&private_key_hex) {
        Ok(private_key) => {
            let training_wheels_key_pair = TrainingWheelsKeyPair::from_sk(private_key);
            info!(
                "Loaded the training wheels verification key: {:?}",
                training_wheels_key_pair.verification_key()
            );

            training_wheels_key_pair
        }
        Err(error) => panic!(
            "Failed to parse the training wheels private key from hex string: {}",
            error
        ),
    }
}

/// Read PROVER_BODY_LIMIT_BYTES from env (default 65536 = 64 KiB).
/// Real prove requests are well under this; the limit is a basic
/// resource-exhaustion guard against oversized POST bodies.
fn body_limit_bytes_from_env() -> usize {
    std::env::var("PROVER_BODY_LIMIT_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64 * 1024)
}

/// Build the per-IP rate-limit state from env.
///
/// `PROVER_IP_RATE_PER_MIN` (default 60) — sustained requests per minute
/// per IP. Set to 0 to disable IP rate limiting (returns `None`).
/// `PROVER_IP_RATE_BURST` (default 10) — short-burst capacity.
/// `PROVER_TRUSTED_PROXY_CIDRS` (default empty) — comma-separated CIDRs
/// whose `X-Forwarded-For` is trusted for resolving the real client IP.
/// Empty list → use the peer address (correct when no L7 proxy is in front).
///
/// The DashMap-backed limiter retains an entry per observed IP. A
/// background GC task spawned by the caller runs `retain_recent` every
/// 10 minutes to bound memory.
fn ip_rate_limit_from_env() -> Option<(IpLimitState, Arc<IpLimiter>)> {
    let per_min = std::env::var("PROVER_IP_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60u32);
    let burst = std::env::var("PROVER_IP_RATE_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u32);

    let limiter = match rate_limit::build_ip_limiter(per_min, burst) {
        Ok(Some(l)) => l,
        Ok(None) => {
            warn!("PROVER_IP_RATE_PER_MIN=0 — per-IP rate limit disabled");
            return None;
        }
        Err(e) => panic!("invalid PROVER_IP_RATE_*: {e}"),
    };

    let trusted = rate_limit::parse_trusted_proxies(
        &std::env::var("PROVER_TRUSTED_PROXY_CIDRS").unwrap_or_default(),
    )
    .unwrap_or_else(|e| panic!("invalid PROVER_TRUSTED_PROXY_CIDRS: {e}"));
    if trusted.is_empty() {
        warn!(
            "PROVER_TRUSTED_PROXY_CIDRS is empty — per-IP limit uses peer address. \
             If deployed behind an L7 proxy, set this to your proxy's CIDR ranges."
        );
    }

    let state = IpLimitState {
        limiter: Some(limiter.clone()),
        trusted_proxies: Arc::new(trusted),
    };
    Some((state, limiter))
}

/// Build a `CorsLayer` from `PROVER_ALLOWED_ORIGINS` (comma-separated).
///
/// Empty / unset → no CORS headers are emitted; cross-origin browser
/// callers are blocked by the browser's same-origin policy.
/// Non-empty → strict allowlist; only the listed origins receive
/// `Access-Control-Allow-Origin`. CORS does NOT defend against
/// server-to-server callers; that's the rate-limit + aud-allowlist +
/// JWT-signature checks' job.
fn cors_layer_from_env() -> Option<CorsLayer> {
    let raw = std::env::var("PROVER_ALLOWED_ORIGINS").ok()?;
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([axum::http::header::CONTENT_TYPE]),
    )
}

/// Records request handling metrics + non-success logging.
/// Wraps every route as an axum middleware (preserves the behavior of
/// the original hyper-level wrapper at the equivalent location).
async fn metrics_logging_middleware(request: Request, next: Next) -> Response {
    let request_start_time = Instant::now();
    let request_origin = handler::get_request_origin(request.headers());
    let request_method = request.method().clone();
    let request_path = request.uri().path().to_owned();

    let response = next.run(request).await;

    metrics::update_request_handling_metrics(
        &request_path,
        request_method.clone(),
        response.status(),
        request_start_time,
    );

    if !response.status().is_success() {
        warn!(
            "Handled request with non-successful response! Request origin: {:?}, \
             request path: {:?}, request method: {:?}, response status: {:?}",
            request_origin,
            request_path,
            request_method,
            response.status()
        );
    }

    response
}

// Starts the prover service
async fn start_prover_service(
    prover_service_port: u16,
    prover_service_state: Arc<ProverServiceState>,
) {
    info!(
        "Starting the Prover service request handler on port {}...",
        prover_service_port
    );

    let body_limit_bytes = body_limit_bytes_from_env();
    info!("Body size limit set to {} bytes", body_limit_bytes);

    let cors_layer = cors_layer_from_env();
    if cors_layer.is_some() {
        info!("CORS allowlist configured from PROVER_ALLOWED_ORIGINS");
    } else {
        info!(
            "No CORS allowlist configured (PROVER_ALLOWED_ORIGINS unset/empty); \
             cross-origin browser callers will be blocked by same-origin policy"
        );
    }

    // Per-IP rate limit applies only to /v0/prove. /healthcheck, /jwks,
    // /about, /config remain unthrottled — operators and probes shouldn't
    // share a bucket with a real prove burst.
    let ip_rate_limit = ip_rate_limit_from_env();
    if let Some((_, ref limiter)) = ip_rate_limit {
        info!("Per-IP rate limit enabled on /v0/prove");
        let limiter_for_gc = limiter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(600)).await;
                limiter_for_gc.retain_recent();
            }
        });
    }

    // Mirror the IP-limiter GC for the per-(iss, sub) limiter built in
    // `ProverServiceState`: governor's DashMap-backed keyed limiter
    // accumulates one entry per observed (iss, sub) and never evicts
    // them on its own, so without `retain_recent` the bucket map grows
    // monotonically for the lifetime of the process.
    if let Some(sub_limiter) = prover_service_state.sub_limiter().cloned() {
        info!("Per-(iss, sub) rate limit enabled on /v0/prove");
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(600)).await;
                sub_limiter.retain_recent();
            }
        });
    }

    let public_router = Router::new()
        .route(
            handler::ABOUT_PATH,
            get(handler::about_handler).options(handler::options_handler),
        )
        .route(
            handler::CONFIG_PATH,
            get(handler::config_handler).options(handler::options_handler),
        )
        .route(
            handler::HEALTH_CHECK_PATH,
            get(handler::healthcheck_handler).options(handler::options_handler),
        )
        .route(
            handler::JWK_PATH,
            get(handler::jwk_handler).options(handler::options_handler),
        )
        .with_state(prover_service_state.clone());

    let prove_router = Router::new()
        .route(
            handler::PROVE_PATH,
            post(prover_handler::prove_handler).options(handler::options_handler),
        )
        .with_state(prover_service_state);
    let prove_router = if let Some((ip_state, _)) = ip_rate_limit {
        prove_router.layer(axum::middleware::from_fn_with_state(
            ip_state,
            ip_limit_middleware,
        ))
    } else {
        prove_router
    };

    let mut router = public_router
        .merge(prove_router)
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .layer(axum::middleware::from_fn(metrics_logging_middleware));

    if let Some(cors) = cors_layer {
        router = router.layer(cors);
    }

    let socket_addr = SocketAddr::from(([0, 0, 0, 0], prover_service_port));
    let listener = match tokio::net::TcpListener::bind(&socket_addr).await {
        Ok(listener) => listener,
        Err(error) => panic!("Prover service bind error! Error: {}", error),
    };
    // ConnectInfo<SocketAddr> is required by ip_limit_middleware to read
    // the peer address; only into_make_service_with_connect_info inserts it.
    if let Err(error) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!("Prover service error! Error: {}", error);
        panic!("Prover service error! Error: {}", error);
    }
}
