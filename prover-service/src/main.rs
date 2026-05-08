// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use aptos_logger::{error, info, warn};
use axum::extract::{DefaultBodyLimit, Request};
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

    let router = Router::new()
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
        .route(
            handler::PROVE_PATH,
            post(prover_handler::prove_handler).options(handler::options_handler),
        )
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .with_state(prover_service_state)
        .layer(axum::middleware::from_fn(metrics_logging_middleware));

    let socket_addr = SocketAddr::from(([0, 0, 0, 0], prover_service_port));
    let listener = match tokio::net::TcpListener::bind(&socket_addr).await {
        Ok(listener) => listener,
        Err(error) => panic!("Prover service bind error! Error: {}", error),
    };
    if let Err(error) = axum::serve(listener, router).await {
        error!("Prover service error! Error: {}", error);
        panic!("Prover service error! Error: {}", error);
    }
}
