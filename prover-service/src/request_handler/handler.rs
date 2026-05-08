// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::JWKCache;
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_state::ProverServiceState;
use aptos_logger::error;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Response, StatusCode};
use std::sync::Arc;

// The list of endpoints/paths offered by the Prover Service.
// Note: if you update these paths, please also update the "ALL_PATHS" array below.
pub const ABOUT_PATH: &str = "/about";
pub const CONFIG_PATH: &str = "/config";
pub const HEALTH_CHECK_PATH: &str = "/healthcheck";
pub const JWK_PATH: &str = "/cached/jwk";
pub const PROVE_PATH: &str = "/v0/prove";

// An array of all known endpoints/paths
pub const ALL_PATHS: [&str; 5] = [
    ABOUT_PATH,
    CONFIG_PATH,
    HEALTH_CHECK_PATH,
    JWK_PATH,
    PROVE_PATH,
];

// Content type constants
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_TEXT: &str = "text/plain";

// Origin header constants
pub const MISSING_ORIGIN_STRING: &str = ""; // Default to empty string if origin header is missing
const ORIGIN_HEADER: &str = "origin";

// Useful message constants
const HEALTH_CHECK_OK_MESSAGE: &str = "OK";

// Unexpected error message constant
const UNEXPECTED_ERROR_MESSAGE: &str = "An unexpected error was encountered!";

/// Returns a response builder for the given status code.
///
/// CORS headers are NOT set here — they're emitted by the
/// `tower_http::cors::CorsLayer` configured in `main.rs` from
/// `PROVER_ALLOWED_ORIGINS`. Setting them inline would conflict with
/// the layer (CorsLayer overrides duplicates).
pub fn create_response_builder(
    _origin: String,
    status_code: StatusCode,
) -> axum::http::response::Builder {
    Response::builder().status(status_code)
}

/// Generates a 400 response for bad requests
pub fn generate_bad_request_response(origin: String, json_error_string: String) -> Response<Body> {
    generate_json_response(origin, StatusCode::BAD_REQUEST, json_error_string)
}

/// Generates a 500 response for unexpected internal server errors
pub fn generate_internal_server_error_response(origin: String) -> Response<Body> {
    generate_text_response(
        origin,
        StatusCode::INTERNAL_SERVER_ERROR,
        UNEXPECTED_ERROR_MESSAGE.into(),
    )
}

/// Generates a 429 response for rate-limited requests. The body
/// intentionally does not disclose the bucketing dimension (per-IP vs
/// per-(iss, sub)) so an attacker cannot probe for sub-keys.
pub fn generate_too_many_requests_response(origin: String) -> Response<Body> {
    generate_json_response(
        origin,
        StatusCode::TOO_MANY_REQUESTS,
        r#"{"error":"rate limit exceeded"}"#.to_string(),
    )
}

/// Generates a 403 response for requests whose JWT `aud` is not allowed.
pub fn generate_forbidden_response(origin: String) -> Response<Body> {
    generate_json_response(
        origin,
        StatusCode::FORBIDDEN,
        r#"{"error":"aud not allowed"}"#.to_string(),
    )
}

/// Generates a JSON response with the given status code and body string
pub fn generate_json_response(
    origin: String,
    status_code: StatusCode,
    body_str: String,
) -> Response<Body> {
    create_response_builder(origin, status_code)
        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
        .body(Body::from(body_str))
        .expect("Failed to build JSON response!")
}

/// Generates a text response with the given status code and body string
pub fn generate_text_response(
    origin: String,
    status_code: StatusCode,
    body_str: String,
) -> Response<Body> {
    create_response_builder(origin, status_code)
        .header(CONTENT_TYPE, CONTENT_TYPE_TEXT)
        .body(Body::from(body_str))
        .expect("Failed to build text response!")
}

/// Extracts the origin header from a `HeaderMap`
pub fn get_request_origin(headers: &HeaderMap) -> String {
    headers
        .get(ORIGIN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(MISSING_ORIGIN_STRING)
        .to_owned()
}

/// Returns true if the given URI path is a known path/endpoint
pub fn is_known_path(uri_path: &str) -> bool {
    ALL_PATHS.contains(&uri_path)
}

// ---------- axum handlers ----------

/// GET /about
pub async fn about_handler(
    State(state): State<Arc<ProverServiceState>>,
    headers: HeaderMap,
) -> Response<Body> {
    let origin = get_request_origin(&headers);
    generate_about_response(origin, state.deployment_information())
}

/// GET /config
pub async fn config_handler(
    State(state): State<Arc<ProverServiceState>>,
    headers: HeaderMap,
) -> Response<Body> {
    let origin = get_request_origin(&headers);
    generate_config_response(origin, state.prover_service_config())
}

/// GET /healthcheck
pub async fn healthcheck_handler(headers: HeaderMap) -> Response<Body> {
    let origin = get_request_origin(&headers);
    generate_text_response(origin, StatusCode::OK, HEALTH_CHECK_OK_MESSAGE.into())
}

/// GET /cached/jwk
pub async fn jwk_handler(
    State(state): State<Arc<ProverServiceState>>,
    headers: HeaderMap,
) -> Response<Body> {
    let origin = get_request_origin(&headers);
    generate_jwt_cache_response(origin, state.jwk_cache())
}

/// OPTIONS preflight handler. Returns 200 OK with empty body — the
/// `tower_http::cors::CorsLayer` in `main.rs` adds the
/// `Access-Control-Allow-{Origin,Methods,Headers}` headers based on
/// the configured `PROVER_ALLOWED_ORIGINS` allowlist.
pub async fn options_handler(_headers: HeaderMap) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("Failed to build options response!")
}

// ---------- response generators (called by handlers above) ----------

fn generate_about_response(
    origin: String,
    deployment_information: &DeploymentInformation,
) -> Response<Body> {
    match serde_json::to_string_pretty(&deployment_information.get_deployment_information_map()) {
        Ok(deployment_info_json) => {
            generate_json_response(origin, StatusCode::OK, deployment_info_json)
        }
        Err(error) => {
            error!(
                "Failed to serialize deployment information to JSON: {}",
                error
            );
            generate_internal_server_error_response(origin)
        }
    }
}

fn generate_config_response(
    origin: String,
    prover_service_config: Arc<ProverServiceConfig>,
) -> Response<Body> {
    match serde_json::to_string_pretty(&prover_service_config) {
        Ok(config_json) => generate_json_response(origin, StatusCode::OK, config_json),
        Err(error) => {
            error!("Failed to serialize configuration to JSON: {}", error);
            generate_internal_server_error_response(origin)
        }
    }
}

fn generate_jwt_cache_response(origin: String, jwk_cache: JWKCache) -> Response<Body> {
    let jwk_cache = jwk_cache.lock().clone();
    match serde_json::to_string_pretty(&jwk_cache) {
        Ok(response_body) => generate_json_response(origin, StatusCode::OK, response_body),
        Err(error) => {
            error!("Failed to serialize to JSON response: {}", error);
            generate_internal_server_error_response(origin)
        }
    }
}
