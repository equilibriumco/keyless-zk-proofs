// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::{FederatedJWKs, JWKCache};
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::handler;
use crate::request_handler::handler::{
    ABOUT_PATH, CONFIG_PATH, HEALTH_CHECK_PATH, JWK_PATH, PROVE_PATH,
};
use crate::request_handler::prover_handler;
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use aptos_infallible::Mutex;
use aptos_types::jwks::rsa::SECURE_TEST_RSA_JWK;
use axum::body::Body;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN,
};
use axum::http::{Method, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use std::ops::Deref;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;

#[tokio::test]
async fn test_options_request_returns_200_without_cors_headers_by_default() {
    // OPTIONS to a registered path returns 200 OK. CORS headers are
    // emitted only when PROVER_ALLOWED_ORIGINS is configured (Task 9
    // moved CORS to a tower-http layer); without the layer the response
    // has no Access-Control-* headers.
    let response = send_request_to_path(
        Method::OPTIONS,
        HEALTH_CHECK_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert!(headers.get(ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none());
    assert!(headers.get(ACCESS_CONTROL_ALLOW_HEADERS).is_none());
    assert!(headers.get(ACCESS_CONTROL_ALLOW_METHODS).is_none());
}

#[tokio::test]
async fn test_cors_allowlist_grants_only_listed_origin() {
    use tower_http::cors::{AllowOrigin, CorsLayer};

    let allowed = "https://wallet.example.com";
    let blocked = "https://attacker.example.com";

    // Build a router with a tower-http CorsLayer matching what
    // main.rs would build from a non-empty PROVER_ALLOWED_ORIGINS.
    let prover_service_state = Arc::new(ProverServiceState::new_for_testing(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
    ));
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([allowed.parse().unwrap()]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE]);
    let router: Router = Router::new()
        .route(
            HEALTH_CHECK_PATH,
            get(handler::healthcheck_handler).options(handler::options_handler),
        )
        .with_state(prover_service_state)
        .layer(cors);

    // Allowed origin → ACAO header echoes the request origin.
    let req = Request::builder()
        .uri(format!("http://127.0.0.1{}", HEALTH_CHECK_PATH))
        .method(Method::OPTIONS)
        .header("origin", allowed)
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        allowed
    );

    // Disallowed origin → no ACAO header.
    let req = Request::builder()
        .uri(format!("http://127.0.0.1{}", HEALTH_CHECK_PATH))
        .method(Method::OPTIONS)
        .header("origin", blocked)
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

#[tokio::test]
async fn test_get_about_request() {
    // Create a new deployment information object
    let mut deployment_information = DeploymentInformation::new();

    // Insert a test entry into the deployment information
    let test_key = "test_key".to_string();
    let test_value = "test_value".to_string();
    deployment_information.extend_deployment_information(test_key.clone(), test_value.clone());

    // Send a GET request to the about endpoint
    let response = send_request_to_path(
        Method::GET,
        ABOUT_PATH,
        Body::empty(),
        None,
        None,
        Some(deployment_information),
        None,
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body as a JSON map
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();

    // Verify the response body contains relevant build information
    assert!(json_map.contains_key("build_cargo_version"));
    assert!(json_map.contains_key("build_commit_hash"));
    assert!(json_map.contains_key("build_is_release_build"));

    // Verify the test entry is present in the response body
    assert_eq!(json_map.get(&test_key).unwrap(), test_value.as_str());
}

#[tokio::test]
async fn test_get_config_request() {
    // Create a new prover service config
    let prover_service_config = ProverServiceConfig {
        setup_dir: "custom/setup/directory/for/tests".into(),
        ..ProverServiceConfig::default()
    };
    let prover_service_config = Arc::new(prover_service_config);

    // Send a GET request to the config endpoint
    let response = send_request_to_path(
        Method::GET,
        CONFIG_PATH,
        Body::empty(),
        Some(prover_service_config.clone()),
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 200
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the config from the response body JSON
    let body_string = get_response_body_string(response).await;
    let response_config: ProverServiceConfig = serde_json::from_str(&body_string).unwrap();
    assert_eq!(&response_config, prover_service_config.deref());
}

#[tokio::test]
async fn test_health_check_request() {
    // Send a GET request to the health check endpoint
    let response = send_request_to_path(
        Method::GET,
        HEALTH_CHECK_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_jwk_request() {
    // Create a JWK cache
    let jwk_cache = Arc::new(Mutex::new(HashMap::new()));

    // Send a GET request to the JWK endpoint
    let response = send_request_to_path(
        Method::GET,
        JWK_PATH,
        Body::empty(),
        None,
        None,
        None,
        Some(jwk_cache.clone()),
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body string and verify that it is an empty JSON map
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();
    assert!(json_map.is_empty());

    // Insert several test JWKs into the cache
    for i in 0..3 {
        // Create the test issuer and key ID
        let test_issuer = format!("test.issuer.{}", i);
        let test_key_id = format!("test.key.id.{}", i);

        // Insert the test JWK into the cache
        let mut jwk_cache = jwk_cache.lock();
        let issuer_entry = jwk_cache.entry(test_issuer.clone()).or_default();
        issuer_entry.insert(
            test_key_id.clone(),
            Arc::new(SECURE_TEST_RSA_JWK.deref().clone()),
        );
    }

    // Send a GET request to the JWK endpoint
    let response = send_request_to_path(
        Method::GET,
        JWK_PATH,
        Body::empty(),
        None,
        None,
        None,
        Some(jwk_cache.clone()),
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body as a JSON map, and verify the number of entries
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();
    assert_eq!(json_map.len(), 3);

    // Verify that the map contains the expected JWKs
    for i in 0..3 {
        // Create the test issuer and key ID
        let test_issuer = format!("test.issuer.{}", i);
        let test_key_id = format!("test.key.id.{}", i);

        // Verify that the map contains the issuer and key ID
        let issuer_entry = json_map.get(&test_issuer).unwrap().as_object().unwrap();
        assert_eq!(issuer_entry.len(), 1);
        assert!(issuer_entry.contains_key(&test_key_id));
    }
}

#[tokio::test]
async fn test_get_invalid_path_or_method_request() {
    // Send a GET request to an unknown endpoint and verify that it returns 404
    let response = send_request_to_path(
        Method::GET,
        "/invalid_path",
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Send a GET request to an endpoint that only supports POST requests, and verify that it returns 405
    let response = send_request_to_path(
        Method::GET,
        PROVE_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Send a POST request to an endpoint that only supports GET requests, and verify that it returns 405
    let response = send_request_to_path(
        Method::POST,
        ABOUT_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_prove_request_bad_request() {
    // Send a POST request to the prove endpoint
    let response = send_request_to_path(
        Method::POST,
        PROVE_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 400 (bad request, since no body was provided)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Send another POST request with an invalid JSON body
    let response = send_request_to_path(
        Method::POST,
        PROVE_PATH,
        Body::from("invalid_json"),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 400 (bad request, since the body was invalid JSON)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_prove_semaphore_returns_503_when_at_capacity() {
    use crate::request_handler::prover_handler;

    // State with semaphore capacity = 1.
    let state = Arc::new(ProverServiceState::new_for_testing_with_semaphore_capacity(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
        1,
    ));

    let router: Router = Router::new()
        .route(handler::PROVE_PATH, post(prover_handler::prove_handler))
        .with_state(state.clone());

    // Hold the only permit externally to force the next request over capacity.
    let _permit = state
        .prove_semaphore()
        .try_acquire_owned()
        .expect("semaphore must have a free permit on test setup");

    let request = Request::builder()
        .uri(format!("http://127.0.0.1{}", PROVE_PATH))
        .method(Method::POST)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_body_size_limit_returns_413() {
    use axum::extract::DefaultBodyLimit;

    // Build a router with an explicit small body limit (8 bytes).
    let prover_service_state = Arc::new(ProverServiceState::new_for_testing(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
    ));
    let router: Router = Router::new()
        .route(
            handler::PROVE_PATH,
            post(crate::request_handler::prover_handler::prove_handler),
        )
        .layer(DefaultBodyLimit::max(8))
        .with_state(prover_service_state);

    // POST a body well over the limit.
    let oversize = vec![b'A'; 100];
    let request = Request::builder()
        .uri(format!("http://127.0.0.1{}", PROVE_PATH))
        .method(Method::POST)
        .header("content-type", "application/json")
        .body(Body::from(oversize))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_ip_rate_limit_returns_429_after_burst() {
    use aptos_keyless_common::rate_limit::{build_ip_limiter, ip_limit_middleware, IpLimitState};
    use axum::extract::ConnectInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Tiny burst (2) so 3rd request must be denied. per-min rate is set
    // high enough that the test only depends on burst capacity.
    let ip_state = IpLimitState {
        limiter: build_ip_limiter(60, 2).unwrap(),
        trusted_proxies: Arc::new(vec![]),
    };

    let prover_service_state = Arc::new(ProverServiceState::new_for_testing(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
    ));
    let router: Router = Router::new()
        .route(handler::PROVE_PATH, post(prover_handler::prove_handler))
        .with_state(prover_service_state)
        .layer(axum::middleware::from_fn_with_state(
            ip_state,
            ip_limit_middleware,
        ));

    let mk_request = || {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 65000);
        let mut r = Request::builder()
            .uri(format!("http://127.0.0.1{}", PROVE_PATH))
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    };

    // First two must pass the IP layer (handler may reject with 400, but
    // crucially not 429).
    for _ in 0..2 {
        let resp = router.clone().oneshot(mk_request()).await.unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Third request from the same peer must be denied at the IP layer.
    let resp = router.oneshot(mk_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
}

/// Gets the response body as a string
async fn get_response_body_string(response: Response<Body>) -> String {
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body_bytes.to_vec()).unwrap()
}

// Calls the request handler with the given method, endpoint, and body
async fn send_request_to_path(
    method: Method,
    endpoint: &str,
    body: Body,
    prover_service_config: Option<Arc<ProverServiceConfig>>,
    training_wheels_key_pair: Option<TrainingWheelsKeyPair>,
    deployment_information: Option<DeploymentInformation>,
    jwk_cache: Option<JWKCache>,
) -> Response<Body> {
    // Get or create the prover service config
    let prover_service_config =
        prover_service_config.unwrap_or_else(|| Arc::new(ProverServiceConfig::default()));

    // Build the URI
    let uri = format!(
        "http://127.0.0.1:{}{}",
        prover_service_config.port, endpoint
    );

    // Build the request
    let request = Request::builder()
        .uri(uri)
        .method(method)
        .body(body)
        .unwrap();

    // Get or create a training wheels key pair
    let training_wheels_key_pair =
        training_wheels_key_pair.unwrap_or_else(TrainingWheelsKeyPair::new_for_testing);

    // Get or create deployment information
    let deployment_information = deployment_information.unwrap_or_default();

    // Get or create a JWK cache
    let jwk_cache = jwk_cache.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));

    // Create a federated JWKs object
    let federated_jwks = FederatedJWKs::new_empty();

    // Create the prover service state
    let prover_service_state = Arc::new(ProverServiceState::new_for_testing(
        training_wheels_key_pair,
        prover_service_config,
        deployment_information,
        jwk_cache,
        federated_jwks,
    ));

    // Serve the request via axum router
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
        .with_state(prover_service_state);

    router.oneshot(request).await.unwrap()
}
