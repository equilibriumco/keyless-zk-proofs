// Copyright (c) Aptos Foundation

use crate::error::ProverServiceError;
use crate::external_resources::jwk_types::{FederatedJWKs, JWKCache};
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use crate::request_handler::training_wheels;
use crate::request_handler::types::RequestInput;
use crate::tests::types::TestJWKKeyPair;
use crate::tests::types::{ProofTestCase, TestJWTPayload};
use crate::tests::utils;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_crypto::Uniform;
use aptos_infallible::Mutex;
use aptos_keyless_common::rate_limit::build_sub_limiter;
use aptos_types::keyless::Pepper;
use aptos_types::transaction::authenticator::EphemeralPublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_validate_default_jwt() {
    // Create a default JWT payload
    let jwt_payload = TestJWTPayload::default();

    // Verify the JWT signature
    test_jwt_signature_validation(jwt_payload, true);
}

#[test]
fn test_validate_jwt_invalid_signature() {
    // Create a default JWT payload
    let jwt_payload = TestJWTPayload::default();

    // Create a test case and convert it to a prover request input
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();
    let jwk_keypair = utils::generate_test_jwk_keypair();
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    // Verify the JWT signature using a different keypair to simulate an invalid signature
    let another_jwk_keypair = utils::generate_test_jwk_keypair();
    let result = training_wheels::validate_jwt_signature(
        &another_jwk_keypair.get_rsa_jwk(),
        &prover_request_input.jwt_b64,
    );

    // Expect the validation to fail
    assert!(result.is_err());
}

#[test]
fn test_validate_jwt_sig_and_dates_expired() {
    // Create a JWT payload with an expired expiration time
    let duration_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let jwt_payload = TestJWTPayload {
        exp: duration_since_epoch.as_secs() - 100,
        ..TestJWTPayload::default()
    };

    // Verify the JWT signature
    test_jwt_signature_validation(jwt_payload, false);
}

#[test]
fn test_sub_rate_limit_denies_after_burst() {
    // burst = 2 → 3rd call from same (iss, sub) must be denied.
    let limiter = build_sub_limiter(60, 2).unwrap().unwrap();
    let state = Arc::new(ProverServiceState::new_for_testing_with_sub_limiter(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
        Some(limiter),
    ));

    let iss = "https://accounts.google.com";
    let sub = "user-123";

    // First two charges succeed.
    assert!(training_wheels::check_sub_rate_limit(&state, iss, sub).is_ok());
    assert!(training_wheels::check_sub_rate_limit(&state, iss, sub).is_ok());

    // Third charge for the same (iss, sub) must return SubRateLimited.
    match training_wheels::check_sub_rate_limit(&state, iss, sub) {
        Err(ProverServiceError::SubRateLimited) => {}
        other => panic!("expected SubRateLimited, got {other:?}"),
    }

    // A different sub still has its own bucket and isn't affected.
    assert!(training_wheels::check_sub_rate_limit(&state, iss, "other-user").is_ok());

    // A different iss is also isolated.
    assert!(
        training_wheels::check_sub_rate_limit(&state, "https://appleid.apple.com", sub).is_ok()
    );
}

#[test]
fn test_aud_allowlist_accepts_listed_and_rejects_others() {
    let mut allowed = HashSet::new();
    allowed.insert("good-aud".to_string());
    allowed.insert("also-good-aud".to_string());
    let state = Arc::new(ProverServiceState::new_for_testing_with_allowed_auds(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
        Some(Arc::new(allowed)),
    ));

    assert!(training_wheels::check_aud_allowlist(&state, "good-aud").is_ok());
    assert!(training_wheels::check_aud_allowlist(&state, "also-good-aud").is_ok());
    match training_wheels::check_aud_allowlist(&state, "unknown-aud") {
        Err(ProverServiceError::AudNotAllowed) => {}
        other => panic!("expected AudNotAllowed, got {other:?}"),
    }
    // Empty string is not implicitly allowed.
    match training_wheels::check_aud_allowlist(&state, "") {
        Err(ProverServiceError::AudNotAllowed) => {}
        other => panic!("expected AudNotAllowed for empty aud, got {other:?}"),
    }
}

#[test]
fn test_aud_allowlist_unset_accepts_any() {
    let state = Arc::new(ProverServiceState::new_for_testing(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
    ));
    assert!(training_wheels::check_aud_allowlist(&state, "anything").is_ok());
    assert!(training_wheels::check_aud_allowlist(&state, "").is_ok());
}

/// Integration-shaped test for the security claim that a JWT whose
/// signature does not verify must NOT consume the targeted (iss, sub)
/// rate-limit bucket. The structural property is that
/// `preprocess_and_validate_request` calls `check_sub_rate_limit` AFTER
/// `validate_jwt_signature(...)?` — a sig failure short-circuits with
/// `Err(BadRequest)` before any bucket charge. Without this guarantee,
/// an attacker holding any forged JWT (right `iss`/`sub`, wrong
/// signature) could repeatedly burn a real user's burst capacity.
///
/// We don't go through `ProofTestCase` here because that asserts the
/// circuit-config / trusted-setup is locally procured. The non-JWT
/// fields of `RequestInput` are dummy values: validation must
/// short-circuit at the signature step before any of them are touched.
#[tokio::test]
async fn test_forged_signature_does_not_drain_sub_bucket() {
    // Two RSA keypairs sharing the same `kid`: one signs the JWT (the
    // attacker), the other is what the prover's JWK cache resolves the
    // kid to. The signature on the JWT will fail to verify against the
    // cached pubkey.
    const KID: &str = "test-rsa";
    let attacker = utils::generate_test_jwk_keypair_with_kid(KID);
    let real_signer = utils::generate_test_jwk_keypair_with_kid(KID);

    let payload = TestJWTPayload::default();
    let iss = payload.iss.clone();
    let sub = payload.sub.clone().expect("default payload has sub");
    let forged_jwt = attacker.sign(&payload);

    // JWK cache: iss + KID → real_signer's pubkey (NOT the attacker's).
    let jwk_cache: JWKCache = Arc::new(Mutex::new(HashMap::new()));
    {
        let mut cache = jwk_cache.lock();
        cache
            .entry(iss.clone())
            .or_default()
            .insert(KID.to_string(), Arc::new(real_signer.get_rsa_jwk()));
    }

    // ProverServiceState with a small-burst (iss, sub) limiter so a
    // single bucket charge would be detectable.
    let limiter = build_sub_limiter(60, 2).unwrap().unwrap();
    let state = Arc::new(ProverServiceState::new_for_testing_with_sub_limiter(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        jwk_cache.clone(),
        FederatedJWKs::new_empty(),
        Some(limiter),
    ));

    // Build a RequestInput by hand. `epk`, `pepper`, `epk_blinder`, etc.
    // are intentionally bogus — validation must reject at the signature
    // step BEFORE they're inspected.
    let dummy_priv = Ed25519PrivateKey::generate_for_testing();
    let dummy_pub: Ed25519PublicKey = (&dummy_priv).into();
    let request_input = RequestInput {
        jwt_b64: forged_jwt,
        epk: EphemeralPublicKey::ed25519(dummy_pub),
        epk_blinder: vec![0u8; 31],
        exp_date_secs: 0,
        exp_horizon_secs: 100,
        pepper: Pepper::from_number(42),
        uid_key: "sub".to_string(),
        extra_field: None,
        idc_aud: None,
        use_insecure_test_jwk: false,
        skip_aud_checks: false,
    };

    let result = training_wheels::preprocess_and_validate_request(
        &state,
        &request_input,
        jwk_cache,
        FederatedJWKs::new_empty(),
    )
    .await;

    // Forged signature → BadRequest. Critically NOT SubRateLimited
    // (which would imply the bucket got charged before sig verify).
    match result {
        Err(ProverServiceError::BadRequest(_)) => {}
        Err(ProverServiceError::SubRateLimited) => panic!(
            "forged JWT tripped SubRateLimited — bucket was charged before signature verify, \
             which lets an attacker drain a real user's bucket"
        ),
        other => panic!("expected BadRequest from sig failure, got {other:?}"),
    }

    // The (iss, sub) bucket must still hold its full 2-token burst —
    // the forged attempt did NOT consume any. If the order ever
    // regresses (charge moved above sig verify), one of these next
    // calls flips to SubRateLimited and the test fails.
    assert!(
        training_wheels::check_sub_rate_limit(&state, &iss, &sub).is_ok(),
        "bucket was drained by the forged attempt"
    );
    assert!(
        training_wheels::check_sub_rate_limit(&state, &iss, &sub).is_ok(),
        "bucket was drained by the forged attempt"
    );
    match training_wheels::check_sub_rate_limit(&state, &iss, &sub) {
        Err(ProverServiceError::SubRateLimited) => {}
        other => panic!("expected SubRateLimited on the third charge, got {other:?}"),
    }
}

#[test]
fn test_sub_rate_limit_no_limiter_always_passes() {
    let state = Arc::new(ProverServiceState::new_for_testing(
        TrainingWheelsKeyPair::new_for_testing(),
        Arc::new(ProverServiceConfig::default()),
        DeploymentInformation::default(),
        Arc::new(Mutex::new(HashMap::new())),
        FederatedJWKs::new_empty(),
    ));
    for _ in 0..100 {
        assert!(training_wheels::check_sub_rate_limit(&state, "iss", "sub").is_ok());
    }
}

/// Helper function to test JWT signature validation
fn test_jwt_signature_validation(jwt_payload: TestJWTPayload, expect_success: bool) {
    // Create a test case and convert it to a prover request input
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();
    let jwk_keypair = utils::generate_test_jwk_keypair();
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    // Verify the JWT signature
    let result = training_wheels::validate_jwt_signature(
        &jwk_keypair.get_rsa_jwk(),
        &prover_request_input.jwt_b64,
    );
    if expect_success {
        assert!(result.is_ok());
    } else {
        assert!(result.is_err());
    }
}
