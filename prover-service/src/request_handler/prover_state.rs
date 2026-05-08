// Copyright (c) Aptos Foundation

use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_keyless_common::input_processing::circuit_config::CircuitConfig;
use aptos_keyless_common::rate_limit::{self, SubLimiter};
use aptos_logger::warn;
use rust_rapidsnark::FullProver;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::external_resources::jwk_types::{FederatedJWKIssuer, FederatedJWKs, JWKCache};
#[cfg(test)]
use aptos_crypto::Uniform;

/// The shared state of the prover service (used across all requests)
pub struct ProverServiceState {
    prover_service_config: Arc<ProverServiceConfig>,
    circuit_config: CircuitConfig,
    deployment_information: DeploymentInformation,
    training_wheels_key_pair: TrainingWheelsKeyPair,
    full_prover: Arc<Mutex<Option<FullProver>>>,
    jwk_cache: JWKCache,
    federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
    /// Caps simultaneous proof generations. Configured via
    /// `PROVER_MAX_CONCURRENCY` (default 4). Over-cap returns 503 instead
    /// of queuing — proof generation is CPU-heavy and a queue under load
    /// just translates to head-of-line latency for everyone.
    prove_semaphore: Arc<Semaphore>,
    /// Per-(iss, sub) rate limiter. Charged only after successful JWT
    /// signature verification, so an attacker holding a forged JWT cannot
    /// drain a real user's bucket. `None` disables the limit.
    sub_limiter: Option<Arc<SubLimiter>>,
}

impl ProverServiceState {
    pub fn init(
        training_wheels_key_pair: TrainingWheelsKeyPair,
        prover_service_config: Arc<ProverServiceConfig>,
        deployment_information: DeploymentInformation,
        jwk_cache: JWKCache,
        federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
    ) -> Self {
        // Load the circuit configuration
        let circuit_configuration = prover_service_config.load_circuit_params();

        // Create the full prover
        let full_prover = FullProver::new(&prover_service_config.zkey_file_path())
            .expect("Failed to create the full prover!");

        let max_concurrency = prove_max_concurrency_from_env();
        let sub_limiter = sub_limiter_from_env();

        // Create the prover service state
        ProverServiceState {
            prover_service_config,
            circuit_config: circuit_configuration,
            deployment_information,
            training_wheels_key_pair,
            full_prover: Arc::new(Mutex::new(Some(full_prover))),
            jwk_cache,
            federated_jwks,
            prove_semaphore: Arc::new(Semaphore::new(max_concurrency)),
            sub_limiter,
        }
    }

    #[cfg(test)]
    /// Creates a new prover service state for testing purposes
    pub fn new_for_testing(
        training_wheels_key_pair: TrainingWheelsKeyPair,
        prover_service_config: Arc<ProverServiceConfig>,
        deployment_information: DeploymentInformation,
        jwk_cache: JWKCache,
        federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
    ) -> Self {
        // Semaphore::new panics above MAX_PERMITS (usize::MAX >> 3); use
        // the documented maximum so tests effectively get an unlimited
        // semaphore without tripping that bound.
        Self::new_for_testing_with_semaphore_capacity(
            training_wheels_key_pair,
            prover_service_config,
            deployment_information,
            jwk_cache,
            federated_jwks,
            Semaphore::MAX_PERMITS,
        )
    }

    #[cfg(test)]
    /// Creates a new prover service state for testing with an explicit
    /// prove-semaphore capacity.
    pub fn new_for_testing_with_semaphore_capacity(
        training_wheels_key_pair: TrainingWheelsKeyPair,
        prover_service_config: Arc<ProverServiceConfig>,
        deployment_information: DeploymentInformation,
        jwk_cache: JWKCache,
        federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
        semaphore_capacity: usize,
    ) -> Self {
        let circuit_configuration = CircuitConfig::new();
        let full_prover = Arc::new(Mutex::new(None));

        ProverServiceState {
            prover_service_config,
            circuit_config: circuit_configuration,
            deployment_information,
            training_wheels_key_pair,
            full_prover,
            jwk_cache,
            federated_jwks,
            prove_semaphore: Arc::new(Semaphore::new(semaphore_capacity)),
            sub_limiter: None,
        }
    }

    #[cfg(test)]
    /// Creates a new prover service state for testing with an explicit
    /// per-(iss, sub) limiter. Used to exercise rate-limit enforcement.
    pub fn new_for_testing_with_sub_limiter(
        training_wheels_key_pair: TrainingWheelsKeyPair,
        prover_service_config: Arc<ProverServiceConfig>,
        deployment_information: DeploymentInformation,
        jwk_cache: JWKCache,
        federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
        sub_limiter: Option<Arc<SubLimiter>>,
    ) -> Self {
        let mut state = Self::new_for_testing(
            training_wheels_key_pair,
            prover_service_config,
            deployment_information,
            jwk_cache,
            federated_jwks,
        );
        state.sub_limiter = sub_limiter;
        state
    }

    /// Returns a reference to the circuit configuration
    pub fn circuit_config(&self) -> &CircuitConfig {
        &self.circuit_config
    }

    /// Returns a reference to the deployment information
    pub fn deployment_information(&self) -> &DeploymentInformation {
        &self.deployment_information
    }

    /// Returns an Arc reference to the JWK cache
    pub fn jwk_cache(&self) -> JWKCache {
        self.jwk_cache.clone()
    }

    /// Returns an Arc reference to the federated JWKs
    pub fn federated_jwks(&self) -> FederatedJWKs<FederatedJWKIssuer> {
        self.federated_jwks.clone()
    }

    /// Returns an Arc reference to the full prover instance (if one exists)
    pub fn full_prover(&self) -> Arc<Mutex<Option<FullProver>>> {
        self.full_prover.clone()
    }

    /// Returns an Arc reference to the prover service config
    pub fn prover_service_config(&self) -> Arc<ProverServiceConfig> {
        self.prover_service_config.clone()
    }

    /// Returns a reference to the training wheels key pair
    pub fn training_wheels_key_pair(&self) -> &TrainingWheelsKeyPair {
        &self.training_wheels_key_pair
    }

    /// Returns a clone of the prove-concurrency semaphore.
    pub fn prove_semaphore(&self) -> Arc<Semaphore> {
        self.prove_semaphore.clone()
    }

    /// Returns the per-(iss, sub) rate limiter, if configured.
    pub fn sub_limiter(&self) -> Option<&Arc<SubLimiter>> {
        self.sub_limiter.as_ref()
    }
}

/// Read PROVER_MAX_CONCURRENCY from env (default 4).
fn prove_max_concurrency_from_env() -> usize {
    std::env::var("PROVER_MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(4)
}

/// Build a per-(iss, sub) rate limiter from env. Returns `None` when
/// `PROVER_SUB_RATE_PER_MIN=0` (limit disabled).
///
/// `PROVER_SUB_RATE_PER_MIN` (default 30), `PROVER_SUB_RATE_BURST` (default 5).
fn sub_limiter_from_env() -> Option<Arc<SubLimiter>> {
    let per_min = std::env::var("PROVER_SUB_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u32);
    let burst = std::env::var("PROVER_SUB_RATE_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5u32);
    match rate_limit::build_sub_limiter(per_min, burst) {
        Ok(Some(l)) => Some(l),
        Ok(None) => {
            warn!("PROVER_SUB_RATE_PER_MIN=0 — per-(iss,sub) rate limit disabled");
            None
        }
        Err(e) => panic!("invalid PROVER_SUB_RATE_*: {e}"),
    }
}

/// The training wheels key pair struct
#[derive(Debug)]
pub struct TrainingWheelsKeyPair {
    signing_key: Ed25519PrivateKey,
    verification_key: Ed25519PublicKey,
}

impl TrainingWheelsKeyPair {
    pub fn from_sk(signing_key: Ed25519PrivateKey) -> Self {
        let verification_key = Ed25519PublicKey::from(&signing_key);

        Self {
            signing_key,
            verification_key,
        }
    }

    #[cfg(test)]
    /// Creates a new training wheels key pair for testing purposes
    pub fn new_for_testing() -> Self {
        let signing_key = Ed25519PrivateKey::generate_for_testing();
        Self::from_sk(signing_key)
    }

    /// Returns a reference to the signing key
    pub fn signing_key(&self) -> &Ed25519PrivateKey {
        &self.signing_key
    }

    /// Returns a reference to the verification key
    pub fn verification_key(&self) -> &Ed25519PublicKey {
        &self.verification_key
    }
}
