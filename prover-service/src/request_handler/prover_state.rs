// Copyright (c) Aptos Foundation

use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_keyless_common::input_processing::circuit_config::CircuitConfig;
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
        Self::new_for_testing_with_semaphore_capacity(
            training_wheels_key_pair,
            prover_service_config,
            deployment_information,
            jwk_cache,
            federated_jwks,
            usize::MAX >> 1,
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
        }
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
}

/// Read PROVER_MAX_CONCURRENCY from env (default 4).
fn prove_max_concurrency_from_env() -> usize {
    std::env::var("PROVER_MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(4)
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
