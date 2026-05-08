use serde::{Deserialize, Serialize};

/// Request body for `POST /pepper`.
///
/// The prover (or any client) passes the full JWT here. Today we only decode
/// it to extract `sub` and `aud`; a hardened version must also verify the
/// JWT's RSA signature against the issuer's JWKs and enforce `iss` /
/// `exp` / `iat` policy before returning a pepper.
#[derive(Debug, Clone, Deserialize)]
pub struct PepperRequest {
    pub jwt: String,
}

/// Response body for `POST /pepper`.
///
/// `pepper` is 31 bytes (248 bits) hex-encoded, sized to fit in a BN254
/// scalar field element.
#[derive(Debug, Clone, Serialize)]
pub struct PepperResponse {
    pub pepper: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
