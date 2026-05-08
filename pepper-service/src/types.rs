use serde::{Deserialize, Serialize};

/// Request body for `POST /pepper`.
///
/// The wallet (or any client) passes the full JWT here. The handler
/// verifies the JWT's RSA signature against the issuer's JWKs and enforces
/// `iss` / `exp` policy via `verify::verify_jwt` before deriving the
/// pepper from `(sub, aud)` — see `pepper-service/src/verify.rs` and
/// the call site in `pepper-service/src/api.rs::pepper`.
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
