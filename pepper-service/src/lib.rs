//! Pepper service: derives the privacy-preserving pepper used in the keyless
//! identity commitment.
//!
//! The pepper is a deterministic 31-byte value derived from the JWT's
//! `(sub, aud)` claims and a server-held secret. The secret must never leak
//! — if it does, anyone can recompute any user's pepper and, combined with a
//! valid JWT, derive their on-chain address. Current POC implementation
//! derives via HMAC-SHA256 with a hardcoded key; production must move this
//! secret into an HSM/KMS and verify the incoming JWT's signature (currently
//! unvalidated by this service).

pub mod api;
pub mod pepper;
pub mod secret;
pub mod types;
pub mod verify;
