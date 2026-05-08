//! Verify the RSA signature on an incoming JWT before deriving a pepper.
//!
//! Without this check any caller with an unsigned/forged JWT could ask for
//! the pepper of any `(sub, aud)` pair, enabling offline enumeration of
//! every keyless address on the chain. With it the service is willing to
//! derive a pepper only for JWTs that Google (or another allowed issuer)
//! actually signed for a real user.
//!
//! The verifier:
//! 1. looks up the JWK modulus for the JWT header's `kid` via the shared
//!    `JwkCache` — cached, TTL-driven, same mechanism as the prover;
//! 2. decodes and verifies the RS256 signature using `jsonwebtoken`;
//! 3. checks that the JWT's `iss` is in the configured allowlist;
//! 4. checks the JWT's `exp` hasn't passed.
//!
//! The `aud` claim is explicitly NOT checked here — that's the prover's
//! job (`PROVER_ALLOWED_AUDS`). The pepper itself is safe to return to a
//! holder of a valid Google JWT; downstream gating on which wallets may
//! be proved for lives in the prover.

use anyhow::anyhow;
use aptos_keyless_common::{jwk::JwkError, JwkCache, ParsedJwt};
use base64::URL_SAFE_NO_PAD;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Claims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    exp: Option<u64>,
}

/// Errors surfaced by [`verify_jwt`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyJwtError {
    /// JWKS endpoint unreachable or returned a non-2xx — transient upstream.
    #[error("JWKS unavailable: {0}")]
    JwksUnavailable(#[source] anyhow::Error),
    /// JWKS healthy but requested `kid` absent — client fault (bad header).
    #[error("kid {0:?} not found in JWKS")]
    KidNotFound(String),
    /// JWT shape, algorithm, signature, issuer, or expiry check failed.
    #[error("{0}")]
    BadJwt(#[source] anyhow::Error),
}

/// Verify the JWT end-to-end (signature + iss + exp).
///
/// # Errors
///
/// See [`VerifyJwtError`].
#[allow(clippy::implicit_hasher)]
pub async fn verify_jwt(
    jwks: &JwkCache,
    allowed_iss: &HashSet<String>,
    parsed: &ParsedJwt,
    raw_jwt: &str,
) -> Result<(), VerifyJwtError> {
    if parsed.header.alg != "RS256" {
        return Err(VerifyJwtError::BadJwt(anyhow!(
            "unsupported JWT alg {:?}; only RS256 is accepted",
            parsed.header.alg
        )));
    }

    let modulus_b64 = jwks
        .get_modulus(&parsed.header.kid)
        .await
        .map_err(|e| match e {
            JwkError::KidNotFound(kid) => VerifyJwtError::KidNotFound(kid),
            JwkError::Unavailable(inner) => VerifyJwtError::JwksUnavailable(inner),
        })?;
    let modulus_bytes = base64::decode_config(&modulus_b64, URL_SAFE_NO_PAD).map_err(|e| {
        VerifyJwtError::BadJwt(anyhow!("failed to base64url-decode JWK modulus: {e}"))
    })?;
    let key = DecodingKey::from_rsa_raw_components(&modulus_bytes, &[0x01, 0x00, 0x01]);

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    if !allowed_iss.is_empty() {
        validation.set_issuer(&allowed_iss.iter().cloned().collect::<Vec<_>>());
    }

    decode::<Claims>(raw_jwt, &key, &validation)
        .map_err(|e| VerifyJwtError::BadJwt(anyhow!("JWT verification failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "hits network (fetches Google JWKs), needs a live JWT"]
    async fn rejects_unsigned_jwt() {
        let jwks = JwkCache::new().unwrap();
        let mut allowed = HashSet::new();
        allowed.insert("https://accounts.google.com".to_string());

        // Real Google kid, header/payload shape, but a bogus signature.
        let kid = {
            let client = reqwest::Client::new();
            let r: serde_json::Value = client
                .get("https://www.googleapis.com/oauth2/v3/certs")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r["keys"][0]["kid"].as_str().unwrap().to_string()
        };
        let header = base64::encode_config(
            format!(r#"{{"alg":"RS256","kid":"{kid}","typ":"JWT"}}"#),
            URL_SAFE_NO_PAD,
        );
        let payload = base64::encode_config(
            r#"{"iss":"https://accounts.google.com","sub":"x","aud":"y","exp":9999999999}"#,
            URL_SAFE_NO_PAD,
        );
        let sig = base64::encode_config("fake", URL_SAFE_NO_PAD);
        let jwt = format!("{header}.{payload}.{sig}");
        let parsed = aptos_keyless_common::parse_jwt(&jwt).unwrap();

        let result = verify_jwt(&jwks, &allowed, &parsed, &jwt).await;
        assert!(matches!(result, Err(VerifyJwtError::BadJwt(_))));
    }

    #[test]
    fn rejects_non_rs256() {
        let parsed = ParsedJwt {
            header: aptos_keyless_common::JwtHeader {
                alg: "HS256".to_string(),
                kid: "anything".to_string(),
                typ: None,
            },
            payload: aptos_keyless_common::JwtPayload {
                iss: "https://accounts.google.com".to_string(),
                sub: "x".to_string(),
                aud: "y".to_string(),
                nonce: "n".to_string(),
                iat: 0,
                exp: 9_999_999_999,
                email: None,
                email_verified: None,
            },
            signed_part: "h.p".to_string(),
            signature: vec![0; 256],
            raw_header_json: b"{}".to_vec(),
            raw_payload_json: b"{}".to_vec(),
        };
        let jwks = JwkCache::new().unwrap();
        let allowed = HashSet::from(["https://accounts.google.com".to_string()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(verify_jwt(&jwks, &allowed, &parsed, "not-used"))
            .unwrap_err();
        match err {
            VerifyJwtError::BadJwt(inner) => assert!(inner.to_string().contains("RS256")),
            other => panic!("expected BadJwt, got {other:?}"),
        }
    }
}
