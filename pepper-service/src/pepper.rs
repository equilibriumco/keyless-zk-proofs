use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// POC-grade default secret. Used ONLY when the operator hasn't supplied
/// one via the `PEPPER_SECRET` env var — and in that case the service logs
/// a warning at startup. Production must supply a real, high-entropy secret
/// sourced from an HSM / KMS.
pub const DEFAULT_SECRET_FOR_POC: &[u8] = b"movement-keyless-poc-pepper-key-not-secure";

/// Derive a 31-byte pepper from `(sub, aud)` using HMAC-SHA256 with the given
/// server secret.
///
/// The pepper is deterministic in `(secret, sub, aud)`: the same user always
/// gets the same pepper, and therefore the same on-chain address. Rotating
/// the secret is effectively not supported in this POC — any new secret
/// would orphan every account derived from the old one.
///
/// # Errors
///
/// Returns an error if the HMAC computation fails (should not happen for
/// HMAC-SHA256 with any valid key).
///
/// # Panics
///
/// Panics if the HMAC key is rejected, which cannot happen for HMAC-SHA256
/// (it accepts keys of any length).
pub fn derive_pepper(secret: &[u8], sub: &str, aud: &str) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    let input = format!("{sub}:{aud}");
    mac.update(input.as_bytes());
    let result = mac.finalize().into_bytes();
    // Take first 31 bytes (248 bits) so the pepper fits in a BN254 scalar field element.
    Ok(result[..31].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pepper_is_deterministic() {
        let p1 = derive_pepper(DEFAULT_SECRET_FOR_POC, "user-123", "my-app.example.com").unwrap();
        let p2 = derive_pepper(DEFAULT_SECRET_FOR_POC, "user-123", "my-app.example.com").unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_pepper_differs_for_different_inputs() {
        let p1 = derive_pepper(DEFAULT_SECRET_FOR_POC, "user-123", "my-app.example.com").unwrap();
        let p2 = derive_pepper(DEFAULT_SECRET_FOR_POC, "user-456", "my-app.example.com").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_pepper_differs_for_different_secrets() {
        let p1 = derive_pepper(b"secret-one", "user-123", "my-app.example.com").unwrap();
        let p2 = derive_pepper(b"secret-two", "user-123", "my-app.example.com").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_pepper_fits_in_bn254_field() {
        let pepper =
            derive_pepper(DEFAULT_SECRET_FOR_POC, "user-123", "my-app.example.com").unwrap();
        assert_eq!(pepper.len(), 31);
    }
}
