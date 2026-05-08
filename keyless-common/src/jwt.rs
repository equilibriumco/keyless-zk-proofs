use anyhow::{ensure, Context, Result};
use base64::URL_SAFE_NO_PAD;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub kid: String,
    #[serde(default)]
    pub typ: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub nonce: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ParsedJwt {
    pub header: JwtHeader,
    pub payload: JwtPayload,
    /// The `header.payload` portion of the JWT (the signed part).
    pub signed_part: String,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
    /// The raw JSON bytes of the header.
    pub raw_header_json: Vec<u8>,
    /// The raw JSON bytes of the payload.
    pub raw_payload_json: Vec<u8>,
}

/// Parse a JWT string into its constituent parts.
///
/// # Errors
///
/// Returns an error if the JWT does not have exactly three dot-separated parts,
/// if any part is not valid base64url, or if the header/payload are not valid JSON.
pub fn parse_jwt(jwt: &str) -> Result<ParsedJwt> {
    let parts: Vec<&str> = jwt.split('.').collect();
    ensure!(
        parts.len() == 3,
        "JWT must have exactly 3 dot-separated parts, got {}",
        parts.len()
    );

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let raw_header_json = base64::decode_config(header_b64, URL_SAFE_NO_PAD)
        .context("failed to base64url-decode JWT header")?;
    let raw_payload_json = base64::decode_config(payload_b64, URL_SAFE_NO_PAD)
        .context("failed to base64url-decode JWT payload")?;
    let signature = base64::decode_config(signature_b64, URL_SAFE_NO_PAD)
        .context("failed to base64url-decode JWT signature")?;

    let header: JwtHeader =
        serde_json::from_slice(&raw_header_json).context("failed to deserialize JWT header")?;
    let payload: JwtPayload =
        serde_json::from_slice(&raw_payload_json).context("failed to deserialize JWT payload")?;

    let signed_part = format!("{header_b64}.{payload_b64}");

    Ok(ParsedJwt {
        header,
        payload,
        signed_part,
        signature,
        raw_header_json,
        raw_payload_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode_json(value: &serde_json::Value) -> String {
        base64::encode_config(serde_json::to_vec(value).unwrap(), URL_SAFE_NO_PAD)
    }

    #[test]
    fn test_parse_jwt_extracts_fields() {
        let header = serde_json::json!({
            "alg": "RS256",
            "kid": "test-key-id",
            "typ": "JWT"
        });
        let payload = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "1234567890",
            "aud": "my-app.example.com",
            "nonce": "test-nonce-value",
            "iat": 1_700_000_000_u64,
            "exp": 1_700_003_600_u64,
            "email": "user@example.com",
            "email_verified": true
        });

        let header_b64 = encode_json(&header);
        let payload_b64 = encode_json(&payload);
        let fake_sig = base64::encode_config(b"fake-signature", URL_SAFE_NO_PAD);
        let jwt = format!("{header_b64}.{payload_b64}.{fake_sig}");

        let parsed = parse_jwt(&jwt).expect("should parse successfully");

        assert_eq!(parsed.header.alg, "RS256");
        assert_eq!(parsed.header.kid, "test-key-id");
        assert_eq!(parsed.header.typ.as_deref(), Some("JWT"));

        assert_eq!(parsed.payload.iss, "https://accounts.google.com");
        assert_eq!(parsed.payload.sub, "1234567890");
        assert_eq!(parsed.payload.aud, "my-app.example.com");
        assert_eq!(parsed.payload.nonce, "test-nonce-value");
        assert_eq!(parsed.payload.iat, 1_700_000_000);
        assert_eq!(parsed.payload.exp, 1_700_003_600);
        assert_eq!(parsed.payload.email.as_deref(), Some("user@example.com"));
        assert_eq!(parsed.payload.email_verified, Some(true));

        assert_eq!(parsed.signed_part, format!("{header_b64}.{payload_b64}"));
        assert_eq!(parsed.signature, b"fake-signature");
    }

    #[test]
    fn test_parse_jwt_rejects_malformed() {
        assert!(parse_jwt("not-a-jwt").is_err());
        assert!(parse_jwt("two.parts").is_err());
        // Three parts but invalid base64
        assert!(parse_jwt("!!!.@@@.###").is_err());
    }
}
