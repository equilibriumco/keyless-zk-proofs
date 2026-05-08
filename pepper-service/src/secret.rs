//! Load the pepper HMAC secret from operator-supplied sources.
//!
//! Priority (first set wins):
//! 1. `PEPPER_SECRET_FILE` — path to a file containing the raw secret bytes.
//!    This is the production shape: Kubernetes secret volumes, Docker
//!    secrets, systemd credentials, and Vault-agent-injected files all
//!    surface the secret as a file on a tmpfs mount. The file's bytes are
//!    used as-is, with one convenience: a single trailing `\n` is trimmed
//!    so `echo "..." > secret` works in dev without changing the HMAC key
//!    relative to a raw-byte file.
//! 2. `PEPPER_SECRET` — hex-encoded string in the environment. Convenient
//!    for local dev / POC. Decoded to raw bytes before use so both sources
//!    land on the same byte string.
//! 3. Hardcoded POC default — insecure, logs a loud warning.
//!
//! Whatever the source, the loaded bytes are what HMAC-SHA256 uses as its
//! key; entropy must come from the operator (target ≥ 32 bytes / 256 bits).

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::pepper::DEFAULT_SECRET_FOR_POC;

/// Minimum accepted secret length in bytes. 32 = 256 bits, matching HMAC-SHA256's
/// security margin. Shorter inputs are rejected (except the built-in POC default,
/// which is accepted only because the warning log makes the weakness loud).
const MIN_SECRET_BYTES: usize = 32;

pub struct LoadedSecret {
    /// Zeroized on drop. The HMAC key lives in this buffer for the
    /// lifetime of the service; in a crash dump or heap-disclosure vuln
    /// only its in-flight HMAC ipad/opad copies remain (the `hmac` crate
    /// doesn't auto-zeroize those, but their lifetimes are per-request).
    pub bytes: Zeroizing<Vec<u8>>,
    pub source: &'static str,
}

/// Load the pepper secret from the environment per the priority list in the
/// module docs.
///
/// # Errors
///
/// Returns an error if a source is configured but unreadable / malformed.
/// Falling back to the POC default is not an error — just a warning.
pub fn load_secret() -> Result<LoadedSecret> {
    if let Ok(path) = env::var("PEPPER_SECRET_FILE") {
        if !path.is_empty() {
            return load_from_file(&PathBuf::from(path));
        }
    }

    if let Ok(hex_str) = env::var("PEPPER_SECRET") {
        if !hex_str.is_empty() {
            return load_from_env_hex(&hex_str);
        }
    }

    tracing::warn!(
        "No PEPPER_SECRET_FILE or PEPPER_SECRET set — falling back to the built-in POC default \
         key. This is insecure; provide a high-entropy secret in production (≥ 32 bytes)."
    );
    Ok(LoadedSecret {
        bytes: Zeroizing::new(DEFAULT_SECRET_FOR_POC.to_vec()),
        source: "built-in POC default (INSECURE)",
    })
}

fn load_from_file(path: &Path) -> Result<LoadedSecret> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read PEPPER_SECRET_FILE at {}", path.display()))?;
    // Wrap immediately so any subsequent allocation that copies these bytes
    // (e.g. `Vec::pop`'s internals do not re-allocate, but a caller could)
    // ends up zeroized when the wrapper drops.
    let mut bytes = Zeroizing::new(raw);
    // Convenience: trim a single trailing newline so files written with
    // `echo` don't produce a key that differs from the "raw bytes" intent.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.len() < MIN_SECRET_BYTES {
        bail!(
            "PEPPER_SECRET_FILE at {} contains {} bytes; need at least {MIN_SECRET_BYTES}",
            path.display(),
            bytes.len(),
        );
    }
    Ok(LoadedSecret {
        bytes,
        source: "PEPPER_SECRET_FILE",
    })
}

fn load_from_env_hex(hex_str: &str) -> Result<LoadedSecret> {
    let bytes = Zeroizing::new(
        hex::decode(hex_str.trim())
            .context("PEPPER_SECRET must be hex-encoded (e.g. `openssl rand -hex 32`)")?,
    );
    if bytes.len() < MIN_SECRET_BYTES {
        bail!(
            "PEPPER_SECRET decoded to {} bytes; need at least {MIN_SECRET_BYTES}",
            bytes.len(),
        );
    }
    Ok(LoadedSecret {
        bytes,
        source: "PEPPER_SECRET (hex)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn file_loader_reads_raw_bytes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let want = vec![0xABu8; 32];
        f.write_all(&want).unwrap();
        let got = load_from_file(f.path()).unwrap();
        assert_eq!(got.bytes.as_slice(), want.as_slice());
        assert_eq!(got.source, "PEPPER_SECRET_FILE");
    }

    #[test]
    fn file_loader_trims_single_trailing_newline() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = vec![0xCDu8; 32];
        bytes.push(b'\n');
        f.write_all(&bytes).unwrap();
        let got = load_from_file(f.path()).unwrap();
        assert_eq!(got.bytes.as_slice(), [0xCDu8; 32].as_slice());
    }

    #[test]
    fn file_loader_rejects_too_short() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 8]).unwrap();
        assert!(load_from_file(f.path()).is_err());
    }

    #[test]
    fn env_hex_decodes() {
        let hex_str = "a".repeat(64); // 32 bytes of 0xAA
        let got = load_from_env_hex(&hex_str).unwrap();
        assert_eq!(got.bytes.as_slice(), [0xAAu8; 32].as_slice());
        assert_eq!(got.source, "PEPPER_SECRET (hex)");
    }

    #[test]
    fn env_hex_rejects_non_hex() {
        assert!(load_from_env_hex("not hex at all!").is_err());
    }

    #[test]
    fn env_hex_rejects_too_short() {
        let hex_str = "abcd"; // 2 bytes
        assert!(load_from_env_hex(hex_str).is_err());
    }
}
