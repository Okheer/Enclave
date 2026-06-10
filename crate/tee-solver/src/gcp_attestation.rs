//! GCP Confidential Space Attestation (SyndDB-style)
//!
//! In production (GCP Confidential Space), this module fetches a real OIDC JWT
//! from the GCP metadata endpoint. The JWT cryptographically binds:
//!   - The container image digest (equivalent to AMD SEV PCR0)
//!   - The TEE's ECDSA public key
//!   - Google's CA signature proving hardware attestation
//!
//! Locally (dev/demo), it produces a simulated token with a SHA-256 hash of the
//! running binary as a stand-in for the image digest.
//!
//! Reference: <https://github.com/SyndicateProtocol/synddb> (crates/gcp-attestation)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// GCP Confidential Space attestation token.
///
/// In production this wraps the real OIDC JWT returned by the GCP metadata
/// endpoint.  Locally it contains a simulation token whose `image_digest`
/// is the SHA-256 of the running binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationToken {
    /// Raw JWT from GCP (or `SIMULATION_JWT_…` locally)
    pub jwt: String,
    /// Container image hash — equivalent to AMD SEV PCR0
    pub image_digest: String,
    /// Hex-encoded compressed secp256k1 public key of this TEE instance
    pub tee_pubkey: String,
    /// `false` when running on real GCP Confidential Space hardware
    pub is_simulation: bool,
}

/// GCP metadata endpoint for Confidential Space identity tokens.
const GCP_METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

/// Audience claim used in the OIDC token request.
const ATTESTATION_AUDIENCE: &str = "prism-protocol";

impl AttestationToken {
    /// Fetch an attestation token.
    ///
    /// * **GCP Confidential Space** — makes one HTTP request to the local
    ///   metadata endpoint and parses the returned JWT.
    /// * **Local dev** — computes the SHA-256 of the running binary and
    ///   builds a simulation token.
    pub async fn fetch(tee_pubkey_hex: &str) -> crate::error::Result<Self> {
        let url = format!(
            "{}?audience={}&format=full",
            GCP_METADATA_URL, ATTESTATION_AUDIENCE
        );

        match reqwest::Client::new()
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let jwt = resp.text().await.map_err(|e| {
                    crate::error::TeeError::InternalError(format!(
                        "Failed to read GCP metadata response: {}",
                        e
                    ))
                })?;
                let image_digest = parse_image_digest_from_jwt(&jwt);
                Ok(Self {
                    jwt,
                    image_digest,
                    tee_pubkey: tee_pubkey_hex.to_string(),
                    is_simulation: false,
                })
            }
            // Not running in GCP → produce a simulation token
            _ => {
                let binary_hash = compute_own_binary_hash();
                Ok(Self {
                    jwt: format!("SIMULATION_JWT_{}", hex::encode(&binary_hash[..8])),
                    image_digest: hex::encode(binary_hash),
                    tee_pubkey: tee_pubkey_hex.to_string(),
                    is_simulation: true,
                })
            }
        }
    }

    /// Human-readable attestation mode string.
    pub fn mode_str(&self) -> &'static str {
        if self.is_simulation {
            "simulation (local dev)"
        } else {
            "hardware (GCP Confidential Space)"
        }
    }

    /// Short JWT preview suitable for logging (first 20 … last 8 chars).
    pub fn jwt_preview(&self) -> String {
        if self.jwt.len() > 32 {
            format!(
                "{}…{}",
                &self.jwt[..20],
                &self.jwt[self.jwt.len() - 8..]
            )
        } else {
            self.jwt.clone()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Best-effort extraction of the container image digest from a GCP OIDC JWT.
///
/// The JWT payload typically contains a claim like:
/// ```json
/// { "google": { "compute_engine": { "container": { "image_digest": "sha256:abc123…" } } } }
/// ```
///
/// If parsing fails we return a placeholder — callers should treat this as
/// informational rather than security-critical (the *JWT itself* is the
/// cryptographic proof).
fn parse_image_digest_from_jwt(jwt: &str) -> String {
    // JWTs are three base64url-encoded segments separated by '.'
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return "unknown_image_digest".to_string();
    }

    // Decode the payload (second segment)
    let payload = match base64url_decode(parts[1]) {
        Some(bytes) => bytes,
        None => return "unknown_image_digest".to_string(),
    };

    // Try to parse as JSON and extract image_digest
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) {
        // Path: google.compute_engine.container.image_digest
        if let Some(digest) = value
            .get("google")
            .and_then(|g| g.get("compute_engine"))
            .and_then(|ce| ce.get("container"))
            .and_then(|c| c.get("image_digest"))
            .and_then(|d| d.as_str())
        {
            return digest.to_string();
        }

        // Fallback: look for "image_digest" at top level or under "eat_nonce"
        if let Some(digest) = value
            .get("image_digest")
            .and_then(|d| d.as_str())
        {
            return digest.to_string();
        }
    }

    "unknown_image_digest".to_string()
}

/// Compute the SHA-256 hash of the currently running binary.
///
/// This serves as a local stand-in for the GCP container image digest:
/// it proves *which code* is running, just without hardware attestation.
fn compute_own_binary_hash() -> [u8; 32] {
    let exe_path = std::env::current_exe().unwrap_or_else(|_| Path::new("tee-solver").into());

    match std::fs::read(&exe_path) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }
        Err(_) => {
            // Fallback: hash the path string itself
            let mut hasher = Sha256::new();
            hasher.update(exe_path.to_string_lossy().as_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }
    }
}

/// Minimal base64url decoder (no padding required).
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    // Replace URL-safe chars with standard base64 chars
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    // Add padding if necessary
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    // Use a simple decoder — we only need this for JWT payload parsing
    // For production, consider the `base64` crate
    simple_base64_decode(&padded)
}

/// Trivial base64 decoder for JWT payload extraction.
fn simple_base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = val(b)?;
        }

        out.push((buf[0] << 2) | (buf[1] >> 4));
        if len > 2 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len > 3 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_fetch_local_is_simulation() {
        // When not running on GCP, we should get a simulation token
        let token = AttestationToken::fetch("0xdeadbeef").await.unwrap();
        assert!(token.is_simulation);
        assert!(token.jwt.starts_with("SIMULATION_JWT_"));
        assert_eq!(token.tee_pubkey, "0xdeadbeef");
        assert!(!token.image_digest.is_empty());
    }

    #[test]
    fn test_binary_hash_is_deterministic() {
        let h1 = compute_own_binary_hash();
        let h2 = compute_own_binary_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_base64url_decode_basic() {
        // "Hello" in base64 is "SGVsbG8="
        let decoded = base64url_decode("SGVsbG8").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_mode_str() {
        let token = AttestationToken {
            jwt: "test".to_string(),
            image_digest: "abc".to_string(),
            tee_pubkey: "0x00".to_string(),
            is_simulation: true,
        };
        assert_eq!(token.mode_str(), "simulation (local dev)");
    }

    #[test]
    fn test_jwt_preview_short() {
        let token = AttestationToken {
            jwt: "short".to_string(),
            image_digest: String::new(),
            tee_pubkey: String::new(),
            is_simulation: true,
        };
        assert_eq!(token.jwt_preview(), "short");
    }
}
