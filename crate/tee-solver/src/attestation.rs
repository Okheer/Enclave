use crate::error::{Result, TeeError};
use crate::types::{Intent, QuoteData};
use alloy_primitives::{Address, U256};
use chrono::{DateTime, Utc};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::SecretKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Attestation emitted by TEE after selecting winning quote.
///
/// The `hash()` method produces keccak256 of the ABI-encoded fields — identical to
/// what `SolvexVerifier.compute_attestation_hash(attestation_data)` computes onchain.
/// The `signature` field is a compact 65-byte `(r[32] || s[32] || v[1])` usable
/// directly by the EVM `ecrecover` precompile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    pub intent_hash: [u8; 32],
    pub winner_solver: String,
    pub fill_route: Address,
    pub output_amount: U256,
    pub block_number: u64,
    pub prev_attest_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    /// Compact 65-byte ECDSA signature: r[32] || s[32] || v[1] (v = 27 or 28)
    pub signature: Vec<u8>,
}

impl Attestation {
    /// ABI-encode the attestation fields in the same layout that Stylus expects:
    ///
    /// ```solidity
    /// struct Attestation {
    ///     bytes32 intentHash;      // slot 0
    ///     address winnerSolver;    // slot 1 (left-padded to 32)
    ///     address fillRoute;       // slot 2 (left-padded to 32)
    ///     uint256 outputAmount;    // slot 3
    ///     uint64  blockNumber;     // slot 4 (right-aligned in 32-byte slot)
    ///     bytes32 prevAttestHash;  // slot 5
    /// }
    /// ```
    ///
    /// This is the raw bytes `P1` passes as `attestation_data` to
    /// `SolvexVerifier.verify(intent_hash, attestation_data, tee_sig)`.
    pub fn to_abi_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192); // 6 × 32 bytes

        // slot 0 — intentHash (bytes32)
        buf.extend_from_slice(&self.intent_hash);

        // slot 1 — winnerSolver (address, 12 zero bytes + 20 addr bytes)
        let winner_addr = Address::parse_checksummed(&self.winner_solver, None)
            .unwrap_or(Address::ZERO);
        let mut addr_slot = [0u8; 32];
        addr_slot[12..].copy_from_slice(winner_addr.as_slice());
        buf.extend_from_slice(&addr_slot);

        // slot 2 — fillRoute (address, same padding)
        let mut fill_slot = [0u8; 32];
        fill_slot[12..].copy_from_slice(self.fill_route.as_slice());
        buf.extend_from_slice(&fill_slot);

        // slot 3 — outputAmount (uint256, big-endian)
        buf.extend_from_slice(&self.output_amount.to_be_bytes::<32>());

        // slot 4 — blockNumber (uint64 right-aligned in 32-byte slot)
        let mut block_slot = [0u8; 32];
        block_slot[24..].copy_from_slice(&self.block_number.to_be_bytes());
        buf.extend_from_slice(&block_slot);

        // slot 5 — prevAttestHash (bytes32)
        buf.extend_from_slice(&self.prev_attest_hash);

        buf
    }

    /// Compute keccak256 of the ABI-encoded attestation.
    ///
    /// This value is what the TEE signs and what `SolvexVerifier` reconstructs
    /// via `compute_attestation_hash(attestation_data)` before calling `ecrecover`.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let bytes = self.to_abi_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AttestationSigner
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the TEE's secp256k1 signing key pair.
///
/// `sign_hash` produces compact 65-byte `(r || s || v)` signatures — the exact
/// format the EVM `ecrecover` precompile inside `SolvexVerifier` expects.
pub struct AttestationSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AttestationSigner {
    /// Create a new signer with a random key.
    pub fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Create a signer from a fixed 32-byte seed (deterministic — for testing only).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_slice(seed)
            .map_err(|e| TeeError::CryptoError(format!("Invalid seed: {:?}", e)))?;
        let signing_key = SigningKey::from(secret);
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Compressed (33-byte) secp256k1 public key — register this in `SolverRegistry.sol`.
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.verifying_key.to_encoded_point(true).as_bytes().to_vec())
    }

    /// Uncompressed (65-byte) secp256k1 public key.
    pub fn get_public_key_uncompressed(&self) -> Result<Vec<u8>> {
        Ok(self.verifying_key.to_encoded_point(false).as_bytes().to_vec())
    }

    /// Derive the Ethereum address from the TEE's public key
    /// (keccak256 of uncompressed pubkey, last 20 bytes).
    /// This is what `SolverRegistry` stores and what `ecrecover` must return.
    pub fn ethereum_address(&self) -> Result<Address> {
        let uncompressed = self.get_public_key_uncompressed()?;
        // Skip the 0x04 prefix byte → hash the 64-byte X||Y point
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]);
        let hash = hasher.finalize();
        Ok(Address::from_slice(&hash[12..]))
    }

    /// Create and sign an attestation from a full `Intent`.
    pub fn create_attestation(
        &self,
        intent: &Intent,
        winning_quote: &QuoteData,
        block_number: u64,
        prev_attest_hash: [u8; 32],
    ) -> Result<Attestation> {
        self.build_attestation(
            intent.hash(),
            winning_quote,
            block_number,
            prev_attest_hash,
        )
    }

    /// Create and sign an attestation when only the intent hash is available
    /// (used by the `/finalize` API endpoint).
    pub fn create_attestation_with_hash(
        &self,
        intent_hash: &[u8; 32],
        winning_quote: &QuoteData,
        block_number: u64,
        prev_attest_hash: [u8; 32],
    ) -> Result<Attestation> {
        self.build_attestation(*intent_hash, winning_quote, block_number, prev_attest_hash)
    }

    fn build_attestation(
        &self,
        intent_hash: [u8; 32],
        winning_quote: &QuoteData,
        block_number: u64,
        prev_attest_hash: [u8; 32],
    ) -> Result<Attestation> {
        let mut attestation = Attestation {
            intent_hash,
            winner_solver: winning_quote.solver_id.clone(),
            fill_route: winning_quote.fill_route,
            output_amount: winning_quote.output_amount,
            block_number,
            prev_attest_hash,
            timestamp: chrono::Utc::now(),
            signature: Vec::new(),
        };

        // hash() uses ABI encoding — consistent with what Stylus will verify
        let hash = attestation.hash()?;
        attestation.signature = self.sign_hash(&hash)?;
        Ok(attestation)
    }

    /// Sign a 32-byte prehash.
    ///
    /// Returns a compact **65-byte** signature: `r[32] || s[32] || v[1]`
    /// where `v` is the Ethereum recovery id (27 or 28).
    ///
    /// This format is required by the EVM `ecrecover` precompile (0x01)
    /// used in `SolvexVerifier.ecrecover_signer()`.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        use ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{RecoveryId, Signature};

        let (sig, recid): (Signature, RecoveryId) = self
            .signing_key
            .sign_prehash(hash)
            .map_err(|e| TeeError::CryptoError(format!("Signing failed: {:?}", e)))?;

        // Compact 64-byte r||s
        let sig_bytes = sig.to_bytes();
        // Ethereum convention: v = 27 + recovery_id
        let v: u8 = recid.to_byte() + 27;

        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig_bytes);
        out.push(v);
        Ok(out)
    }

    /// Verify a compact 65-byte `(r || s || v)` signature.
    ///
    /// Drops the `v` byte and uses `PrehashVerifier` — no digest re-computation.
    pub fn verify_signature(&self, hash: &[u8; 32], signature_bytes: &[u8]) -> Result<bool> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::Signature;

        if signature_bytes.len() != 65 {
            return Err(TeeError::CryptoError(format!(
                "Expected 65-byte compact signature, got {}",
                signature_bytes.len()
            )));
        }

        // r || s are bytes 0..64; v (byte 64) is not needed for verification
        let sig = Signature::from_bytes(signature_bytes[..64].into())
            .map_err(|e| TeeError::CryptoError(format!("Invalid signature bytes: {:?}", e)))?;

        match self.verifying_key.verify_prehash(hash, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for AttestationSigner {
    fn default() -> Self {
        Self::new().expect("Failed to create default AttestationSigner")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn make_intent() -> Intent {
        Intent {
            user: Address::ZERO,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: U256::from(1000u64),
            min_amount_out: U256::from(900u64),
            deadline: 9_999_999_999,
            nonce: 1,
        }
    }

    fn make_quote() -> QuoteData {
        QuoteData {
            output_amount: U256::from(950u64),
            fill_route: Address::ZERO,
            gas_estimate: U256::from(100_000u64),
            timestamp: Utc::now(),
            solver_id: "solver1".to_string(),
        }
    }

    #[test]
    fn test_signer_creation() {
        let signer = AttestationSigner::new().unwrap();
        let pubkey = signer.get_public_key().unwrap();
        assert_eq!(pubkey.len(), 33, "Compressed public key must be 33 bytes");
    }

    #[test]
    fn test_signer_from_seed_is_deterministic() {
        let seed = [1u8; 32];
        let s1 = AttestationSigner::from_seed(&seed).unwrap();
        let s2 = AttestationSigner::from_seed(&seed).unwrap();
        assert_eq!(s1.get_public_key().unwrap(), s2.get_public_key().unwrap());
    }

    #[test]
    fn test_sign_produces_65_bytes() {
        let signer = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = signer.sign_hash(&hash).unwrap();
        assert_eq!(sig.len(), 65, "Compact signature must be exactly 65 bytes");
    }

    #[test]
    fn test_v_is_27_or_28() {
        let signer = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = signer.sign_hash(&hash).unwrap();
        let v = sig[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28, got {}", v);
    }

    #[test]
    fn test_signature_verification_roundtrip() {
        let signer = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = signer.sign_hash(&hash).unwrap();
        assert!(signer.verify_signature(&hash, &sig).unwrap());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let s1 = AttestationSigner::new().unwrap();
        let s2 = AttestationSigner::new().unwrap();
        let hash = [42u8; 32];
        let sig = s1.sign_hash(&hash).unwrap();
        // Different key must not verify
        assert!(!s2.verify_signature(&hash, &sig).unwrap());
    }

    #[test]
    fn test_abi_encoding_is_192_bytes() {
        let signer = AttestationSigner::new().unwrap();
        let attestation = signer
            .create_attestation(&make_intent(), &make_quote(), 100, [0u8; 32])
            .unwrap();
        assert_eq!(
            attestation.to_abi_bytes().len(),
            192,
            "ABI-encoded attestation must be 6 × 32 = 192 bytes"
        );
    }

    #[test]
    fn test_attestation_hash_is_deterministic() {
        let signer = AttestationSigner::new().unwrap();
        let a = signer
            .create_attestation(&make_intent(), &make_quote(), 100, [0u8; 32])
            .unwrap();
        assert_eq!(a.hash().unwrap(), a.hash().unwrap());
    }

    #[test]
    fn test_attestation_signature_valid() {
        let signer = AttestationSigner::new().unwrap();
        let att = signer
            .create_attestation(&make_intent(), &make_quote(), 100, [0u8; 32])
            .unwrap();
        let hash = att.hash().unwrap();
        assert!(signer.verify_signature(&hash, &att.signature).unwrap());
    }

    #[test]
    fn test_ethereum_address_length() {
        let signer = AttestationSigner::new().unwrap();
        let addr = signer.ethereum_address().unwrap();
        assert_ne!(addr, Address::ZERO, "TEE Ethereum address must not be zero");
    }
}
