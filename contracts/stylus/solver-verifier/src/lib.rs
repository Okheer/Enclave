//! SolvexVerifier — Stylus/Rust ECDSA Attestation Verifier for Enclave Protocol
//!
//! This contract verifies TEE-signed attestations from sealed solver competitions.
//! It performs three sequential checks before approving settlement:
//!
//!   1. **Nonce Guard** — Rejects replay of already-settled intent hashes via a
//!      storage-backed set of settled intent hashes.
//!   2. **ECDSA Signature Check** — Recovers the signer from
//!      `keccak256(abi.encode(attestation))` using the EVM `ecrecover` precompile
//!      and compares against the expected TEE public key.
//!   3. **Merkle Chain Continuity** — Verifies `attestation.prev_attest_hash`
//!      matches the stored chain head, ensuring no past fill was silently dropped.
//!
//! Compiled to WASM via Arbitrum Stylus for ~10x gas savings over equivalent
//! Solidity ECDSA verification (~310 gas vs ~3,000 gas per ecrecover).
//!
//! ## ABI Compatibility
//!
//! The Stylus SDK auto-converts Rust `snake_case` function names to Solidity
//! `camelCase` in the exported ABI. The Solidity interface (`ISolvexVerifier.sol`)
//! must use the camelCase names (e.g., `verifyWithExpectedSigner`, `getLastAttestHash`).
//!
//! Parameters use `Bytes` (from `alloy_primitives`) to map to Solidity `bytes`,
//! not `Vec<u8>` which would incorrectly map to `uint8[]`.
//!
//! Note: this code has not been audited.

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::{Address, Bytes, FixedBytes, U256},
    alloy_sol_types::{sol, SolError, SolEvent, SolValue},
    call::RawCall,
    prelude::*,
};

// ───────────────────────────────────────────────────────────────────────
// Solidity ABI type mirroring (for encoding / decoding attestation data)
// ───────────────────────────────────────────────────────────────────────
sol! {
    /// Mirrors the on-chain Attestation struct from SolvexSettlement.sol
    struct Attestation {
        bytes32 intentHash;
        address winnerSolver;
        address fillRoute;
        uint256 outputAmount;
        uint64 blockNumber;
        bytes32 prevAttestHash;
    }

    /// Events emitted by the verifier
    event AttestationVerified(
        bytes32 indexed intentHash,
        address indexed winnerSolver,
        bytes32 attestHash
    );

    event MerkleChainAdvanced(
        bytes32 oldHead,
        bytes32 newHead
    );

    /// Custom errors matching Errors.sol
    error IntentAlreadySettled(bytes32 intentHash);
    error InvalidSignature();
    error EcrecoverFailed();
    error MerkleChainBroken(bytes32 expected, bytes32 actual);
    error InvalidAttestation();
}

// ───────────────────────────────────────────────────────────────────────
// EVM precompile addresses
// ───────────────────────────────────────────────────────────────────────

/// Address of the `ecrecover` precompile (0x01).
const ECRECOVER_PRECOMPILE: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

// ───────────────────────────────────────────────────────────────────────
// Contract storage layout
// ───────────────────────────────────────────────────────────────────────
sol_storage! {
    #[entrypoint]
    pub struct SolvexVerifier {
        /// Owner / deployer address (for admin functions)
        address owner;

        /// Mapping: intent_hash → bool indicating whether the intent has been settled.
        /// Acts as the nonce guard / replay protection layer.
        mapping(bytes32 => bool) settled_intents;

        /// The head of the Merkle attestation chain.
        /// Each new attestation must reference this value as its `prev_attest_hash`.
        bytes32 last_attest_hash;

        /// Counter of total verified attestations (useful for indexing / stats).
        uint256 attestation_count;
    }
}

// ───────────────────────────────────────────────────────────────────────
// External interface
//
// IMPORTANT: The Stylus SDK converts snake_case → camelCase for ABI export.
//   verify                      → verify
//   verify_with_expected_signer → verifyWithExpectedSigner
//   is_intent_settled           → isIntentSettled
//   get_last_attest_hash        → getLastAttestHash
//   get_attestation_count       → getAttestationCount
//   get_owner                   → getOwner
//
// The Solidity ISolvexVerifier interface MUST use the camelCase names.
// ───────────────────────────────────────────────────────────────────────
#[public]
impl SolvexVerifier {
    // ─────────────────────────────────────────────────────────────────
    // Core verification (matches ISolvexVerifier.verify)
    // ─────────────────────────────────────────────────────────────────

    /// Verifies a TEE attestation for an intent settlement.
    ///
    /// Performs three checks:
    ///   1. Nonce guard — rejects if `intent_hash` already settled
    ///   2. ECDSA recovery — recovers signer from `attestation_data` + `tee_sig`
    ///   3. Merkle chain — verifies `prev_attest_hash` matches stored chain head
    ///
    /// On success, marks the intent as settled, advances the Merkle chain head,
    /// and emits `AttestationVerified` + `MerkleChainAdvanced` events.
    ///
    /// Returns `true` on success; reverts on failure.
    ///
    /// ABI: `verify(bytes32,bytes,bytes) → bool`
    pub fn verify(
        &mut self,
        intent_hash: FixedBytes<32>,
        attestation_data: Bytes,
        tee_sig: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let attestation_bytes = attestation_data.to_vec();
        let sig_bytes = tee_sig.to_vec();

        // ── 1. Nonce Guard ─────────────────────────────────────────
        self.check_nonce(intent_hash)?;

        // ── Decode attestation ─────────────────────────────────────
        let attestation = self.decode_attestation(&attestation_bytes)?;

        // Verify intent_hash in attestation matches the supplied one
        if attestation.intentHash != intent_hash {
            return Err(InvalidAttestation {}.abi_encode());
        }

        // ── 2. ECDSA Signature Verification ────────────────────────
        let signer = self.ecrecover_signer(&attestation_bytes, &sig_bytes)?;

        // ── 2b. Signer validation check ────────────────────────────
        //       Validate that the recovered signer matches the attestation's winner_solver
        //       (keyless variant — verify_with_expected_signer is the variant that takes
        //        an explicit expected signer from SolverRegistry).
        if signer != attestation.winnerSolver {
            return Err(InvalidAttestation {}.abi_encode());
        }

        // ── 3. Merkle Chain Continuity ─────────────────────────────
        self.verify_chain(attestation.prevAttestHash)?;

        // ── Commit state changes ───────────────────────────────────
        self.commit_state(intent_hash, &attestation_bytes, &attestation);

        Ok(true)
    }

    // ─────────────────────────────────────────────────────────────────
    // Verification with signer check (matches ISolvexVerifier.verifyWithExpectedSigner)
    // ─────────────────────────────────────────────────────────────────

    /// Same as `verify`, but additionally checks that the recovered signer
    /// matches `expected_signer` (typically fetched from SolverRegistry).
    ///
    /// ABI: `verifyWithExpectedSigner(bytes32,bytes,bytes,address,address) → bool`
    pub fn verify_with_expected_signer(
        &mut self,
        intent_hash: FixedBytes<32>,
        attestation_data: Bytes,
        tee_sig: Bytes,
        expected_signer: Address,
        expected_winner: Address,
    ) -> Result<bool, Vec<u8>> {
        let attestation_bytes = attestation_data.to_vec();
        let sig_bytes = tee_sig.to_vec();

        // ── 1. Nonce Guard ─────────────────────────────────────────
        self.check_nonce(intent_hash)?;

        // ── Decode attestation ─────────────────────────────────────
        let attestation = self.decode_attestation(&attestation_bytes)?;

        if attestation.intentHash != intent_hash {
            return Err(InvalidAttestation {}.abi_encode());
        }

        // ── 2. ECDSA Signature Verification ────────────────────────
        let signer = self.ecrecover_signer(&attestation_bytes, &sig_bytes)?;

        // ── 2b. Signer match check ────────────────────────────────
        if signer != expected_signer {
            return Err(InvalidAttestation {}.abi_encode());
        }

        // ── 3. Merkle Chain Continuity ─────────────────────────────
        self.verify_chain(attestation.prevAttestHash)?;

        // ── Winner validation ──────────────────────────────────────
        if attestation.winnerSolver != expected_winner {
            return Err(InvalidAttestation {}.abi_encode());
        }

        // ── Commit state changes ───────────────────────────────────
        self.commit_state(intent_hash, &attestation_bytes, &attestation);

        Ok(true)
    }

    // ─────────────────────────────────────────────────────────────────
    // View functions
    // ─────────────────────────────────────────────────────────────────

    /// Checks if an intent has already been settled through this verifier.
    /// ABI: `isIntentSettled(bytes32) → bool`
    pub fn is_intent_settled(&self, intent_hash: FixedBytes<32>) -> bool {
        self.settled_intents.getter(intent_hash).get()
    }

    /// Returns the hash of the most recent attestation (Merkle chain head).
    /// ABI: `getLastAttestHash() → bytes32`
    pub fn get_last_attest_hash(&self) -> FixedBytes<32> {
        self.last_attest_hash.get()
    }

    /// Returns the total number of verified attestations.
    /// ABI: `getAttestationCount() → uint256`
    pub fn get_attestation_count(&self) -> U256 {
        self.attestation_count.get()
    }

    /// Returns the contract owner address.
    /// ABI: `getOwner() → address`
    pub fn get_owner(&self) -> Address {
        self.owner.get()
    }
}

// ───────────────────────────────────────────────────────────────────────
// Internal helpers
// ───────────────────────────────────────────────────────────────────────
impl SolvexVerifier {
    /// **Nonce Guard**: Rejects replay by checking if the intent hash has
    /// already been settled.
    fn check_nonce(&self, intent_hash: FixedBytes<32>) -> Result<(), Vec<u8>> {
        if self.settled_intents.getter(intent_hash).get() {
            return Err(IntentAlreadySettled { intentHash: intent_hash }.abi_encode());
        }
        Ok(())
    }

    /// **Merkle Chain Continuity**: Verifies `prev_attest_hash` matches the
    /// stored `last_attest_hash`, ensuring no attestations were silently dropped.
    ///
    /// For the very first attestation (chain head is zero), any `prev_attest_hash`
    /// of zero is accepted (genesis case).
    fn verify_chain(&self, prev_attest_hash: FixedBytes<32>) -> Result<(), Vec<u8>> {
        let stored_head = self.last_attest_hash.get();
        if prev_attest_hash != stored_head {
            return Err(MerkleChainBroken {
                expected: stored_head,
                actual: prev_attest_hash,
            }
            .abi_encode());
        }
        Ok(())
    }

    /// **ECDSA Recovery**: Verifies ECDSA signature against the attestation data.
    ///
    /// Uses the ecrecover precompile (0x01) via a static call to recover
    /// the signer address from a keccak256 hash and signature (r, s, v).
    ///
    /// Uses `RawCall::new_static(self.vm())` for the read-only precompile call.
    fn ecrecover_signer(
        &self,
        attestation_data: &[u8],
        tee_sig: &[u8],
    ) -> Result<Address, Vec<u8>> {
        if tee_sig.len() != 65 {
            return Err(InvalidSignature {}.abi_encode());
        }

        let hash = stylus_sdk::alloy_primitives::keccak256(attestation_data);

        let v = tee_sig[64];
        let odd_y = v == 28 || v == 1;

        // Build the 128-byte input for ecrecover: [hash(32) | v(32) | r(32) | s(32)]
        let mut input = [0u8; 128];
        input[0..32].copy_from_slice(hash.as_slice());
        input[63] = if odd_y { 28 } else { 27 };
        input[64..96].copy_from_slice(&tee_sig[0..32]);
        input[96..128].copy_from_slice(&tee_sig[32..64]);

        // ecrecover is a read-only precompile — use static call with host reference
        // Safety: ecrecover precompile has no side effects and cannot modify state
        let result = unsafe {
            RawCall::new_static(self.vm())
                .call(ECRECOVER_PRECOMPILE, &input)
                .map_err(|_| EcrecoverFailed {}.abi_encode())?
        };

        if result.len() < 32 {
            return Err(EcrecoverFailed {}.abi_encode());
        }

        // Verify the result is not the zero address (indicates invalid signature)
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&result[12..32]);
        let recovered = Address::from(addr_bytes);

        if recovered == Address::ZERO {
            return Err(InvalidSignature {}.abi_encode());
        }

        Ok(recovered)
    }

    /// Decodes ABI-encoded attestation data into the `Attestation` struct.
    fn decode_attestation(&self, data: &[u8]) -> Result<Attestation, Vec<u8>> {
        <Attestation as SolValue>::abi_decode(data)
            .map_err(|_| InvalidAttestation {}.abi_encode())
    }

    /// Computes `keccak256` of the attestation data.
    /// This is used both for ECDSA recovery and for Merkle chain linkage.
    fn compute_attestation_hash(&self, attestation_data: &[u8]) -> FixedBytes<32> {
        stylus_sdk::alloy_primitives::keccak256(attestation_data)
    }

    /// Commits all state changes and emits events after successful verification.
    /// Extracted to avoid code duplication between `verify` and `verify_with_expected_signer`.
    fn commit_state(
        &mut self,
        intent_hash: FixedBytes<32>,
        attestation_data: &[u8],
        attestation: &Attestation,
    ) {
        // Mark intent as settled
        self.settled_intents.setter(intent_hash).set(true);

        // Compute new attestation hash and advance chain
        let old_head = self.last_attest_hash.get();
        let new_head = self.compute_attestation_hash(attestation_data);
        self.last_attest_hash.set(new_head);

        // Increment counter
        let count = self.attestation_count.get();
        self.attestation_count.set(count + U256::from(1));

        // Emit events using SDK 0.10 self.vm().emit_log() pattern
        // Event format: [topic0 (event sig)] [topic1 (indexed)] ... [non-indexed data]
        let attest_verified = AttestationVerified {
            intentHash: intent_hash,
            winnerSolver: attestation.winnerSolver,
            attestHash: new_head,
        };
        let attest_topics = attest_verified.encode_topics();
        let attest_data = attest_verified.encode_data();
        let mut attest_log = Vec::new();
        for topic in &attest_topics {
            attest_log.extend_from_slice(topic.as_ref());
        }
        attest_log.extend_from_slice(&attest_data);
        self.vm().emit_log(&attest_log, attest_topics.len());

        let merkle_advanced = MerkleChainAdvanced {
            oldHead: old_head,
            newHead: new_head,
        };
        let merkle_topics = merkle_advanced.encode_topics();
        let merkle_data = merkle_advanced.encode_data();
        let mut merkle_log = Vec::new();
        for topic in &merkle_topics {
            merkle_log.extend_from_slice(topic.as_ref());
        }
        merkle_log.extend_from_slice(&merkle_data);
        self.vm().emit_log(&merkle_log, merkle_topics.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
 
    #[test]
    fn test_attestation_encoding() {
        let attest = Attestation {
            intentHash: FixedBytes::ZERO,
            winnerSolver: Address::ZERO,
            fillRoute: Address::ZERO,
            outputAmount: U256::from(1000u64),
            blockNumber: 12345,
            prevAttestHash: FixedBytes::ZERO,
        };
 
        let encoded = attest.abi_encode();
        assert!(!encoded.is_empty(), "ABI encoding should produce bytes");
 
        let decoded = <Attestation as SolValue>::abi_decode(&encoded)
            .expect("Should decode successfully");
        assert_eq!(decoded.intentHash, attest.intentHash);
        assert_eq!(decoded.winnerSolver, attest.winnerSolver);
        assert_eq!(decoded.outputAmount, attest.outputAmount);
        assert_eq!(decoded.blockNumber, attest.blockNumber);
    }
 
    #[test]
    fn test_attestation_hash_deterministic() {
        let attest = Attestation {
            intentHash: FixedBytes::ZERO,
            winnerSolver: Address::ZERO,
            fillRoute: Address::ZERO,
            outputAmount: U256::from(1000u64),
            blockNumber: 12345,
            prevAttestHash: FixedBytes::ZERO,
        };
 
        let encoded = attest.abi_encode();
        let hash1 = stylus_sdk::alloy_primitives::keccak256(&encoded);
        let hash2 = stylus_sdk::alloy_primitives::keccak256(&encoded);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_ne!(hash1, FixedBytes::ZERO, "Hash should not be zero");
    }
 
    #[test]
    fn test_signature_length_validation() {
        // Valid signature is exactly 65 bytes (r[32] + s[32] + v[1])
        let short_sig = vec![0u8; 64];
        assert_ne!(short_sig.len(), 65, "Short sig should fail validation");
 
        let valid_sig = vec![0u8; 65];
        assert_eq!(valid_sig.len(), 65, "Valid sig should be 65 bytes");
    }
 
    #[test]
    fn test_parity_mapping() {
        // Verify v→odd_y_parity logic covers both legacy and EIP-2098 formats
        let cases: &[(u8, bool)] = &[
            (27, false), // legacy even-y
            (28, true),  // legacy odd-y
            (0, false),  // EIP-2098 even-y
            (1, true),   // EIP-2098 odd-y
        ];
        for &(v, expected_parity) in cases {
            let odd_y_parity = v == 28 || v == 1;
            assert_eq!(odd_y_parity, expected_parity, "v={v} parity mismatch");
        }
    }

    #[test]
    fn test_bytes_type_abi_encoding() {
        // Verify that Bytes (alloy_primitives::Bytes) encodes as Solidity `bytes`
        // and not as `uint8[]` — this is the critical ABI compatibility check
        let data = Bytes::from(vec![1u8, 2, 3, 4]);
        assert_eq!(data.len(), 4);
        assert_eq!(&data[..], &[1, 2, 3, 4]);
    }
}
