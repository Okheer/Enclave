use crate::attestation::Attestation;
use crate::error::{TeeError, Result};
use dashmap::DashMap;
use sha3::{Digest, Keccak256};
use parking_lot::RwLock;
use std::sync::Arc;

/// Merkle chain for attestation continuity
/// Each attestation includes hash of previous attestation:
/// prev_attest_hash = keccak256(prev_attestation)
/// This creates a continuous chain that prevents silent drops of historical fills
pub struct MerkleChain {
    /// Map of attestation hash -> full attestation
    chain: Arc<DashMap<[u8; 32], Attestation>>,
    /// Latest attestation hash (head of chain)
    latest_hash: Arc<RwLock<[u8; 32]>>,
    /// Chain length for monitoring
    length: Arc<RwLock<u64>>,
}

impl MerkleChain {
    pub fn new() -> Self {
        // Initialize latest_hash to genesis
        let genesis = Self::compute_genesis_hash();
        Self {
            chain: Arc::new(DashMap::new()),
            latest_hash: Arc::new(RwLock::new(genesis)),
            length: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the genesis (initial) hash - empty attestation
    fn compute_genesis_hash() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"PRISM_GENESIS");
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get the genesis (initial) hash - empty attestation (public for tests)
    fn genesis_hash() -> [u8; 32] {
        Self::compute_genesis_hash()
    }

    /// Append an attestation to the chain
    pub fn append(&self, attestation: &Attestation) -> Result<()> {
        let hash = self.compute_hash(attestation)?;

        // Verify chain continuity: prev_hash must be in our chain
        if attestation.prev_attest_hash != Self::genesis_hash() {
            if !self.chain.contains_key(&attestation.prev_attest_hash) {
                return Err(TeeError::MerkleError(
                    "Previous attestation not found in chain".to_string(),
                ));
            }
        }

        // Add to chain
        self.chain.insert(hash, attestation.clone());

        // Update latest
        *self.latest_hash.write() = hash;
        *self.length.write() += 1;

        Ok(())
    }

    /// Verify that an attestation exists in the chain
    pub fn verify_attestation(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self.chain.contains_key(hash))
    }

    /// Get an attestation from the chain
    pub fn get_attestation(&self, hash: &[u8; 32]) -> Option<Attestation> {
        self.chain.get(hash).map(|r| r.clone())
    }

    /// Verify chain continuity from an attestation backwards to genesis
    pub fn verify_chain_continuity(&self, start_hash: &[u8; 32]) -> Result<Vec<Attestation>> {
        let mut chain = Vec::new();
        let mut current_hash = *start_hash;

        loop {
            let attestation = self
                .get_attestation(&current_hash)
                .ok_or_else(|| TeeError::MerkleError("Attestation not found in chain".to_string()))?;

            chain.push(attestation.clone());

            // Stop at genesis
            if attestation.prev_attest_hash == Self::genesis_hash() {
                break;
            }

            current_hash = attestation.prev_attest_hash;
        }

        chain.reverse();
        Ok(chain)
    }

    /// Compute keccak256 hash of an attestation
    fn compute_hash(&self, attestation: &Attestation) -> Result<[u8; 32]> {
        attestation.hash()
    }

    /// Get the current head of the chain
    pub fn get_latest_hash(&self) -> [u8; 32] {
        *self.latest_hash.read()
    }

    /// Get chain length
    pub fn get_length(&self) -> u64 {
        *self.length.read()
    }

    /// Get the entire chain from genesis to latest
    pub fn get_full_chain(&self) -> Result<Vec<Attestation>> {
        let latest = self.get_latest_hash();
        if latest == [0u8; 32] {
            return Ok(Vec::new());
        }
        self.verify_chain_continuity(&latest)
    }

    /// Snapshot the chain state (for auditing)
    pub fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            latest_hash: self.get_latest_hash(),
            chain_length: self.get_length(),
            genesis_hash: Self::genesis_hash(),
        }
    }

    /// Reset the chain (testing only)
    pub fn reset(&self) -> Result<()> {
        self.chain.clear();
        *self.latest_hash.write() = [0u8; 32];
        *self.length.write() = 0;
        Ok(())
    }
}

impl Default for MerkleChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of chain state
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    pub latest_hash: [u8; 32],
    pub chain_length: u64,
    pub genesis_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationSigner;
    use crate::types::Intent;
    use alloy_primitives::Address;

    fn create_test_attestation(signer: &AttestationSigner, nonce: u64) -> Attestation {
        let intent = Intent {
            user: Address::ZERO,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: Default::default(),
            min_amount_out: Default::default(),
            deadline: 0,
            nonce,
        };

        let quote = crate::types::QuoteData {
            output_amount: Default::default(),
            fill_route: Address::ZERO,
            gas_estimate: Default::default(),
            timestamp: chrono::Utc::now(),
            solver_id: "test_solver".to_string(),
        };

        signer
            .create_attestation(
                &intent,
                &quote,
                1,
                MerkleChain::genesis_hash(),
            )
            .unwrap()
    }

    #[test]
    fn test_chain_initialization() {
        let chain = MerkleChain::new();
        assert_eq!(chain.get_length(), 0);
        // Latest hash should be genesis on initialization
        assert_eq!(chain.get_latest_hash(), MerkleChain::genesis_hash());
    }

    #[test]
    fn test_append_attestation() {
        let chain = MerkleChain::new();
        let signer = AttestationSigner::new().unwrap();
        let attestation = create_test_attestation(&signer, 1);

        chain.append(&attestation).unwrap();

        assert_eq!(chain.get_length(), 1);
    }

    #[test]
    fn test_chain_continuity() {
        let chain = MerkleChain::new();
        let signer = AttestationSigner::new().unwrap();

        let attestation1 = create_test_attestation(&signer, 1);
        chain.append(&attestation1).unwrap();

        // Create attestation2 with prev_hash pointing to attestation1
        let hash1 = attestation1.hash().unwrap();
        let mut attestation2 = create_test_attestation(&signer, 2);
        attestation2.prev_attest_hash = hash1;
        chain.append(&attestation2).unwrap();

        assert_eq!(chain.get_length(), 2);

        // Verify continuity
        let full_chain = chain.get_full_chain().unwrap();
        assert_eq!(full_chain.len(), 2);
    }

    #[test]
    fn test_broken_chain_rejection() {
        let chain = MerkleChain::new();
        let signer = AttestationSigner::new().unwrap();

        let mut attestation = create_test_attestation(&signer, 1);
        // Point to non-existent previous hash
        attestation.prev_attest_hash = [99u8; 32];

        let result = chain.append(&attestation);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_attestation() {
        let chain = MerkleChain::new();
        let signer = AttestationSigner::new().unwrap();
        let attestation = create_test_attestation(&signer, 1);
        let hash = attestation.hash().unwrap();

        chain.append(&attestation).unwrap();

        let retrieved = chain.get_attestation(&hash).unwrap();
        assert_eq!(retrieved.winner_solver, attestation.winner_solver);
    }
}
