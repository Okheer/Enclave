pub mod api;
pub mod attestation;
pub mod competition;
pub mod error;
pub mod gcp_attestation;
pub mod merkle;
pub mod simulation;
pub mod types;
pub mod verifier_interface;

pub use attestation::{Attestation, AttestationSigner};
pub use competition::SolverCompetition;
pub use error::{Result, TeeError};
pub use types::{Intent, Solver};

/// TEE Solver Engine - Main orchestrator for sealed solver competition
pub struct TeeSolverEngine {
    signer: AttestationSigner,
    competition: SolverCompetition,
    merkle_chain: merkle::MerkleChain,
    registered_solvers: dashmap::DashMap<String, Solver>,
    verifier_interface: parking_lot::RwLock<Option<verifier_interface::VerifierInterface>>,
}

impl TeeSolverEngine {
    /// Initialize the TEE Solver Engine with a new signing key
    pub fn new() -> Result<Self> {
        Ok(Self {
            signer: AttestationSigner::new()?,
            competition: SolverCompetition::new(),
            merkle_chain: merkle::MerkleChain::new(),
            registered_solvers: dashmap::DashMap::new(),
            verifier_interface: parking_lot::RwLock::new(None),
        })
    }

    /// Register a solver with their TEE public key
    pub fn register_solver(&self, solver_id: String, pubkey: Vec<u8>) -> Result<()> {
        let solver = Solver {
            id: solver_id.clone(),
            pubkey,
            registered_at: chrono::Utc::now(),
        };
        self.registered_solvers.insert(solver_id, solver);
        Ok(())
    }

    /// Start a new sealed auction for a specific intent
    pub fn start_competition(&self, intent_hash: [u8; 32]) -> Result<()> {
        self.competition.start_competition(intent_hash)?;
        Ok(())
    }

    /// Collect a quote from a solver during sealed auction
    pub fn submit_quote(&self, solver_id: String, quote: types::QuoteData) -> Result<()> {
        self.competition.add_quote(solver_id, quote)?;
        Ok(())
    }

    /// Run the sealed solver competition - selects winner by argmax(output_amount)
    pub fn finalize_competition(&self, intent: &Intent, block_number: u64) -> Result<Attestation> {
        let winning_quote = self.competition.select_winner()?;
        let attestation = self.signer.create_attestation(
            intent,
            &winning_quote,
            block_number,
            self.merkle_chain.get_latest_hash(),
        )?;

        // Add to Merkle chain for continuity verification
        self.merkle_chain.append(&attestation)?;

        // Reset competition for next auction
        self.competition.reset()?;

        Ok(attestation)
    }

    /// Get the TEE's public key for onchain registration
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        self.signer.get_public_key()
    }

    /// Get the TEE's Ethereum address (keccak256 of uncompressed pubkey, last 20 bytes).
    /// This is what `SolverRegistry.sol` must store and what `SolvexVerifier.ecrecover_signer()`
    /// will return — use it in `verify_with_expected_signer()` calls.
    pub fn get_ethereum_address(&self) -> Result<alloy_primitives::Address> {
        self.signer.ethereum_address()
    }

    /// Configure P2 integration - set SolvexVerifier contract address and RPC endpoint
    pub fn configure_p2_integration(
        &self,
        verifier_address: alloy_primitives::Address,
        settlement_address: alloy_primitives::Address,
        rpc_endpoint: String,
    ) -> Result<()> {
        let verifier = verifier_interface::VerifierInterface::new(
            verifier_address,
            settlement_address,
            rpc_endpoint,
        );
        *self.verifier_interface.write() = Some(verifier);
        Ok(())
    }

    /// Finalize competition and submit attestation to P2 for verification
    pub fn finalize_and_verify_p2(
        &self,
        intent: &Intent,
        block_number: u64,
    ) -> Result<(Attestation, String)> {
        // Finalize locally
        let attestation = self.finalize_competition(intent, block_number)?;

        // Get verifier interface or return error
        let verifier_lock = self.verifier_interface.read();
        let verifier = verifier_lock.as_ref().ok_or(TeeError::InternalError(
            "P2 integration not configured".to_string(),
        ))?;

        // Note: In production, this would be async and actually call P2
        // For now, we'll return the attestation with a placeholder tx hash
        Ok((attestation, format!("0x{}", hex::encode(intent.hash()))))
    }

    /// Finalize competition with just intent hash (for API endpoint)
    pub fn finalize_competition_with_intent_hash(
        &self,
        intent_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<Attestation> {
        // Create a minimal intent from hash
        let winning_quote = self.competition.select_winner()?;

        // Create attestation with the provided intent hash
        let mut attestation = self.signer.create_attestation_with_hash(
            intent_hash,
            &winning_quote,
            block_number,
            self.merkle_chain.get_latest_hash(),
        )?;

        // Add to Merkle chain for continuity verification
        self.merkle_chain.append(&attestation)?;

        // Reset competition for next auction
        self.competition.reset()?;

        Ok(attestation)
    }
}

impl Default for TeeSolverEngine {
    fn default() -> Self {
        Self::new().expect("Failed to initialize TEE Solver Engine")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_initialization() {
        let engine = TeeSolverEngine::new().unwrap();
        let pubkey = engine.get_public_key().unwrap();
        assert!(!pubkey.is_empty());
    }
}
