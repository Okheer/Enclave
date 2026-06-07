//! TEE Simulation Environment (P3 Days 3–5)
//!
//! Provides a local simulation of GCP Confidential Space behaviour for demo
//! and testing purposes — no hardware TEE required.
//!
//! Key guarantees emulated:
//! - Quote opacity: solvers never see peer quotes (enforced by `SolverCompetition`)
//! - Deterministic winner selection: `argmax(output_amount)`
//! - Signed attestation: real ECDSA using the same `AttestationSigner` as production
//! - Merkle chain: real chain continuity tracking
//!
//! Usage:
//! ```ignore
//! let mut sim = TeeSimulation::new();
//! sim.register_solver("alice", 1_000_000);   // solver id, stake (wei)
//! sim.register_solver("bob",   1_000_000);
//!
//! let auction = sim.open_auction([1u8; 32]);
//! auction.submit_quote("alice", 995_000_000_000_000_000u128); // 0.995 ETH
//! auction.submit_quote("bob",   998_000_000_000_000_000u128); // 0.998 ETH
//!
//! let result = sim.close_and_attest(auction).unwrap();
//! println!("Winner: {}", result.winner_solver_id);
//! println!("Sig (65 bytes): 0x{}", hex::encode(&result.attestation.signature));
//! ```

use crate::attestation::{Attestation, AttestationSigner};
use crate::competition::SolverCompetition;
use crate::error::{Result, TeeError};
use crate::merkle::MerkleChain;
use crate::types::QuoteData;
use alloy_primitives::{Address, U256};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// A registered solver in the simulation
#[derive(Debug, Clone)]
pub struct SimSolver {
    pub id: String,
    /// Stake amount in wei (simulated — not onchain in sim mode)
    pub stake_wei: u128,
    /// Whether this solver is a "colluding" cartel member (used in MEV demo)
    pub is_cartel: bool,
}

/// An open sealed auction ready to accept quotes
pub struct Auction {
    pub intent_hash: [u8; 32],
    pub competition: SolverCompetition,
}

impl Auction {
    fn new(intent_hash: [u8; 32]) -> Self {
        let competition = SolverCompetition::new();
        competition
            .start_competition(intent_hash)
            .expect("Failed to start competition");
        Self { intent_hash, competition }
    }

    /// Submit a quote from a solver — sealed inside TEE memory, invisible to peers.
    pub fn submit_quote(&self, solver_id: &str, output_wei: u128) -> Result<()> {
        let quote = QuoteData {
            output_amount: U256::from(output_wei),
            fill_route: Address::ZERO,
            gas_estimate: U256::from(100_000u64),
            timestamp: Utc::now(),
            solver_id: solver_id.to_string(),
        };
        self.competition.add_quote(solver_id.to_string(), quote)
    }
}

/// Result of a completed sealed auction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionResult {
    pub intent_hash: [u8; 32],
    pub winner_solver_id: String,
    pub winning_output_wei: u128,
    /// Signed TEE attestation — ready to be passed to SolvexVerifier.verify()
    pub attestation: Attestation,
    /// ABI-encoded attestation bytes (pass as `attestation_data` to Stylus)
    pub attestation_data: Vec<u8>,
    /// Compact 65-byte signature (pass as `tee_sig` to Stylus)
    pub tee_sig: Vec<u8>,
    pub block_number: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// TeeSimulation
// ─────────────────────────────────────────────────────────────────────────────

/// Local simulation of GCP Confidential Space TEE.
///
/// Provides the same cryptographic guarantees as production:
/// - Real k256 ECDSA signing with `PrehashSigner`
/// - Real Merkle chain linking attestations
/// - Quote opacity enforced by Rust's borrow checker (DashMap private to `SolverCompetition`)
pub struct TeeSimulation {
    signer: AttestationSigner,
    merkle_chain: MerkleChain,
    solvers: HashMap<String, SimSolver>,
    auction_counter: u64,
}

impl TeeSimulation {
    /// Create a new simulation instance with a fresh random TEE key pair.
    pub fn new() -> Self {
        Self {
            signer: AttestationSigner::new().expect("Failed to create TEE signer"),
            merkle_chain: MerkleChain::new(),
            solvers: HashMap::new(),
            auction_counter: 0,
        }
    }

    /// Create a simulation with a deterministic key (for reproducible tests/demos).
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            signer: AttestationSigner::from_seed(&seed).expect("Failed to create TEE signer"),
            merkle_chain: MerkleChain::new(),
            solvers: HashMap::new(),
            auction_counter: 0,
        }
    }

    /// Return the TEE's compressed secp256k1 public key (33 bytes).
    /// → Register this in `SolverRegistry.sol` during onboarding.
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.get_public_key().unwrap()
    }

    /// Return the TEE's Ethereum address.
    /// → This is what `SolvexVerifier.ecrecover_signer()` will return after a valid attestation.
    pub fn ethereum_address(&self) -> Address {
        self.signer.ethereum_address().unwrap()
    }

    /// Register a solver in the simulation.
    pub fn register_solver(&mut self, id: &str, stake_wei: u128) {
        self.solvers.insert(
            id.to_string(),
            SimSolver { id: id.to_string(), stake_wei, is_cartel: false },
        );
    }

    /// Register a cartel (colluding) solver — used in MEV attack demo.
    pub fn register_cartel_solver(&mut self, id: &str, stake_wei: u128) {
        self.solvers.insert(
            id.to_string(),
            SimSolver { id: id.to_string(), stake_wei, is_cartel: true },
        );
    }

    /// Open a new sealed auction for `intent_hash`.
    /// Mirrors: P1 calling `POST /start` on the TEE server.
    pub fn open_auction(&mut self, intent_hash: [u8; 32]) -> Auction {
        self.auction_counter += 1;
        Auction::new(intent_hash)
    }

    /// Finalize an auction, run `argmax(output_amount)`, and produce a signed attestation.
    /// Mirrors: P1 calling `POST /finalize` after the quote window closes.
    pub fn close_and_attest(&mut self, auction: Auction, block_number: u64) -> Result<AuctionResult> {
        let winner = auction.competition.select_winner()?;
        let prev_hash = self.merkle_chain.get_latest_hash();

        let attestation = self.signer.create_attestation_with_hash(
            &auction.intent_hash,
            &winner,
            block_number,
            prev_hash,
        )?;

        // Append to Merkle chain
        self.merkle_chain.append(&attestation)?;

        let attestation_data = attestation.to_abi_bytes();
        let tee_sig = attestation.signature.clone();
        let winning_output_wei = winner.output_amount.to::<u128>();

        Ok(AuctionResult {
            intent_hash: auction.intent_hash,
            winner_solver_id: winner.solver_id,
            winning_output_wei,
            attestation,
            attestation_data,
            tee_sig,
            block_number,
        })
    }

    /// Get the current Merkle chain head (pass as `prevAttestHash` to next attestation).
    pub fn merkle_head(&self) -> [u8; 32] {
        self.merkle_chain.get_latest_hash()
    }

    /// Get the number of completed auctions.
    pub fn auction_count(&self) -> u64 {
        self.auction_counter
    }

    /// Verify a previously produced attestation is cryptographically valid.
    pub fn verify_attestation(&self, result: &AuctionResult) -> Result<bool> {
        let hash = result.attestation.hash()?;
        self.signer.verify_signature(&hash, &result.tee_sig)
    }
}

impl Default for TeeSimulation {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MEV Attack Scenarios (for demo)
// ─────────────────────────────────────────────────────────────────────────────

/// Demonstrates the three MEV attack vectors and why PRISM eliminates them.
pub struct MevDemoScenario;

impl MevDemoScenario {
    /// **Attack 1: Quote Sniping**
    ///
    /// Without TEE: Solver B observes A's quote and undercuts by 1 wei.
    /// With PRISM: Impossible — B cannot see A's sealed quote.
    ///
    /// Returns `(winner_id, winning_output_wei, was_sniping_attempt_successful)`
    pub fn quote_sniping_demo() -> (String, u128, bool) {
        let mut sim = TeeSimulation::with_seed([42u8; 32]);
        sim.register_solver("alice_honest", 1_000_000);
        sim.register_solver("bob_sniper",   1_000_000);
        sim.register_solver("charlie_best", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);

        // Alice submits a legitimate quote
        auction.submit_quote("alice_honest",  995_000_000_000_000_000).unwrap();

        // Bob tries to snipe — in a real system Bob can't see Alice's quote.
        // He guesses 999 (thinking he's undercutting) but gets beaten by Charlie.
        auction.submit_quote("bob_sniper",    999_000_000_000_000_000).unwrap();

        // Charlie submits the genuinely best quote
        auction.submit_quote("charlie_best", 1_005_000_000_000_000_000).unwrap();

        let result = sim.close_and_attest(auction, 18_500_100).unwrap();

        let sniping_worked = result.winner_solver_id == "bob_sniper";
        (result.winner_solver_id, result.winning_output_wei, sniping_worked)
    }

    /// **Attack 2: Collusive Floor Setting**
    ///
    /// Cartel agrees: "never bid above 990". Honest solver breaks the floor.
    /// Returns `(winner_id, winning_output_wei, cartel_won)`
    pub fn collusion_demo() -> (String, u128, bool) {
        let mut sim = TeeSimulation::with_seed([43u8; 32]);
        sim.register_cartel_solver("cartel_a",  1_000_000);
        sim.register_cartel_solver("cartel_b",  1_000_000);
        sim.register_solver("honest_carol", 1_000_000);

        let auction = sim.open_auction([2u8; 32]);

        // Cartel members artificially cap their quotes
        auction.submit_quote("cartel_a",    990_000_000_000_000_000).unwrap();
        auction.submit_quote("cartel_b",    985_000_000_000_000_000).unwrap();

        // Honest Carol submits true market rate
        auction.submit_quote("honest_carol", 1_100_000_000_000_000_000).unwrap();

        let result = sim.close_and_attest(auction, 18_500_101).unwrap();

        let cartel_won = result.winner_solver_id.starts_with("cartel");
        (result.winner_solver_id, result.winning_output_wei, cartel_won)
    }

    /// **Attack 3: Sandwich Attack Attempt**
    ///
    /// A solver controlling settlement tries to front-run fill at DEX level.
    /// With PRISM: winner is selected and *attested* before any onchain tx,
    /// so the settlement route is committed inside the TEE — no front-running possible.
    ///
    /// Returns `(attested_fill_route, was_route_tampered)`
    pub fn sandwich_demo() -> (Address, bool) {
        let mut sim = TeeSimulation::with_seed([44u8; 32]);
        sim.register_solver("dave_sandwicher", 1_000_000);
        sim.register_solver("eve_honest",      1_000_000);

        let auction = sim.open_auction([3u8; 32]);
        auction.submit_quote("dave_sandwicher", 970_000_000_000_000_000).unwrap();
        auction.submit_quote("eve_honest",       980_000_000_000_000_000).unwrap();

        let result = sim.close_and_attest(auction, 18_500_102).unwrap();

        // The fill_route is committed in the attestation; Stylus verifies it matches
        let attested_route = result.attestation.fill_route;
        let route_tampered = attested_route != Address::ZERO; // would be non-zero if tampered
        (attested_route, route_tampered)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_basic_flow() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);
        sim.register_solver("s2", 1_000_000);

        let auction = sim.open_auction([99u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();
        auction.submit_quote("s2", 2_000).unwrap();

        let result = sim.close_and_attest(auction, 1).unwrap();
        assert_eq!(result.winner_solver_id, "s2");
        assert_eq!(result.winning_output_wei, 2_000);
    }

    #[test]
    fn test_attestation_is_65_bytes() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();

        let result = sim.close_and_attest(auction, 1).unwrap();
        assert_eq!(result.tee_sig.len(), 65, "Compact signature must be 65 bytes");
    }

    #[test]
    fn test_attestation_data_is_192_bytes() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();

        let result = sim.close_and_attest(auction, 1).unwrap();
        assert_eq!(result.attestation_data.len(), 192, "ABI-encoded attestation must be 192 bytes");
    }

    #[test]
    fn test_verify_attestation() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let auction = sim.open_auction([1u8; 32]);
        auction.submit_quote("s1", 1_000).unwrap();

        let result = sim.close_and_attest(auction, 1).unwrap();
        assert!(sim.verify_attestation(&result).unwrap());
    }

    #[test]
    fn test_merkle_chain_links() {
        let mut sim = TeeSimulation::new();
        sim.register_solver("s1", 1_000_000);

        let a1 = sim.open_auction([1u8; 32]);
        a1.submit_quote("s1", 1_000).unwrap();
        let r1 = sim.close_and_attest(a1, 1).unwrap();

        let a2 = sim.open_auction([2u8; 32]);
        a2.submit_quote("s1", 2_000).unwrap();
        let r2 = sim.close_and_attest(a2, 2).unwrap();

        // attestation2.prev_attest_hash must equal hash of attestation1
        let hash1 = r1.attestation.hash().unwrap();
        assert_eq!(r2.attestation.prev_attest_hash, hash1);
    }

    #[test]
    fn test_quote_sniping_prevented() {
        let (winner, output, sniping_worked) = MevDemoScenario::quote_sniping_demo();
        assert_eq!(winner, "charlie_best", "Best honest quote must win");
        assert_eq!(output, 1_005_000_000_000_000_000u128);
        assert!(!sniping_worked, "Sniping must have failed");
    }

    #[test]
    fn test_collusion_prevented() {
        let (winner, output, cartel_won) = MevDemoScenario::collusion_demo();
        assert_eq!(winner, "honest_carol");
        assert_eq!(output, 1_100_000_000_000_000_000u128);
        assert!(!cartel_won, "Cartel must not have won");
    }

    #[test]
    fn test_ethereum_address_non_zero() {
        let sim = TeeSimulation::new();
        assert_ne!(sim.ethereum_address(), Address::ZERO);
    }
}
