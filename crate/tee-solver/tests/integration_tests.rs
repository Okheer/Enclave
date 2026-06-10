11/// End-to-end integration tests for the PRISM TEE Solver Engine.
///
/// Test hierarchy:
///   1. Sealed competition flow (P3 only)
///   2. Merkle chain continuity
///   3. ECDSA attestation validity
///   4. Quote sniping prevention
///   5. P1→P3→P2 full pipeline simulation (new — Days 3-5)
///   6. MEV attack scenarios via TeeSimulation
use tee_solver::{
    attestation::AttestationSigner,
    simulation::{MevDemoScenario, TeeSimulation},
    types::{Intent, QuoteData},
    verifier_interface::VerifierInterface,
    Attestation, TeeSolverEngine,
};
use alloy_primitives::{Address, U256};
use chrono::Utc;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_intent(nonce: u64) -> Intent {
    Intent {
        user: Address::ZERO,
        token_in: Address::ZERO,
        token_out: Address::ZERO,
        amount_in: U256::from(1_000u64),
        min_amount_out: U256::from(900u64),
        deadline: 9_999_999_999,
        nonce,
    }
}

fn make_quote(solver_id: &str, output: u64) -> QuoteData {
    QuoteData {
        output_amount: U256::from(output),
        fill_route: Address::ZERO,
        gas_estimate: U256::from(100_000u64),
        timestamp: Utc::now(),
        solver_id: solver_id.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Sealed competition flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_end_to_end_sealed_competition() {
    let engine = TeeSolverEngine::new().unwrap();
    let verifying_key = engine.get_public_key().unwrap();
    assert!(!verifying_key.is_empty());

    let intent = make_intent(1);

    engine.register_solver("solver1".to_string(), verifying_key.clone()).unwrap();
    engine.register_solver("solver2".to_string(), verifying_key.clone()).unwrap();
    engine.register_solver("solver3".to_string(), verifying_key.clone()).unwrap();

    engine.start_competition(intent.hash()).unwrap();

    engine.submit_quote("solver1".to_string(), make_quote("solver1", 950)).unwrap();
    engine.submit_quote("solver2".to_string(), make_quote("solver2", 980)).unwrap();
    engine.submit_quote("solver3".to_string(), make_quote("solver3", 920)).unwrap();

    let attestation = engine.finalize_competition(&intent, 100).unwrap();

    assert_eq!(attestation.winner_solver, "solver2", "Highest output (980) must win");
    assert_eq!(attestation.output_amount, U256::from(980u64));
    assert_eq!(attestation.block_number, 100);
    assert_eq!(attestation.signature.len(), 65, "Must be compact 65-byte sig");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Merkle chain continuity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_merkle_chain_continuity() {
    let engine = TeeSolverEngine::new().unwrap();
    let pubkey = engine.get_public_key().unwrap();

    let intent1 = make_intent(1);
    engine.register_solver("solver_a".to_string(), pubkey.clone()).unwrap();
    engine.start_competition(intent1.hash()).unwrap();
    engine.submit_quote("solver_a".to_string(), make_quote("solver_a", 950)).unwrap();
    let attest1 = engine.finalize_competition(&intent1, 100).unwrap();

    let intent2 = make_intent(2);
    engine.register_solver("solver_b".to_string(), pubkey).unwrap();
    engine.start_competition(intent2.hash()).unwrap();
    engine.submit_quote("solver_b".to_string(), make_quote("solver_b", 1_950)).unwrap();
    let attest2 = engine.finalize_competition(&intent2, 101).unwrap();

    // attestation2 must chain to attestation1
    let hash1 = attest1.hash().unwrap();
    assert_eq!(attest2.prev_attest_hash, hash1, "Merkle chain must link attest2 → attest1");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ECDSA attestation validity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_attestation_signature_validity() {
    let signer = AttestationSigner::new().unwrap();
    let intent = make_intent(1);
    let quote = make_quote("solver1", 950);

    let attestation = signer.create_attestation(&intent, &quote, 100, [0u8; 32]).unwrap();

    assert_eq!(attestation.signature.len(), 65, "Compact sig must be 65 bytes");

    // v byte must be Ethereum convention (27 or 28)
    let v = attestation.signature[64];
    assert!(v == 27 || v == 28, "v must be 27 or 28, got {}", v);

    // Signature must verify
    let hash = attestation.hash().unwrap();
    assert!(signer.verify_signature(&hash, &attestation.signature).unwrap());
}

#[test]
fn test_attestation_abi_encoding() {
    let signer = AttestationSigner::new().unwrap();
    let attestation = signer
        .create_attestation(&make_intent(1), &make_quote("s", 1_000), 1, [0u8; 32])
        .unwrap();

    let abi_bytes = attestation.to_abi_bytes();
    // 6 fields × 32 bytes per ABI slot = 192 bytes
    assert_eq!(abi_bytes.len(), 192, "ABI-encoded attestation must be 192 bytes");

    // intent_hash is in the first 32 bytes
    assert_eq!(&abi_bytes[0..32], &attestation.intent_hash);

    // output_amount is in slot 3 (bytes 96..128), big-endian U256
    let expected_amount_bytes = attestation.output_amount.to_be_bytes::<32>();
    assert_eq!(&abi_bytes[96..128], &expected_amount_bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Quote sniping prevention
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_multiple_quotes_best_price_wins() {
    let engine = TeeSolverEngine::new().unwrap();
    let pubkey = engine.get_public_key().unwrap();

    engine.register_solver("solver_a".to_string(), pubkey.clone()).unwrap();
    engine.register_solver("solver_b".to_string(), pubkey.clone()).unwrap();
    engine.register_solver("solver_c".to_string(), pubkey).unwrap();

    let intent = make_intent(1);
    engine.start_competition(intent.hash()).unwrap();

    // solver_b quotes just under solver_a trying to snipe — impossible inside TEE
    engine.submit_quote("solver_a".to_string(), make_quote("solver_a", 999)).unwrap();
    engine.submit_quote("solver_b".to_string(), make_quote("solver_b", 998)).unwrap();
    engine.submit_quote("solver_c".to_string(), make_quote("solver_c", 1_005)).unwrap();

    let attestation = engine.finalize_competition(&intent, 100).unwrap();

    assert_eq!(attestation.winner_solver, "solver_c", "True best quote (1005) must win");
    assert_eq!(attestation.output_amount, U256::from(1_005u64));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. P1 → P3 → P2 Full Pipeline Simulation (Days 3-5)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates the complete PRISM flow without deploying anything:
///   P1: escrows funds, emits intent_hash
///   P3: TEE opens auction, collects quotes, produces signed attestation
///   P2: verifier interface prepares the calldata P1 would call onchain
#[test]
fn test_p1_p3_p2_pipeline_simulation() {
    // ── P1: User signs EIP-712 intent ──────────────────────────────────────
    let intent = Intent {
        user: Address::from([0xaa; 20]),
        token_in:  Address::from([0x11; 20]),  // e.g. ETH
        token_out: Address::from([0x22; 20]),  // e.g. USDC
        amount_in: U256::from(10_000_000_000_000_000_000u128), // 10 ETH
        min_amount_out: U256::from(30_000_000_000u64),          // 30,000 USDC min
        deadline: 1_999_999_999,
        nonce: 42,
    };
    let intent_hash = intent.hash();

    // ── P3: TEE receives intent_hash, opens sealed auction ─────────────────
    let mut sim = TeeSimulation::new();

    // Print TEE address — this would be registered in SolverRegistry.sol
    let tee_addr = sim.ethereum_address();
    assert_ne!(tee_addr, Address::ZERO, "TEE must have a valid Ethereum address");

    sim.register_solver("solver_alice", 5_000_000_000_000_000_000); // 5 ETH stake
    sim.register_solver("solver_bob",   5_000_000_000_000_000_000);
    sim.register_solver("solver_charlie", 5_000_000_000_000_000_000);

    let auction = sim.open_auction(intent_hash);

    // Solvers submit sealed quotes — they cannot see each other's bids
    auction.submit_quote("solver_alice",   30_500_000_000u128).unwrap(); // 30,500 USDC
    auction.submit_quote("solver_bob",     30_700_000_000u128).unwrap(); // 30,700 USDC ← best
    auction.submit_quote("solver_charlie", 30_200_000_000u128).unwrap(); // 30,200 USDC

    // P3 closes auction, selects argmax, signs attestation
    let result = sim.close_and_attest(auction, 18_600_000).unwrap();

    assert_eq!(result.winner_solver_id, "solver_bob", "Bob's 30,700 USDC must win");
    assert_eq!(result.winning_output_wei, 30_700_000_000u128);

    // ── Attestation structure checks ──────────────────────────────────────
    // Signature is compact 65 bytes (r||s||v) as required by ecrecover
    assert_eq!(result.tee_sig.len(), 65);
    // ABI-encoded attestation is 192 bytes (6 × 32-byte slots)
    assert_eq!(result.attestation_data.len(), 192);
    // intent_hash in attestation matches what P1 emitted
    assert_eq!(result.attestation.intent_hash, intent_hash);
    // block_number is recorded
    assert_eq!(result.attestation.block_number, 18_600_000);

    // Self-verification: TEE can verify its own signature
    assert!(sim.verify_attestation(&result).unwrap());

    // ── P2: Prepare calldata for SolvexVerifier.verify() ──────────────────
    let verifier_iface = VerifierInterface::new(
        Address::from([0xAB; 20]), // SolvexVerifier contract address
        Address::from([0xCD; 20]), // SolvexSettlement contract address
        "https://sepolia-rollup.arbitrum.io/rpc".to_string(),
    );

    let calldata = verifier_iface
        .build_verify_calldata(&intent_hash, &result.attestation_data, &result.tee_sig)
        .unwrap();

    // Selector: keccak256("verify(bytes32,bytes,bytes)")[0:4] = 0xfc735e99
    assert_eq!(&calldata[0..4], &[0xfc, 0x73, 0x5e, 0x99], "Wrong function selector");

    // intent_hash embedded at bytes 4..36
    assert_eq!(&calldata[4..36], &intent_hash);

    // Total calldata length:
    // 4 (selector) + 32 (intent_hash) + 32 (attest_offset) + 32 (sig_offset)
    // + 32 (attest_len) + 192 (attest_data) + 32 (sig_len) + 96 (65B sig padded to 96)
    assert_eq!(calldata.len(), 4 + 32 + 32 + 32 + 32 + 192 + 32 + 96);

    println!("\n✅ P1→P3→P2 Pipeline test PASSED");
    println!("   TEE Ethereum address:  {:?}", tee_addr);
    println!("   Winner:                {}", result.winner_solver_id);
    println!("   Winning output:        {} USDC (raw)", result.winning_output_wei);
    println!("   Signature (65 bytes):  0x{}", hex::encode(&result.tee_sig));
    println!("   Calldata length:       {} bytes", calldata.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. MEV Attack Scenarios
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mev_quote_sniping_eliminated() {
    let (winner, output, sniping_worked) = MevDemoScenario::quote_sniping_demo();
    assert_eq!(winner, "charlie_best", "Honest best quote must win, not the sniper");
    assert!(!sniping_worked, "Quote sniping must be impossible inside TEE");
    println!("\n✅ Quote Sniping eliminated — winner: {}, output: {} wei", winner, output);
}

#[test]
fn test_mev_collusion_eliminated() {
    let (winner, output, cartel_won) = MevDemoScenario::collusion_demo();
    assert_eq!(winner, "honest_carol", "Honest solver breaks cartel floor");
    assert!(!cartel_won, "Cartel must not be able to suppress honest competition");
    println!("\n✅ Collusion eliminated — winner: {}, output: {} wei", winner, output);
}

#[test]
fn test_mev_sandwich_eliminated() {
    let (attested_route, route_tampered) = MevDemoScenario::sandwich_demo();
    // Route committed inside TEE, recorded in attestation — cannot be swapped at settlement
    assert!(!route_tampered, "Attested fill route must be Address::ZERO (un-tampered default)");
    println!("\n✅ Sandwich eliminated — attested fill route: {:?}", attested_route);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Ethereum address derivation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tee_ethereum_address_derivation() {
    let engine = TeeSolverEngine::new().unwrap();
    let addr = engine.get_ethereum_address().unwrap();

    // Must not be zero
    assert_ne!(addr, Address::ZERO, "Derived Ethereum address must be non-zero");

    // Derived address is deterministic for same seed
    let signer = AttestationSigner::from_seed(&[7u8; 32]).unwrap();
    let addr1 = signer.ethereum_address().unwrap();
    let addr2 = signer.ethereum_address().unwrap();
    assert_eq!(addr1, addr2, "Address derivation must be deterministic");
}
