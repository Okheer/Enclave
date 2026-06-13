// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {SolvexSettlement} from "../src/SolvexSettlement.sol";
import {SolverRegistry} from "../src/SolverRegistry.sol";
import {IntentPool} from "../src/IntentPool.sol";
import {ISolvexVerifier} from "../src/interfaces/ISolvexVerifier.sol";
import {ISolverRegistry} from "../src/interfaces/ISolverRegistry.sol";
import {IIntentPool} from "../src/interfaces/IIntentPool.sol";

// ═══════════════════════════════════════════════════════════════════════
// StylusMockSolvexVerifier
// ═══════════════════════════════════════════════════════════════════════
//
// A high-fidelity Solidity mock that mirrors the exact logic of the Rust
// SolverVerifier (contracts/stylus/solver-verifier/src/lib.rs).
//
// Replicates all 3 verification checks:
//   1. Nonce Guard — settled_intents mapping
//   2. ECDSA Recovery — ecrecover + signer match
//   3. Merkle Chain Continuity — prev_attest_hash == lastHash
//
// Plus additional winner_solver validation.
// ═══════════════════════════════════════════════════════════════════════

contract StylusMockSolvexVerifier is ISolvexVerifier {
    bytes32 public lastHash;
    mapping(bytes32 => bool) public settledIntents;
    uint256 public attestationCount;
    address public ownerAddr;

    constructor() {
        ownerAddr = msg.sender;
    }

    /// @notice Mirrors lib.rs verify() — performs all 3 checks + signer == winnerSolver
    function verify(
        bytes32 intentHash,
        bytes calldata attestationData,
        bytes calldata teeSig
    ) external override returns (bool) {
        // 1. Nonce Guard
        require(!settledIntents[intentHash], "StylusMock: IntentAlreadySettled");

        // Decode attestation
        SolvexSettlement.Attestation memory att = abi.decode(attestationData, (SolvexSettlement.Attestation));

        // Intent hash cross-check
        require(att.intent_hash == intentHash, "StylusMock: InvalidAttestation (hash mismatch)");

        // 2. ECDSA Signature Verification
        bytes32 hash = keccak256(attestationData);
        address recovered = _recoverSigner(hash, teeSig);
        require(recovered != address(0), "StylusMock: EcrecoverFailed");

        // In verify(), signer must match winnerSolver (keyless variant)
        require(recovered == att.winner_solver, "StylusMock: InvalidAttestation (signer != winner)");

        // 3. Merkle Chain Continuity
        require(att.prev_attest_hash == lastHash, "StylusMock: MerkleChainBroken");

        // Commit state
        _commitState(intentHash, attestationData, att);

        return true;
    }

    /// @notice Mirrors lib.rs verify_with_expected_signer() — full production path
    function verifyWithExpectedSigner(
        bytes32 intentHash,
        bytes calldata attestationData,
        bytes calldata teeSig,
        address expectedSigner,
        address expectedWinner
    ) external override returns (bool) {
        // 1. Nonce Guard
        if (settledIntents[intentHash]) return false;

        // Decode attestation
        SolvexSettlement.Attestation memory att = abi.decode(attestationData, (SolvexSettlement.Attestation));

        // Intent hash cross-check
        if (att.intent_hash != intentHash) return false;

        // 2. ECDSA Signature Verification
        bytes32 hash = keccak256(attestationData);
        address recovered = _recoverSigner(hash, teeSig);
        if (recovered == address(0)) return false;

        // Signer must match expectedSigner (derived from TEE pubkey)
        if (recovered != expectedSigner) return false;

        // 3. Merkle Chain Continuity
        if (att.prev_attest_hash != lastHash) return false;

        // Winner validation
        if (att.winner_solver != expectedWinner) return false;

        // Commit state
        _commitState(intentHash, attestationData, att);

        return true;
    }

    function isIntentSettled(bytes32 intentHash) external view override returns (bool) {
        return settledIntents[intentHash];
    }

    function getLastAttestHash() external view override returns (bytes32) {
        return lastHash;
    }

    function getAttestationCount() external view override returns (uint256) {
        return attestationCount;
    }

    function getOwner() external view override returns (address) {
        return ownerAddr;
    }

    // ── Internal helpers ──────────────────────────────────────────────

    function _commitState(
        bytes32 intentHash,
        bytes calldata attestationData,
        SolvexSettlement.Attestation memory /* att */
    ) internal {
        settledIntents[intentHash] = true;
        lastHash = keccak256(attestationData);
        attestationCount++;
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Test ERC20 Token
// ═══════════════════════════════════════════════════════════════════════

contract TestERC20 is ERC20 {
    constructor() ERC20("Test Token", "TST") {
        _mint(msg.sender, 1_000_000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// E2E Integration Tests
// ═══════════════════════════════════════════════════════════════════════
//
// Tests the complete Enclave pipeline:
//
//   User signs intent → IntentPool escrows funds
//         ↓
//   TEE runs sealed auction → signs Attestation
//         ↓
//   SolvexSettlement.settleIntent() →
//       calls SolverRegistry.isValidSolver()
//       calls SolverRegistry.getTeePublicKey()
//       calls SolvexVerifier.verifyWithExpectedSigner()
//           → nonce guard
//           → ecrecover signer check
//           → Merkle chain check
//       calls IntentPool.getEscrowRecord()
//       calls IntentPool.markFilled()
//       distributes: solver gets (amount - fee), treasury gets fee
//       calls SolverRegistry.updateReputation()
//
// ═══════════════════════════════════════════════════════════════════════

contract IntegrationTest is Test {
    using SafeERC20 for TestERC20;

    // ── Contracts ────────────────────────────────────────────────────
    SolverRegistry public registry;
    IntentPool public pool;
    SolvexSettlement public settlement;
    StylusMockSolvexVerifier public verifier;
    TestERC20 public token;

    // ── Solver keypair (TEE-generated secp256k1) ─────────────────────
    // This simulates the ephemeral keypair created inside GCP Confidential Space.
    // In production: generated in TEE, pubkey registered via bootstrap.
    uint256 public constant SOLVER_PRIVATE_KEY = 0x70d821942f7e3491dd3cbebf4faaf12ac2b846ebab374b361f9561f4f2577843;
    bytes public constant TEE_PUBKEY = hex"048a875028b433a93e34964e8191bf3d7d059ac7aaac927467a478503d964334e21874d45ff588f95f5bdf9e8b9c7226bd90ac5ae33e163d729bdcbfb0732a96c1";

    // ── Actors ────────────────────────────────────────────────────────
    address public solverAddress;
    address public userAddress;
    address public feeRecipient;

    uint256 public userPrivateKey = 0x999;
    uint256 public constant INITIAL_USER_BALANCE = 500e18;
    uint256 public constant INTENT_AMOUNT = 100e18;
    uint256 public constant MIN_AMOUNT_OUT = 90e18;

    // ── Events (for expectEmit) ──────────────────────────────────────
    event IntentSubmitted(
        bytes32 indexed intent_hash,
        address indexed user,
        address token_in,
        address token_out,
        uint256 amount_in,
        uint256 min_amount_out,
        uint256 deadline
    );
    event IntentFilled(bytes32 indexed intent_hash, address indexed winner_solver);
    event IntentSettled(
        bytes32 indexed intent_hash,
        address indexed winner_solver,
        address fill_route,
        uint256 output_amount,
        uint256 fee_paid,
        uint64 block_number
    );

    // ═════════════════════════════════════════════════════════════════
    // Setup
    // ═════════════════════════════════════════════════════════════════

    function setUp() public {
        solverAddress = vm.addr(SOLVER_PRIVATE_KEY);
        userAddress = vm.addr(userPrivateKey);
        feeRecipient = address(0x3333);

        // Pre-calculate create addresses to deploy with circular deps
        address deployer = address(this);
        uint256 nonce = vm.getNonce(deployer);

        // Deploy order: registry(nonce), pool(nonce+1), verifier(nonce+2), settlement(nonce+3)
        address poolAddr = vm.computeCreateAddress(deployer, nonce + 1);
        address settlementAddr = vm.computeCreateAddress(deployer, nonce + 3);

        // 1. Deploy all contracts
        registry = new SolverRegistry(feeRecipient);
        pool = new IntentPool(settlementAddr);
        require(address(pool) == poolAddr, "Pool address mismatch");

        verifier = new StylusMockSolvexVerifier();
        settlement = new SolvexSettlement(
            address(verifier),
            address(registry),
            address(pool),
            feeRecipient
        );
        require(address(settlement) == settlementAddr, "Settlement address mismatch");

        // 2. Grant SETTLER_ROLE to settlement
        registry.grantRole(registry.SETTLER_ROLE(), address(settlement));

        // 3. Deploy and distribute tokens
        token = new TestERC20();
        token.transfer(userAddress, INITIAL_USER_BALANCE);

        console.log("=== Enclave E2E Test Setup ===");
        console.log("  Registry:   ", address(registry));
        console.log("  IntentPool: ", address(pool));
        console.log("  Verifier:   ", address(verifier));
        console.log("  Settlement: ", address(settlement));
        console.log("  Token:      ", address(token));
        console.log("  Solver:     ", solverAddress);
        console.log("  User:       ", userAddress);
        console.log("  Fee Recip:  ", feeRecipient);
        console.log("==============================");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 1: Full Pipeline — Happy Path
    // ═════════════════════════════════════════════════════════════════
    //
    // Complete end-to-end flow:
    //   1. Register solver with TEE pubkey
    //   2. User signs & submits EIP-712 intent
    //   3. TEE signs attestation
    //   4. Settle: verifier does ecrecover + nonce + Merkle check
    //   5. Funds flow: user → pool → settlement → solver + fee
    //

    function test_E2E_FullPipeline() public {
        console.log("\n--- TEST 1: Full Pipeline ---");

        // ── Step 1: Register Solver ──────────────────────────────────
        console.log("[Step 1] Registering solver with TEE pubkey...");
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        assertTrue(registry.isValidSolver(solverAddress), "Solver should be valid");
        assertEq(registry.getStake(solverAddress), 2 ether, "Stake mismatch");
        assertEq(registry.getReputation(solverAddress), 500, "Initial rep should be 500");
        console.log("[Step 1] Solver registered. Stake: 2 ETH, Rep: 500");

        // ── Step 2: User Submits Intent ──────────────────────────────
        console.log("[Step 2] User submitting intent...");
        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);

        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });

        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes memory userSig = abi.encodePacked(r, s, v);

        bytes32 intentHash = pool.submitIntent(intent, userSig);
        vm.stopPrank();

        assertEq(intentHash, digest, "Intent hash should equal digest");
        assertEq(token.balanceOf(userAddress), INITIAL_USER_BALANCE - INTENT_AMOUNT, "User balance did not decrease");
        assertEq(token.balanceOf(address(pool)), INTENT_AMOUNT, "Pool did not receive tokens");

        IntentPool.EscrowRecord memory rec = pool.getEscrowRecord(intentHash);
        assertEq(uint256(rec.state), 1, "Intent should be PENDING");
        assertEq(rec.user, userAddress);
        assertEq(rec.min_amount_out, MIN_AMOUNT_OUT);
        console.log("[Step 2] Intent submitted. Hash:", vm.toString(intentHash));

        // ── Step 3: TEE Signs Attestation ────────────────────────────
        console.log("[Step 3] TEE signing attestation...");
        SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: solverAddress,
            fill_route: address(0x5555),
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: bytes32(0) // Genesis: no previous attestation
        });

        bytes memory attestationData = abi.encode(att);
        bytes32 attestHash = keccak256(attestationData);

        // TEE signs with its private key (simulated)
        (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);
        bytes memory teeSig = abi.encodePacked(tr, ts, tv);
        console.log("[Step 3] Attestation signed. Hash:", vm.toString(attestHash));

        // ── Step 4: Settle Intent ────────────────────────────────────
        console.log("[Step 4] Settling intent through full pipeline...");
        console.log("  -> Settlement calls SolverRegistry.isValidSolver()");
        console.log("  -> Settlement calls SolverRegistry.getTeePublicKey()");
        console.log("  -> Settlement calls SolvexVerifier.verifyWithExpectedSigner()");
        console.log("     -> Verifier: nonce guard check");
        console.log("     -> Verifier: ecrecover signer check");
        console.log("     -> Verifier: Merkle chain continuity check");
        console.log("  -> Settlement calls IntentPool.getEscrowRecord()");
        console.log("  -> Settlement calls IntentPool.markFilled()");
        console.log("  -> Settlement distributes rewards");
        console.log("  -> Settlement calls SolverRegistry.updateReputation()");

        settlement.settleIntent(intentHash, att, teeSig);

        // ── Step 5: Verify All Final States ──────────────────────────
        console.log("[Step 5] Verifying final states across all contracts...");

        // Verifier state
        assertTrue(verifier.isIntentSettled(intentHash), "Verifier: intent should be settled");
        assertEq(verifier.getLastAttestHash(), attestHash, "Verifier: Merkle head mismatch");
        assertEq(verifier.getAttestationCount(), 1, "Verifier: count should be 1");

        // Settlement state
        assertTrue(settlement.isSettled(intentHash), "Settlement: should be settled");
        assertEq(settlement.getChainHead(), attestHash, "Settlement: chain head mismatch");

        // IntentPool state
        rec = pool.getEscrowRecord(intentHash);
        assertEq(uint256(rec.state), 2, "Pool: intent should be FILLED");

        // Fund flow
        uint256 expectedFee = (INTENT_AMOUNT * 10) / 10_000; // 0.1%
        uint256 expectedSolverAmount = INTENT_AMOUNT - expectedFee;

        assertEq(token.balanceOf(address(pool)), 0, "Pool should be empty");
        assertEq(token.balanceOf(address(settlement)), 0, "Settlement should not hold funds");
        assertEq(token.balanceOf(solverAddress), expectedSolverAmount, "Solver balance mismatch");
        assertEq(token.balanceOf(feeRecipient), expectedFee, "Fee recipient balance mismatch");

        // Reputation
        // R_new = (5 * 1000 + 95 * 500) / 100 = 525
        assertEq(registry.getReputation(solverAddress), 525, "Reputation mismatch");

        console.log("[Step 5] All assertions passed!");
        console.log("  Solver received:", expectedSolverAmount / 1e18, "tokens");
        console.log("  Protocol fee:  ", expectedFee / 1e18, "tokens");
        console.log("  New reputation: 525");
        console.log("--- TEST 1 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 2: Multi-Intent Merkle Chain
    // ═════════════════════════════════════════════════════════════════
    //
    // Chains 3 intents through the full pipeline. Verifies:
    //   - Merkle chain head advances correctly at each step
    //   - Each attestation's prev_attest_hash links to the previous one
    //   - Attestation counter increments
    //

    function test_E2E_MultiIntentMerkleChain() public {
        console.log("\n--- TEST 2: Multi-Intent Merkle Chain ---");

        // Register solver
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        // Fund user with enough for 3 intents
        token.mint(userAddress, 300e18);

        bytes32 prevAttestHash = bytes32(0); // Genesis

        for (uint256 i = 1; i <= 3; i++) {
            console.log("  [Chain link", i, "]");

            // User submits intent
            vm.startPrank(userAddress);
            token.approve(address(pool), INTENT_AMOUNT);

            IntentPool.Intent memory intent = IntentPool.Intent({
                user: userAddress,
                tokenIn: address(token),
                tokenOut: address(0x4444),
                amountIn: INTENT_AMOUNT,
                amountOutMin: MIN_AMOUNT_OUT,
                deadline: block.timestamp + 1 hours,
                nonce: i
            });

            bytes32 digest = _getDigest(intent);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
            bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
            vm.stopPrank();

            // TEE signs attestation with correct prev_attest_hash
            SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
                intent_hash: intentHash,
                winner_solver: solverAddress,
                fill_route: address(0x5555),
                output_amount: MIN_AMOUNT_OUT,
                block_number: uint64(block.number),
                prev_attest_hash: prevAttestHash
            });

            bytes memory attestData = abi.encode(att);
            bytes32 attestHash = keccak256(attestData);
            (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);

            settlement.settleIntent(intentHash, att, abi.encodePacked(tr, ts, tv));

            // Verify chain advanced
            assertEq(verifier.getLastAttestHash(), attestHash, "Merkle head should advance");
            assertEq(settlement.getChainHead(), attestHash, "Settlement chain head should match");
            assertEq(verifier.getAttestationCount(), i, "Attestation count mismatch");
            assertTrue(verifier.isIntentSettled(intentHash), "Intent should be settled");

            prevAttestHash = attestHash; // Chain link
            console.log("    Merkle head:", vm.toString(attestHash));
        }

        assertEq(verifier.getAttestationCount(), 3, "Should have 3 attestations");
        console.log("--- TEST 2 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 3: Replay Attack Rejected
    // ═════════════════════════════════════════════════════════════════
    //
    // Tries to settle the same intent twice. The verifier's nonce guard
    // should reject the second attempt (returns false → settlement reverts).
    //

    function test_E2E_ReplayAttackRejected() public {
        console.log("\n--- TEST 3: Replay Attack Rejected ---");

        // Setup: register solver + submit intent + settle once
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });
        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
        vm.stopPrank();

        SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: solverAddress,
            fill_route: address(0x5555),
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: bytes32(0)
        });

        bytes memory attestData = abi.encode(att);
        bytes32 attestHash = keccak256(attestData);
        (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);
        bytes memory teeSig = abi.encodePacked(tr, ts, tv);

        // First settlement succeeds
        settlement.settleIntent(intentHash, att, teeSig);
        assertTrue(settlement.isSettled(intentHash), "First settlement should succeed");
        console.log("  First settlement succeeded");

        // Second settlement should revert (AlreadySettled in Settlement contract)
        vm.expectRevert(
            abi.encodeWithSelector(SolvexSettlement.AlreadySettled.selector, intentHash)
        );
        settlement.settleIntent(intentHash, att, teeSig);
        console.log("  Replay correctly rejected by Settlement nonce guard");
        console.log("--- TEST 3 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 4: Wrong TEE Signature Rejected
    // ═════════════════════════════════════════════════════════════════
    //
    // Signs the attestation with a different private key. The verifier's
    // ecrecover returns a different address → signer != expected → revert.
    //

    function test_E2E_WrongSignatureRejected() public {
        console.log("\n--- TEST 4: Wrong Signature Rejected ---");

        // Setup
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });
        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
        vm.stopPrank();

        SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: solverAddress,
            fill_route: address(0x5555),
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: bytes32(0)
        });

        bytes memory attestData = abi.encode(att);
        bytes32 attestHash = keccak256(attestData);

        // Sign with user's key instead of solver's TEE key
        uint256 wrongKey = 0xBEEF;
        (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(wrongKey, attestHash);
        bytes memory wrongSig = abi.encodePacked(tr, ts, tv);

        console.log("  Signed with wrong key. Expected signer:", solverAddress);
        console.log("  Actual signer:", vm.addr(wrongKey));

        // Verifier returns false → Settlement reverts with AttestationVerificationFailed
        vm.expectRevert(
            abi.encodeWithSelector(SolvexSettlement.AttestationVerificationFailed.selector, intentHash)
        );
        settlement.settleIntent(intentHash, att, wrongSig);

        // Verify no state changed
        assertFalse(settlement.isSettled(intentHash), "Intent should NOT be settled");
        assertEq(token.balanceOf(address(pool)), INTENT_AMOUNT, "Pool should still hold funds");
        assertEq(token.balanceOf(solverAddress), 0, "Solver should have no tokens");
        console.log("  Wrong signature correctly rejected");
        console.log("--- TEST 4 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 5: Merkle Chain Break Rejected
    // ═════════════════════════════════════════════════════════════════
    //
    // Submits an attestation with a wrong prev_attest_hash.
    // The SolvexSettlement Solidity-layer pre-check catches this before
    // even calling the verifier.
    //

    function test_E2E_MerkleChainBreakRejected() public {
        console.log("\n--- TEST 5: Merkle Chain Break Rejected ---");

        // Setup
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });
        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
        vm.stopPrank();

        // Attestation with wrong prev_attest_hash (should be 0 for genesis)
        bytes32 wrongPrevHash = keccak256("wrong_prev_hash");
        SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: solverAddress,
            fill_route: address(0x5555),
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: wrongPrevHash
        });

        bytes memory attestData = abi.encode(att);
        bytes32 attestHash = keccak256(attestData);
        (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);
        bytes memory teeSig = abi.encodePacked(tr, ts, tv);

        // Settlement's Solidity-layer pre-check catches this
        bytes32 expectedChainHead = verifier.getLastAttestHash();
        vm.expectRevert(
            abi.encodeWithSelector(
                SolvexSettlement.MerkleChainBroken.selector,
                expectedChainHead,
                wrongPrevHash
            )
        );
        settlement.settleIntent(intentHash, att, teeSig);

        assertFalse(settlement.isSettled(intentHash), "Should not be settled");
        console.log("  Merkle chain break correctly rejected");
        console.log("--- TEST 5 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 6: Expired Intent Refund
    // ═════════════════════════════════════════════════════════════════
    //
    // User submits intent, nobody fills it, deadline passes,
    // anyone calls refundIntent() → user gets tokens back.
    //

    function test_E2E_ExpiredIntentRefund() public {
        console.log("\n--- TEST 6: Expired Intent Refund ---");

        // Don't need solver for this test, just IntentPool
        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);

        uint256 deadline = block.timestamp + 1 hours;
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: deadline,
            nonce: 1
        });

        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
        vm.stopPrank();

        uint256 userBalanceBefore = token.balanceOf(userAddress);
        assertEq(token.balanceOf(address(pool)), INTENT_AMOUNT, "Pool should hold escrow");
        console.log("  Intent submitted. Escrowed:", INTENT_AMOUNT / 1e18, "tokens");

        // Try refund before deadline — should fail
        vm.expectRevert(
            abi.encodeWithSelector(IntentPool.DeadlineNotReached.selector, intentHash, deadline)
        );
        pool.refundIntent(intentHash);
        console.log("  Early refund correctly rejected");

        // Warp past deadline
        vm.warp(deadline + 1);
        console.log("  Time warped past deadline");

        // Anyone can trigger refund
        pool.refundIntent(intentHash);

        // Verify refund
        IntentPool.EscrowRecord memory rec = pool.getEscrowRecord(intentHash);
        assertEq(uint256(rec.state), 3, "Intent should be EXPIRED");
        assertEq(token.balanceOf(userAddress), userBalanceBefore + INTENT_AMOUNT, "User should get tokens back");
        assertEq(token.balanceOf(address(pool)), 0, "Pool should be empty");
        console.log("  User refunded:", INTENT_AMOUNT / 1e18, "tokens");
        console.log("--- TEST 6 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 7: Fund Flow Verification
    // ═════════════════════════════════════════════════════════════════
    //
    // Tracks every wei through the pipeline to ensure no funds are lost
    // or created. Verifies the conservation of tokens.
    //

    function test_E2E_FundFlowVerification() public {
        console.log("\n--- TEST 7: Fund Flow Verification ---");

        // Setup
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        // Snapshot initial token supply and balances
        uint256 totalSupply = token.totalSupply();
        uint256 userBefore = token.balanceOf(userAddress);
        uint256 solverBefore = token.balanceOf(solverAddress);
        uint256 feeBefore = token.balanceOf(feeRecipient);
        uint256 poolBefore = token.balanceOf(address(pool));
        uint256 settlementBefore = token.balanceOf(address(settlement));

        console.log("  Initial balances:");
        console.log("    User:      ", userBefore / 1e18);
        console.log("    Solver:    ", solverBefore / 1e18);
        console.log("    Fee Recip: ", feeBefore / 1e18);
        console.log("    Pool:      ", poolBefore / 1e18);
        console.log("    Settlement:", settlementBefore / 1e18);

        // Submit intent
        vm.startPrank(userAddress);
        token.approve(address(pool), INTENT_AMOUNT);
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: userAddress,
            tokenIn: address(token),
            tokenOut: address(0x4444),
            amountIn: INTENT_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });
        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
        vm.stopPrank();

        // Verify: user -100, pool +100
        assertEq(token.balanceOf(userAddress), userBefore - INTENT_AMOUNT, "User: -INTENT_AMOUNT");
        assertEq(token.balanceOf(address(pool)), poolBefore + INTENT_AMOUNT, "Pool: +INTENT_AMOUNT");
        console.log("  After submit: User -100, Pool +100");

        // Settle
        SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: solverAddress,
            fill_route: address(0x5555),
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: bytes32(0)
        });
        bytes memory attestData = abi.encode(att);
        bytes32 attestHash = keccak256(attestData);
        (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);
        settlement.settleIntent(intentHash, att, abi.encodePacked(tr, ts, tv));

        // Verify final balances
        uint256 expectedFee = (INTENT_AMOUNT * 10) / 10_000;
        uint256 expectedSolver = INTENT_AMOUNT - expectedFee;

        uint256 userAfter = token.balanceOf(userAddress);
        uint256 solverAfter = token.balanceOf(solverAddress);
        uint256 feeAfter = token.balanceOf(feeRecipient);
        uint256 poolAfter = token.balanceOf(address(pool));
        uint256 settlementAfter = token.balanceOf(address(settlement));

        console.log("  Final balances:");
        console.log("    User:      ", userAfter / 1e18);
        console.log("    Solver:    ", solverAfter / 1e18);
        console.log("    Fee Recip: ", feeAfter / 1e18);
        console.log("    Pool:      ", poolAfter / 1e18);
        console.log("    Settlement:", settlementAfter / 1e18);

        assertEq(userAfter, userBefore - INTENT_AMOUNT, "User balance incorrect");
        assertEq(solverAfter, solverBefore + expectedSolver, "Solver balance incorrect");
        assertEq(feeAfter, feeBefore + expectedFee, "Fee recipient balance incorrect");
        assertEq(poolAfter, 0, "Pool should be empty");
        assertEq(settlementAfter, 0, "Settlement should not hold any tokens");

        // Token supply conservation
        assertEq(token.totalSupply(), totalSupply, "Total supply should not change");

        // Sum of all relevant balances should equal original
        uint256 sumBefore = userBefore + solverBefore + feeBefore + poolBefore + settlementBefore;
        uint256 sumAfter = userAfter + solverAfter + feeAfter + poolAfter + settlementAfter;
        assertEq(sumAfter, sumBefore, "Token conservation violated!");

        console.log("  Token conservation verified: sum before == sum after");
        console.log("--- TEST 7 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // TEST 8: Reputation Progression via EMA
    // ═════════════════════════════════════════════════════════════════
    //
    // Settles 5 intents. Verifies reputation converges via EMA:
    //   R_new = (α * accuracy + (1 - α) * R_prev)
    //   where α = 5/100 = 0.05
    //
    // All fills at exactly min_amount_out → accuracy = 1000 (100%)
    // Expected: 500 → 525 → 548 → 570 → 591 → 611
    //

    function test_E2E_ReputationProgression() public {
        console.log("\n--- TEST 8: Reputation Progression ---");

        // Setup
        vm.deal(solverAddress, 10 ether);
        vm.prank(solverAddress);
        registry.registerSolver{value: 2 ether}(solverAddress, TEE_PUBKEY, "");

        // Fund user with enough for 5 intents
        token.mint(userAddress, 500e18);

        uint256 expectedRep = 500; // Initial
        bytes32 prevAttestHash = bytes32(0);

        console.log("  Initial reputation:", expectedRep);

        for (uint256 i = 1; i <= 5; i++) {
            // Submit intent
            vm.startPrank(userAddress);
            token.approve(address(pool), INTENT_AMOUNT);
            IntentPool.Intent memory intent = IntentPool.Intent({
                user: userAddress,
                tokenIn: address(token),
                tokenOut: address(0x4444),
                amountIn: INTENT_AMOUNT,
                amountOutMin: MIN_AMOUNT_OUT,
                deadline: block.timestamp + 1 hours,
                nonce: i
            });
            bytes32 digest = _getDigest(intent);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
            bytes32 intentHash = pool.submitIntent(intent, abi.encodePacked(r, s, v));
            vm.stopPrank();

            // Settle
            SolvexSettlement.Attestation memory att = SolvexSettlement.Attestation({
                intent_hash: intentHash,
                winner_solver: solverAddress,
                fill_route: address(0x5555),
                output_amount: MIN_AMOUNT_OUT, // Exact match → accuracy = 1000
                block_number: uint64(block.number),
                prev_attest_hash: prevAttestHash
            });

            bytes memory attestData = abi.encode(att);
            bytes32 attestHash = keccak256(attestData);
            (uint8 tv, bytes32 tr, bytes32 ts) = vm.sign(SOLVER_PRIVATE_KEY, attestHash);
            settlement.settleIntent(intentHash, att, abi.encodePacked(tr, ts, tv));

            // Compute expected reputation via EMA
            // R_new = (5 * 1000 + 95 * R_prev) / 100
            expectedRep = (5 * 1000 + 95 * expectedRep) / 100;

            uint256 actualRep = registry.getReputation(solverAddress);
            assertEq(actualRep, expectedRep, string.concat("Rep mismatch at fill #", vm.toString(i)));
            console.log("  Fill #", i, "-> Reputation:", actualRep);

            prevAttestHash = attestHash;
        }

        // After 5 perfect fills: 500 → 525 → 548 → 570 → 591 → 611
        assertGt(registry.getReputation(solverAddress), 500, "Rep should increase above initial");
        console.log("  Reputation converging toward 1000 via EMA (alpha=0.05)");
        console.log("--- TEST 8 PASSED ---\n");
    }

    // ═════════════════════════════════════════════════════════════════
    // Helper: Compute EIP-712 digest (matches IntentPool._hashmessage)
    // ═════════════════════════════════════════════════════════════════

    function _getDigest(IntentPool.Intent memory _intent) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IntentPool")),
                keccak256(bytes("1")),
                block.chainid,
                address(pool)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Intent(address user,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOutMin,uint256 deadline,uint256 nonce)"
                ),
                _intent.user,
                _intent.tokenIn,
                _intent.tokenOut,
                _intent.amountIn,
                _intent.amountOutMin,
                _intent.deadline,
                _intent.nonce
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
