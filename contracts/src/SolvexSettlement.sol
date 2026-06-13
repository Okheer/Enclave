// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20}          from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20}       from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Interfaces for sibling contracts
import {ISolvexVerifier} from "./interfaces/ISolvexVerifier.sol";
import {ISolverRegistry} from "./interfaces/ISolverRegistry.sol";
import {IIntentPool}     from "./interfaces/IIntentPool.sol";

/// @title SolvexSettlement
/// @notice Attestation-gated fund release and solver fee distribution for PRISM.
/// @dev    This is the final layer in the 4-layer PRISM stack. It:
///           1. Receives a TEE-signed attestation from the winning solver
///           2. Forwards it to SolvexVerifier (Stylus/Rust) for ECDSA verification
///           3. On success, instructs IntentPool to release escrowed tokens
///           4. Distributes: (amount_in - protocol_fee) → winning solver
///                           protocol_fee                → feeRecipient
///           5. Updates solver reputation in SolverRegistry
///           6. Slashes solver if it fails to fill within deadline (Phase 2)
///
///         Gas cost of the verification step: ~310 gas via Stylus vs ~3,000 in Solidity.
///
///         @dev DEPENDENCY NOTE — IIntentPool.EscrowRecord:
///              SolvexSettlement expects IntentPool.getEscrowRecord() to return
///              a record that includes `min_amount_out` and `quoted_amount`.
///              The current IntentPool.sol EscrowRecord only stores:
///              { user, token_in, amount_in, deadline, state }.
///              Before deploying, update IntentPool to persist min_amount_out from
///              the submitted Intent struct, and update IIntentPool accordingly.
///              `quoted_amount` is the solver's output quote captured by the TEE;
///              for Phase 1 we approximate it with `min_amount_out` since quotes
///              are sealed inside the enclave and not stored onchain.
contract SolvexSettlement is ReentrancyGuard {
    using SafeERC20 for IERC20;


    struct Attestation {
        bytes32 intent_hash;
        address winner_solver;
        address fill_route;
        uint256 output_amount;
        uint64  block_number;
        bytes32 prev_attest_hash;
    }

    uint256 public constant PROTOCOL_FEE_BPS = 10; // 0.1%

    uint256 private constant BPS_DENOM = 10_000;

    /// @notice Maximum accuracy score used in reputation calculation (1000 = 100%).
    uint256 private constant MAX_ACCURACY = 1_000;

    /// @notice SolvexVerifier (Arbitrum Stylus Rust contract).
    ///         Called with `verify(intent_hash, attestation, tee_sig)`.
    ISolvexVerifier public immutable solvexVerifier;
    ISolverRegistry public immutable solverRegistry;
    IIntentPool     public immutable intentPool;

    address public immutable feeRecipient;


    /// @notice Tracks settled intent hashes (prevents double-settlement).
    ///         Also acts as the Merkle chain anchor alongside SolvexVerifier's
    ///         nonce guard in the Stylus layer.
    mapping(bytes32 => bool) public settled;
    mapping(bytes32 => address) public auctionResults;

    /// @notice Last attestation hash — head of the Merkle chain.
    ///         SolvexVerifier checks that each new attestation's prev_attest_hash
    ///         matches this value (ensures no fills silently dropped).
    bytes32 public lastAttestationHash;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event IntentSettled(
        bytes32 indexed intent_hash,
        address indexed winner_solver,
        address         fill_route,
        uint256         output_amount,
        uint256         fee_paid,
        uint64          block_number
    );

    event AttestationVerified(
        bytes32 indexed intent_hash,
        bytes32         attestation_hash,
        address indexed winner_solver
    );

    event RewardDistributed(
        address indexed solver,
        address         token,
        uint256         solver_amount,
        uint256         protocol_fee
    );

    // Phase 2
    event SolverSlashedForNonFill(address indexed solver, uint256 amount);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error AlreadySettled(bytes32 intent_hash);
    error AttestationVerificationFailed(bytes32 intent_hash);
    error InvalidSolver(address solver);
    error OutputBelowMinimum(uint256 output, uint256 minimum);
    error IntentHashMismatch(bytes32 from_attestation, bytes32 from_pool);
    error MerkleChainBroken(bytes32 expected_prev, bytes32 got_prev);
    error ZeroOutput();

    // Phase 2
    error IntentNotExpired(bytes32 intent_hash, uint256 deadline);
    error IntentAlreadySettled(bytes32 intent_hash);
    error SlashAmountZero();

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param _solvexVerifier  Address of the deployed Stylus SolvexVerifier contract.
    /// @param _solverRegistry  Address of the SolverRegistry contract.
    /// @param _intentPool      Address of the IntentPool contract.
    /// @param _feeRecipient    Protocol treasury address.
    constructor(
        address _solvexVerifier,
        address _solverRegistry,
        address _intentPool,
        address _feeRecipient
    ) {
        require(_solvexVerifier != address(0), "SolvexSettlement: zero verifier");
        require(_solverRegistry != address(0), "SolvexSettlement: zero registry");
        require(_intentPool     != address(0), "SolvexSettlement: zero pool");
        require(_feeRecipient   != address(0), "SolvexSettlement: zero recipient");

        solvexVerifier = ISolvexVerifier(_solvexVerifier);
        solverRegistry = ISolverRegistry(_solverRegistry);
        intentPool     = IIntentPool(_intentPool);
        feeRecipient   = _feeRecipient;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core Settlement
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Settle an intent by verifying a TEE attestation and releasing escrowed funds.
    /// @dev    End-to-end flow:
    ///           1.  Guard: not already settled
    ///           2.  Validate: solver is active and not slashed (SolverRegistry)
    ///           3.  Cross-check: attestation.intent_hash == _intent_hash arg
    ///           4.  Zero-output guard
    ///           5.  Merkle chain pre-check (belt-and-suspenders before Stylus)
    ///           6.  SolvexVerifier call (Stylus/Rust, ~310 gas):
    ///                 a. Nonce/bloom-filter replay guard  (inside Stylus)
    ///                 b. ECDSA signer == solver's TEE pubkey (inside Stylus)
    ///                 c. Merkle chain continuity check    (inside Stylus)
    ///           7.  Min-output check against IntentPool escrow record
    ///           8.  State writes (settled flag + Merkle chain head) — before
    ///               external calls to follow CEI pattern
    ///           9.  Fund release from IntentPool → this contract
    ///           10. Fee distribution: solver gets (amount_in - fee), treasury gets fee
    ///           11. Reputation update in SolverRegistry (accuracy proxy via min_amount_out)
    ///           12. Events for The Graph indexer
    ///
    /// @param  _intent_hash   Canonical intent ID (must match attestation.intent_hash).
    /// @param  _attestation   Attestation struct emitted by the TEE after argmax selection.
    /// @param  _tee_sig       ECDSA signature bytes (65 bytes: r, s, v) from TEE.
    function settleIntent(
        bytes32              _intent_hash,
        Attestation calldata _attestation,
        bytes       calldata _tee_sig
    ) external nonReentrant {

        // ──   Guard: not already settled ────────────────────────────────────
        if (settled[_intent_hash]) revert AlreadySettled(_intent_hash);

        // ──    Solver validity: active, not slashed, TEE key unexpired ───────
        if (!solverRegistry.isValidSolver(_attestation.winner_solver))
            revert InvalidSolver(_attestation.winner_solver);

        // ──    Intent hash cross-check ────────────────────────────────────────
        //       The TEE embeds intent_hash in the attestation; if these diverge
        //       the caller is either replaying a different intent or corrupted.
        if (_attestation.intent_hash != _intent_hash)
            revert IntentHashMismatch(_attestation.intent_hash, _intent_hash);

        // ──    Zero-output guard ──────────────────────────────────────────────
        //       Catches degenerate attestations before hitting the verifier.
        if (_attestation.output_amount == 0) revert ZeroOutput();

        // ──    Merkle chain pre-check (Solidity layer) ────────────────────────
        //       SolvexVerifier also enforces this; duplicating here ensures the
        //       Solidity state machine can never advance without a valid chain.
        bytes32 chainHead = solvexVerifier.getLastAttestHash();
if (_attestation.prev_attest_hash != chainHead)
    revert MerkleChainBroken(chainHead, _attestation.prev_attest_hash);


        // ──    SolvexVerifier call (Arbitrum Stylus / Rust, ~310 gas) ─────────
        //       Performs three checks atomically inside the Rust WASM:
        //         a) bloom-filter nonce guard (prevents intent replay)
        //         b) ecrecover signer == solver.teePubkey in SolverRegistry
        //         c) attestation.prev_attest_hash continuity (Merkle chain)
        //
        //       Attestation must be ABI-encoded for the Stylus verifier contract.
        bytes memory teePubkey = solverRegistry.getTeePublicKey(_attestation.winner_solver);
        address expectedSigner = _pubkeyToAddress(teePubkey);

        bool ok = solvexVerifier.verifyWithExpectedSigner(
            _intent_hash,
            abi.encode(_attestation),
            _tee_sig,
            expectedSigner,
            _attestation.winner_solver
        );
        if (!ok) revert AttestationVerificationFailed(_intent_hash);

        // ──    Min-output check against IntentPool escrow record ──────────────
        //       Fetches the EscrowRecord (which must include min_amount_out —
        //       see DEPENDENCY NOTE in contract NatDoc above).
        IIntentPool.EscrowRecord memory rec = intentPool.getEscrowRecord(_intent_hash);
        if (_attestation.output_amount < rec.min_amount_out)
            revert OutputBelowMinimum(_attestation.output_amount, rec.min_amount_out);

        // ── 8. State writes — CEI: all state before external calls ────────────
        settled[_intent_hash] = true;

        bytes32 attestHash    = keccak256(abi.encode(_attestation));
        lastAttestationHash   = attestHash;

        // ──    Fund release: IntentPool transfers token_in → this contract ────
        //       IntentPool marks the intent FILLED and pushes escrowed tokens
        //       here; settlement then forwards them to solver minus fee.
        (address token_in, uint256 amount_in) =
            intentPool.markFilled(_intent_hash, _attestation.winner_solver);

        // ── 10. Fee distribution ──────────────────────────────────────────────
        uint256 fee = _distributeRewards(token_in, amount_in, _attestation.winner_solver);

        // ──     Reputation update ─────────────────────────────────────────────
        //        accuracy = (output_amount / min_amount_out) * 1000, capped at 1000.
        //        Phase 1 proxy: we can't store the solver's sealed quote onchain,
        //        so min_amount_out serves as the baseline. A solver that fills
        //        at exactly the floor scores 1000; one that fills at 2× scores
        //        still 1000 (capped). Phase 2 will store quoted_amount in
        //        EscrowRecord from the TEE's AuctionResult event.
        uint256 accuracy = (_attestation.output_amount * MAX_ACCURACY) / rec.min_amount_out;
        if (accuracy > MAX_ACCURACY) accuracy = MAX_ACCURACY;
        solverRegistry.updateReputation(_attestation.winner_solver, accuracy);

        // ── 12. Events ────────────────────────────────────────────────────────
        emit AttestationVerified(_intent_hash, attestHash, _attestation.winner_solver);
        emit IntentSettled(
            _intent_hash,
            _attestation.winner_solver,
            _attestation.fill_route,
            _attestation.output_amount,
            fee,
            _attestation.block_number
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fee Distribution (internal)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Split amount_in between winning solver and protocol treasury.
    /// @dev    protocol_fee  = amount_in * PROTOCOL_FEE_BPS / BPS_DENOM
    ///         solver_amount = amount_in - protocol_fee
    ///
    ///         Both transfers use safeTransfer to handle non-standard ERC-20s
    ///         (fee-on-transfer, missing return value, etc.).
    ///
    ///         Returns the fee amount so the caller can include it in the
    ///         IntentSettled event without recomputing.
    ///
    /// @param  _token          ERC-20 token address (must have been transferred here).
    /// @param  _amount         Total amount received from IntentPool escrow.
    /// @param  _winner_solver  Solver that wins the auction.
    /// @return fee             Protocol fee deducted from _amount.
    function _distributeRewards(
        address _token,
        uint256 _amount,
        address _winner_solver
    ) internal returns (uint256 fee) {
        fee = (_amount * PROTOCOL_FEE_BPS) / BPS_DENOM;
        uint256 solverAmount = _amount - fee;

        IERC20(_token).safeTransfer(_winner_solver, solverAmount);
        IERC20(_token).safeTransfer(feeRecipient,   fee);

        emit RewardDistributed(_winner_solver, _token, solverAmount, fee);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slash Trigger (Phase 2 — solver fails to fill after winning auction)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Slash solver stake when it won the auction but failed to fill.
    /// @dev    Phase 2 feature. Callable by anyone after ALL of:
    ///           - The intent deadline has passed
    ///           - The intent is still PENDING (not filled or refunded)
    ///           - An onchain AuctionResult record (emitted by TEE, stored by
    ///             a trusted relay or The Graph) confirms _winner_solver won
    ///
    ///         Phase 1 is a no-op stub. User recourse in Phase 1 is via
    ///         IntentPool.refundIntent() after deadline; no automatic slashing.
    ///
    ///         Phase 2 design notes:
    ///           - AuctionResult storage: either (a) TEE posts a compact
    ///             `AuctionResult(intent_hash, winner_solver, deadline)` event
    ///             onchain before the fill window, stored in a mapping here, or
    ///             (b) a governance-controlled oracle relays it. Option (a) is
    ///             preferred for trustlessness.
    ///           - Slash amount should be governance-set (not caller-supplied)
    ///             to prevent griefing with zero or dust slash amounts.
    ///           - Add a dispute window (e.g. 1 hour) before slash is final.
    ///
    /// @param  _intent_hash     The unfilled intent.
    /// @param  _winner_solver   Solver selected by TEE but didn't fill.
    /// @param  _slash_amount    Amount of stake to slash.
    function slashNonFill(
        bytes32 _intent_hash,
        address _winner_solver,
        uint256 _slash_amount
    ) external {
        // Phase 1: intentional no-op
        // ─────────────────────────────────────────────────────────────────────
        // Phase 2 implementation:
        //
        if (_slash_amount == 0) revert SlashAmountZero();
        
        IIntentPool.EscrowRecord memory rec = intentPool.getEscrowRecord(_intent_hash);
        
        if (rec.state != IIntentPool.IntentState.PENDING)
            revert IntentAlreadySettled(_intent_hash);

        if (block.timestamp <= rec.deadline)
            revert IntentNotExpired(_intent_hash, rec.deadline);
        
        address recorded = auctionResults[_intent_hash];
        require(recorded == _winner_solver, "SolvexSettlement: wrong solver");
        
        solverRegistry.slashSolver(_winner_solver, _slash_amount, "non-fill");
        
        emit SolverSlashedForNonFill(_winner_solver, _slash_amount);
    }

    function isSettled(bytes32 _intent_hash) external view returns (bool) {
        return settled[_intent_hash];
    }
    
    function getChainHead() external view returns (bytes32) {
        return lastAttestationHash;
    }

    /// @notice Compute the protocol fee for a given input amount (for UI preview).
    /// @param  _amount       Total amount to split.
    /// @return fee           Protocol fee portion.
    /// @return solverAmount  Amount the winning solver receives.
    function computeFee(uint256 _amount) external pure returns (uint256 fee, uint256 solverAmount) {
        fee          = (_amount * PROTOCOL_FEE_BPS) / BPS_DENOM;
        solverAmount = _amount - fee;
    }
    function _pubkeyToAddress(bytes memory pubkey) internal pure returns (address) {
        require(pubkey.length == 65, "SolvexSettlement: bad pubkey length");
        // Extract the last 64 bytes (skip the first byte which is the format prefix)
        // and hash them to derive the address
        bytes memory pubkeyXY = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            pubkeyXY[i] = pubkey[i + 1];
        }
        bytes32 h = keccak256(pubkeyXY);
        return address(uint160(uint256(h)));
    }
}
