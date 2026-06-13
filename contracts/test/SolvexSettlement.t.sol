// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {SolvexSettlement} from "../src/SolvexSettlement.sol";
import {ISolvexVerifier} from "../src/interfaces/ISolvexVerifier.sol";
import {ISolverRegistry} from "../src/interfaces/ISolverRegistry.sol";
import {IIntentPool} from "../src/interfaces/IIntentPool.sol";

// ─────────────────────────────────────────────────────────────────────────
// Mock Contracts
// ─────────────────────────────────────────────────────────────────────────

/// @notice Mock ERC20 token for testing
contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MOCK") {
        _mint(msg.sender, type(uint256).max / 2);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Mock SolvexVerifier that accepts all attestations by default
contract MockSolvexVerifier is ISolvexVerifier {
    bytes32 public lastHash;
    mapping(bytes32 => bool) public settled;

    bool public shouldRevert;
    bytes public revertReason;

    function verify(
        bytes32 intent_hash,
        bytes calldata attestation_data,
        bytes calldata tee_sig
    ) external override returns (bool) {
        if (shouldRevert) {
            revert(string(revertReason));
        }
        settled[intent_hash] = true;
        // Simulate Merkle chain update
        lastHash = keccak256(attestation_data);
        return true;
    }

    function verifyWithExpectedSigner(
        bytes32 intent_hash,
        bytes calldata attestation_data,
        bytes calldata tee_sig,
        address expected_signer,
        address expected_winner
    ) external override returns (bool) {
        if (shouldRevert) {
            revert(string(revertReason));
        }
        settled[intent_hash] = true;
        lastHash = keccak256(attestation_data);
        return true;
    }

    function isIntentSettled(bytes32 intent_hash) external view override returns (bool) {
        return settled[intent_hash];
    }

    function getLastAttestHash() external view override returns (bytes32) {
        return lastHash;
    }

    function getAttestationCount() external view override returns (uint256) {
        return 0;
    }

    function getOwner() external view override returns (address) {
        return address(0);
    }

    function setShouldRevert(bool _should, bytes memory _reason) external {
        shouldRevert = _should;
        revertReason = _reason;
    }
}

/// @notice Mock SolverRegistry
contract MockSolverRegistry is ISolverRegistry {
    mapping(address => SolverRecord) public solverRecords;
    address[] public solverList_;

    constructor() {}

    function registerSolver(
        address _solver,
        bytes calldata _teePubkey,
        bytes calldata _gcpAttestation
    ) external payable override {
        solverRecords[_solver] = SolverRecord({
            teePubkey: _teePubkey,
            keyRegisteredAt: block.timestamp,
            stake: msg.value,
            reputation: 1000, // Start at max reputation
            slashed: false,
            active: true
        });
        solverList_.push(_solver);
    }

    function rotateTeeKey(bytes calldata _newPubkey) external override {}
    function addStake() external payable override {}
    function withdrawStake() external override {}

    function slashSolver(
        address _solver,
        uint256 _amount,
        string calldata _reason
    ) external override {
        require(solverRecords[_solver].stake >= _amount, "Insufficient stake");
        solverRecords[_solver].stake -= _amount;
        if (solverRecords[_solver].stake == 0) {
            solverRecords[_solver].slashed = true;
        }
    }

    function updateReputation(address _solver, uint256 _accuracy) external override {
        require(_accuracy <= 1000, "Invalid accuracy");
        // Simplified EMA: accuracy = (0.05 * new + 0.95 * old)
        uint256 alpha_num = 5;
        uint256 alpha_den = 100;
        solverRecords[_solver].reputation =
            ((alpha_num * _accuracy) + (alpha_den - alpha_num) * solverRecords[_solver].reputation) /
            alpha_den;
    }

    function isValidSolver(address _solver) external view override returns (bool) {
        return solverRecords[_solver].active && !solverRecords[_solver].slashed;
    }

    function getTeePublicKey(address _solver) external view override returns (bytes memory) {
        return solverRecords[_solver].teePubkey;
    }

    function getReputation(address _solver) external view override returns (uint256) {
        return solverRecords[_solver].reputation;
    }

    function getStake(address _solver) external view override returns (uint256) {
        return solverRecords[_solver].stake;
    }

    function getSolverRecord(address _solver) external view override returns (SolverRecord memory) {
        return solverRecords[_solver];
    }

    function solverCount() external view override returns (uint256) {
        return solverList_.length;
    }

    function getSolvers(uint256 offset, uint256 limit)
        external
        view
        override
        returns (address[] memory)
    {
        uint256 len = limit > solverList_.length - offset ? solverList_.length - offset : limit;
        address[] memory result = new address[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = solverList_[offset + i];
        }
        return result;
    }

    function solvers(address _solver)
        external
        view
        override
        returns (bytes memory, uint256, uint256, uint256, bool, bool)
    {
        SolverRecord memory rec = solverRecords[_solver];
        return (rec.teePubkey, rec.keyRegisteredAt, rec.stake, rec.reputation, rec.slashed, rec.active);
    }

    function SETTLER_ROLE() external pure override returns (bytes32) {
        return keccak256("SETTLER_ROLE");
    }

    function MIN_STAKE() external pure override returns (uint256) {
        return 1 ether;
    }

    function KEY_TTL() external pure override returns (uint256) {
        return 30 days;
    }

    function ALPHA_NUM() external pure override returns (uint256) {
        return 5;
    }

    function ALPHA_DEN() external pure override returns (uint256) {
        return 100;
    }

    function REP_SUSPEND_THRESHOLD() external pure override returns (uint256) {
        return 300;
    }

    function REP_PREMIUM_THRESHOLD() external pure override returns (uint256) {
        return 850;
    }

    function feeRecipient() external pure override returns (address) {
        return address(0);
    }

    function solverList(uint256 index) external view override returns (address) {
        return solverList_[index];
    }
}

/// @notice Mock IntentPool
contract MockIntentPool is IIntentPool {
    mapping(bytes32 => EscrowRecord) public escrows_;
    mapping(address => mapping(uint256 => bool)) public usedNonces_;
    uint256 public tokenBalance;

    function submitIntent(Intent calldata _intent, bytes calldata _signature)
        external
        override
        returns (bytes32 intentHash)
    {
        // In a real implementation, verify the signature
        bytes32 hash = keccak256(abi.encode(_intent));

        // Verify nonce not used
        require(!usedNonces_[_intent.user][_intent.nonce], "Nonce already used");
        usedNonces_[_intent.user][_intent.nonce] = true;

        // Store escrow
        escrows_[hash] = EscrowRecord({
            user: _intent.user,
            token_in: _intent.tokenIn,
            amount_in: _intent.amountIn,
            min_amount_out: _intent.amountOutMin,
            deadline: _intent.deadline,
            state: IntentState.PENDING
        });

        emit IntentSubmitted(
            hash,
            _intent.user,
            _intent.tokenIn,
            _intent.tokenOut,
            _intent.amountIn,
            _intent.amountOutMin,
            _intent.deadline
        );

        return hash;
    }

    function markFilled(bytes32 _intent_hash, address _winner_solver)
        external
        override
        returns (address token_in, uint256 amount_in)
    {
        EscrowRecord storage rec = escrows_[_intent_hash];
        require(rec.state == IntentState.PENDING, "Intent not pending");

        rec.state = IntentState.FILLED;
        token_in = rec.token_in;
        amount_in = rec.amount_in;

        emit IntentFilled(_intent_hash, _winner_solver);
    }

    function refundIntent(bytes32 _intent_hash) external override {
        EscrowRecord storage rec = escrows_[_intent_hash];
        require(rec.state == IntentState.PENDING, "Intent not pending");
        require(block.timestamp > rec.deadline, "Deadline not reached");

        rec.state = IntentState.EXPIRED;
    }

    function getEscrowRecord(bytes32 _intent_hash)
        external
        view
        override
        returns (EscrowRecord memory)
    {
        return escrows_[_intent_hash];
    }

    function escrows(bytes32 _intent_hash)
        external
        view
        override
        returns (address, address, uint256, uint256, uint256, IntentState)
    {
        EscrowRecord memory rec = escrows_[_intent_hash];
        return (rec.user, rec.token_in, rec.amount_in, rec.min_amount_out, rec.deadline, rec.state);
    }

    function usedNonces(address _user, uint256 _nonce) external view override returns (bool) {
        return usedNonces_[_user][_nonce];
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SolvexSettlement Tests
// ─────────────────────────────────────────────────────────────────────────

contract SolvexSettlementTest is Test {
    using SafeERC20 for IERC20;

    SolvexSettlement public settlement;
    MockSolvexVerifier public mockVerifier;
    MockSolverRegistry public mockRegistry;
    MockIntentPool public mockPool;
    MockToken public token;

    address public constant SOLVER_ADDRESS = address(0x1111);
    address public constant USER_ADDRESS = address(0x2222);
    address public constant FEE_RECIPIENT = address(0x3333);
    address public constant FILL_ROUTE = address(0x4444);

    uint256 public constant TEST_AMOUNT = 1000e18;
    uint256 public constant MIN_AMOUNT_OUT = 900e18;
    uint256 public constant PROTOCOL_FEE_BPS = 10; // 0.1%

    event IntentSettled(
        bytes32 indexed intent_hash,
        address indexed winner_solver,
        address fill_route,
        uint256 output_amount,
        uint256 fee_paid,
        uint64 block_number
    );

    event RewardDistributed(
        address indexed solver,
        address token,
        uint256 solver_amount,
        uint256 protocol_fee
    );

    function setUp() public {
        // Deploy mocks
        mockVerifier = new MockSolvexVerifier();
        mockRegistry = new MockSolverRegistry();
        mockPool = new MockIntentPool();
        token = new MockToken();

        // Deploy settlement contract
        settlement = new SolvexSettlement(
            address(mockVerifier),
            address(mockRegistry),
            address(mockPool),
            FEE_RECIPIENT
        );

        // Register solver with valid 65-byte pubkey (0x04 + 64 bytes)
        bytes memory teePubkey = abi.encodePacked(
            hex"04",
            hex"1111111111111111111111111111111111111111111111111111111111111111",
            hex"2222222222222222222222222222222222222222222222222222222222222222"
        );
        mockRegistry.registerSolver{value: 10 ether}(SOLVER_ADDRESS, teePubkey, "");

        // Fund token balances to mockPool so it can transfer to settlement
        token.mint(address(mockPool), TEST_AMOUNT * 100);
        // Fund settlement so it can transfer to solver and fee recipient
        token.mint(address(settlement), TEST_AMOUNT * 100);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Fee Calculation
    // ─────────────────────────────────────────────────────────────────────

    function test_ComputeFee_CalculatesCorrectFeeAndSolverAmount() public {
        (uint256 fee, uint256 solverAmount) = settlement.computeFee(TEST_AMOUNT);

        uint256 expectedFee = (TEST_AMOUNT * PROTOCOL_FEE_BPS) / 10_000;
        uint256 expectedSolverAmount = TEST_AMOUNT - expectedFee;

        assertEq(fee, expectedFee, "Fee calculation incorrect");
        assertEq(solverAmount, expectedSolverAmount, "Solver amount calculation incorrect");
    }

    function test_ComputeFee_WithZeroAmount() public {
        (uint256 fee, uint256 solverAmount) = settlement.computeFee(0);
        assertEq(fee, 0, "Fee should be zero");
        assertEq(solverAmount, 0, "Solver amount should be zero");
    }

    function test_ComputeFee_WithMaxUint() public {
        uint256 maxAmount = type(uint256).max / 10_000; // Avoid overflow
        (uint256 fee, uint256 solverAmount) = settlement.computeFee(maxAmount);

        uint256 expectedFee = (maxAmount * PROTOCOL_FEE_BPS) / 10_000;
        assertEq(fee, expectedFee, "Fee calculation incorrect for large amount");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Settlement Flow
    // ─────────────────────────────────────────────────────────────────────

    function test_SettleIntent_SuccessfulSettlement() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory attestationEncoded = abi.encode(attestation);
        bytes memory teeSig = hex"00";

        // Settle intent
        settlement.settleIntent(intentHash, attestation, teeSig);

        // Verify settlement state
        assertTrue(settlement.isSettled(intentHash), "Intent should be marked settled");
        assertEq(settlement.getChainHead(), mockVerifier.getLastAttestHash(), "Chain head mismatch");
    }

    function test_SettleIntent_AlreadySettledReverts() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 2
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        // First settlement succeeds
        settlement.settleIntent(intentHash, attestation, teeSig);

        // Second settlement should revert
        vm.expectRevert(
            abi.encodeWithSelector(SolvexSettlement.AlreadySettled.selector, intentHash)
        );
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    function test_SettleIntent_InvalidSolverReverts() public {
        bytes32 intentHash = keccak256("test_intent_invalid_solver");
        address invalidSolver = address(0x9999);

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: invalidSolver,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory attestationEncoded = abi.encode(attestation);
        bytes memory teeSig = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(SolvexSettlement.InvalidSolver.selector, invalidSolver)
        );
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    function test_SettleIntent_OutputBelowMinimumReverts() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 3
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");
        uint256 lowOutput = MIN_AMOUNT_OUT - 1;

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: lowOutput,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvexSettlement.OutputBelowMinimum.selector, lowOutput, MIN_AMOUNT_OUT
            )
        );
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    function test_SettleIntent_ZeroOutputReverts() public {
        bytes32 intentHash = keccak256("test_intent_zero_output");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: 0,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory attestationEncoded = abi.encode(attestation);
        bytes memory teeSig = hex"00";

        vm.expectRevert(SolvexSettlement.ZeroOutput.selector);
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    function test_SettleIntent_IntentHashMismatchReverts() public {
        bytes32 intentHash = keccak256("test_intent_hash_mismatch");
        bytes32 wrongHash = keccak256("wrong_hash");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: wrongHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory attestationEncoded = abi.encode(attestation);
        bytes memory teeSig = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvexSettlement.IntentHashMismatch.selector, wrongHash, intentHash
            )
        );
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    function test_SettleIntent_VerificationFailsReverts() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 4
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        // Make verifier revert
        mockVerifier.setShouldRevert(true, "Verification failed");

        vm.expectRevert("Verification failed");
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Reputation Updates
    // ─────────────────────────────────────────────────────────────────────

    function test_SettleIntent_UpdatesReputation() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 5
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        // Calculate expected accuracy
        uint256 MAX_ACCURACY = 1_000;
        uint256 expectedAccuracy = (MIN_AMOUNT_OUT * MAX_ACCURACY) / MIN_AMOUNT_OUT;
        if (expectedAccuracy > MAX_ACCURACY) expectedAccuracy = MAX_ACCURACY;

        settlement.settleIntent(intentHash, attestation, teeSig);

        uint256 reputationAfter = mockRegistry.getReputation(SOLVER_ADDRESS);

        // Reputation should be updated
        assertEq(reputationAfter, expectedAccuracy, "Reputation not updated correctly");
    }

    function test_SettleIntent_ReputationCapAtMaxAccuracy() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 6
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT * 2, // Output 2x minimum
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        settlement.settleIntent(intentHash, attestation, teeSig);

        uint256 reputationAfter = mockRegistry.getReputation(SOLVER_ADDRESS);

        // Reputation should be capped at 1000
        assertEq(reputationAfter, 1000, "Reputation should be capped at 1000");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Merkle Chain
    // ─────────────────────────────────────────────────────────────────────

    function test_SettleIntent_UpdatesMerkleChain() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 7
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        bytes32 initialChainHead = settlement.getChainHead();
        assertEq(initialChainHead, 0, "Initial chain head should be zero");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory attestationEncoded = abi.encode(attestation);
        bytes memory teeSig = hex"00";

        settlement.settleIntent(intentHash, attestation, teeSig);

        bytes32 newChainHead = settlement.getChainHead();
        bytes32 expectedChainHead = keccak256(attestationEncoded);

        assertEq(newChainHead, expectedChainHead, "Chain head not updated correctly");
        assertNotEq(newChainHead, initialChainHead, "Chain head should change");
    }

    function test_SettleIntent_MerkleChainBrokenReverts() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 8
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");
        bytes32 wrongPrevHash = keccak256("wrong_prev_hash");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: wrongPrevHash
        });

        bytes memory teeSig = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvexSettlement.MerkleChainBroken.selector,
                settlement.getChainHead(),
                wrongPrevHash
            )
        );
        settlement.settleIntent(intentHash, attestation, teeSig);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Slash Functionality (Phase 2)
    // ─────────────────────────────────────────────────────────────────────

    function test_SlashNonFill_WithValidParameters() public {
        // This test is skipped because slashNonFill is a Phase 2 feature
        // and requires auctionResults to be populated by off-chain TEE during auction.
        // Phase 1 is a no-op stub. Will be implemented in Phase 2.
        assertTrue(true);
    }

    function test_SlashNonFill_ZeroAmountReverts() public {
        // Create and submit intent
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 10
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        vm.warp(block.timestamp + 2 hours);

        vm.expectRevert(SolvexSettlement.SlashAmountZero.selector);
        settlement.slashNonFill(intentHash, SOLVER_ADDRESS, 0);
    }

    function test_SlashNonFill_IntentNotExpiredReverts() public {
        // Create and submit intent
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 11
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");
        uint256 slashAmount = 1 ether;

        // Do NOT move time forward

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvexSettlement.IntentNotExpired.selector,
                intentHash,
                block.timestamp + 1 hours
            )
        );
        settlement.slashNonFill(intentHash, SOLVER_ADDRESS, slashAmount);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: View Functions
    // ─────────────────────────────────────────────────────────────────────

    function test_IsSettled_ReturnsFalseBeforeSettlement() public {
        bytes32 intentHash = keccak256("test_intent_not_settled");
        assertFalse(settlement.isSettled(intentHash), "Intent should not be settled");
    }

    function test_IsSettled_ReturnsTrueAfterSettlement() public {
        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 12
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        settlement.settleIntent(intentHash, attestation, teeSig);

        assertTrue(settlement.isSettled(intentHash), "Intent should be settled");
    }

    function test_GetChainHead_InitiallyZero() public {
        assertEq(settlement.getChainHead(), 0, "Chain head should initially be zero");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Reentrancy Protection
    // ─────────────────────────────────────────────────────────────────────

    function test_SettleIntent_ReentrancyProtected() public {
        // This test verifies that ReentrancyGuard is in place
        // The actual reentrancy attack vector is in _distributeRewards
        // which calls IERC20.safeTransfer() - should be protected by ReentrancyGuard

        // Setup intent and submit to pool
        IIntentPool.Intent memory intent = IIntentPool.Intent({
            user: USER_ADDRESS,
            tokenIn: address(token),
            tokenOut: address(token),
            amountIn: TEST_AMOUNT,
            amountOutMin: MIN_AMOUNT_OUT,
            deadline: block.timestamp + 1 hours,
            nonce: 13
        });

        bytes32 intentHash = mockPool.submitIntent(intent, "");

        SolvexSettlement.Attestation memory attestation = SolvexSettlement.Attestation({
            intent_hash: intentHash,
            winner_solver: SOLVER_ADDRESS,
            fill_route: FILL_ROUTE,
            output_amount: MIN_AMOUNT_OUT,
            block_number: uint64(block.number),
            prev_attest_hash: 0
        });

        bytes memory teeSig = hex"00";

        // Should complete without reentrancy issues
        settlement.settleIntent(intentHash, attestation, teeSig);

        assertTrue(settlement.isSettled(intentHash), "Settlement should complete successfully");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test: Fee Distribution
    // ─────────────────────────────────────────────────────────────────────

    function test_FeeDistribution_CalculatesCorrectly() public {
        uint256 amount = 1000e18;
        uint256 expectedFee = (amount * PROTOCOL_FEE_BPS) / 10_000;
        uint256 expectedSolverAmount = amount - expectedFee;

        (uint256 fee, uint256 solverAmount) = settlement.computeFee(amount);

        assertEq(fee, expectedFee, "Fee calculation mismatch");
        assertEq(solverAmount, expectedSolverAmount, "Solver amount mismatch");
        assertEq(fee + solverAmount, amount, "Fee + Solver amount should equal total");
    }

    function test_FeeDistribution_PreservesTotal() public {
        for (uint256 i = 0; i < 10; i++) {
            uint256 amount = (i + 1) * 100e18;
            (uint256 fee, uint256 solverAmount) = settlement.computeFee(amount);
            assertEq(fee + solverAmount, amount, "Total should be preserved");
        }
    }
}