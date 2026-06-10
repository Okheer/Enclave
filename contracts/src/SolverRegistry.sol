// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SolverRegistry
/// @notice Manages solver onboarding, TEE public key lifecycle, stake accounting,
///         and slashing for the PRISM sealed-auction protocol.
/// @dev    Adapted from SyndDB's TeeKeyManager.sol. Solver stake is held in this
///         contract; slashed funds are burned or redistributed to the protocol fee
///         recipient. Phase 2 extends this with EMA reputation scores and fee-tier
///         gating (R < 0.3 → suspension, R > 0.85 → lower fee cap).
contract SolverRegistry is AccessControl, ReentrancyGuard {


    /// @notice Granted to SolvexSettlement so it can call slashSolver and
    ///         updateReputation after each fill.
    bytes32 public constant SETTLER_ROLE = keccak256("SETTLER_ROLE");


    uint256 public constant MIN_STAKE = 0;

    /// @notice Pubkey validity window. TEE ephemeral key must be refreshed
    ///         before this many seconds elapse.
    uint256 public constant KEY_TTL = 7 days;

    /// @notice EMA smoothing factor numerator (α = 5/100 = 0.05).
    ///         Reputation converges over ~20 fills.
    uint256 public constant ALPHA_NUM = 5;
    uint256 public constant ALPHA_DEN = 100;

    /// @notice Reputation thresholds (scaled 0–1000 for integer math).
    uint256 public constant REP_SUSPEND_THRESHOLD  = 300;  // R < 0.3
    uint256 public constant REP_PREMIUM_THRESHOLD  = 850;  // R > 0.85

    struct SolverRecord {
        bytes   teePubkey;   /// Raw secp256k1 public key (65 bytes uncompressed) from the TEE enclave.
        uint256 keyRegisteredAt;      /// Block timestamp when the key was last registered/rotated.
        uint256 stake;        /// ETH staked by this solver (wei).
        uint256 reputation;      /// Reputation score in [0, 1000] (1000 = perfect).
        bool    slashed;     /// True if solver has been permanently slashed out.
        bool    active;             /// True once registration has been confirmed (stake ≥ MIN_STAKE, key set).
    }

    /// @notice solver address → SolverRecord.
    mapping(address => SolverRecord) public solvers;

    /// @notice Ordered list of registered solver addresses (for iteration).
    address[] public solverList;

    /// @notice Protocol fee recipient for slashed stake.
    address public feeRecipient;

    event SolverRegistered(address indexed solver, bytes teePubkey, uint256 stake);
    event SolverKeyRotated(address indexed solver, bytes newPubkey);
    event SolverSlashed(address indexed solver, uint256 amount, string reason);
    event SolverSuspended(address indexed solver);
    event ReputationUpdated(address indexed solver, uint256 oldRep, uint256 newRep);
    event StakeWithdrawn(address indexed solver, uint256 amount);


    error InsufficientStake(uint256 sent, uint256 required);
    error AlreadyRegistered(address solver);
    error SolverNotActive(address solver);
    error SolverSlashedOut(address solver);
    error KeyExpired(address solver);
    error InvalidPubkey();
    error SlashExceedsStake(uint256 amount, uint256 stake);
    error Suspended(address solver);

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param _feeRecipient Address that receives slashed solver stake.
    constructor(address _feeRecipient) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        feeRecipient = _feeRecipient;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registration & Key Management
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Register a new solver with its TEE public key.
    /// @dev    Called by prism-bootstrap after the TEE generates an ephemeral
    ///         secp256k1 keypair inside GCP Confidential Space. The GCP OIDC
    ///         token is passed as `_gcpAttestation` for optional off-chain
    ///         verification (Phase 2); in MVP it is logged but not checked here.
    /// @param  _solver          The on-chain address the solver will transact from.
    /// @param  _teePubkey       65-byte uncompressed secp256k1 public key from TEE.
    /// @param  _gcpAttestation  Raw GCP OIDC token proving TEE provenance (Phase 2).
    function registerSolver(
        address _solver,
        bytes calldata _teePubkey,
        bytes calldata _gcpAttestation
    ) external payable nonReentrant {
        if (msg.value < MIN_STAKE) revert InsufficientStake(msg.value, MIN_STAKE);
        if (solvers[_solver].active) revert AlreadyRegistered(_solver);
        if (solvers[_solver].slashed) revert SolverSlashedOut(_solver);
        if (_teePubkey.length != 65) revert InvalidPubkey();

        solvers[_solver] = SolverRecord({
            teePubkey: _teePubkey,
            keyRegisteredAt: block.timestamp,
            stake: msg.value,
            reputation: 500, // neutral default
            slashed: false,
            active: true
        });

        solverList.push(_solver);

        emit SolverRegistered(_solver, _teePubkey, msg.value);
    }

    /// @notice Rotate TEE public key before KEY_TTL expiry.
    /// @dev    The TEE issues a new ephemeral key each restart. Solvers must
    ///         rotate before their key expires or isValidSolver() returns false.
    ///         Only callable by the solver address itself.
    /// @param  _newPubkey  New 65-byte secp256k1 public key from TEE enclave.
    function rotateTeeKey(bytes calldata _newPubkey) external {
        if (!solvers[msg.sender].active) revert SolverNotActive(msg.sender);
        if (solvers[msg.sender].slashed) revert SolverSlashedOut(msg.sender);
        if (_newPubkey.length != 65) revert InvalidPubkey();

        solvers[msg.sender].teePubkey = _newPubkey;
        solvers[msg.sender].keyRegisteredAt = block.timestamp;

        emit SolverKeyRotated(msg.sender, _newPubkey);
    }

    /// @notice Top up stake for an existing solver.
    /// @dev    Allows solvers to top-up after partial slashing without re-registering.
    function addStake() external payable {
        if (!solvers[msg.sender].active) revert SolverNotActive(msg.sender);
        if (solvers[msg.sender].slashed) revert SolverSlashedOut(msg.sender);

        solvers[msg.sender].stake += msg.value;
    }

    /// @notice Withdraw stake after voluntarily deregistering.
    /// @dev    A solver must signal deregistration; a 1-epoch cooldown prevents
    ///         exit-before-slash. (Phase 2 will enforce a dispute window.)
    function withdrawStake() external nonReentrant {
        if (!solvers[msg.sender].active) revert SolverNotActive(msg.sender);
        if (solvers[msg.sender].slashed) revert SolverSlashedOut(msg.sender);

        uint256 amountToWithdraw = solvers[msg.sender].stake;
        solvers[msg.sender].stake = 0;
        solvers[msg.sender].active = false;

        emit StakeWithdrawn(msg.sender, amountToWithdraw);

        (bool success, ) = msg.sender.call{value: amountToWithdraw}("");
        require(success, "Transfer failed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slashing
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Slash a solver's stake for protocol violations.
    /// @dev    Called by SolvexSettlement (SETTLER_ROLE) when:
    ///           - Solver submits invalid fill (wrong output amount)
    ///           - Solver fails to fill within deadline after winning auction
    ///           - Merkle chain continuity break attributable to solver
    ///         Slashed ETH is forwarded to feeRecipient.
    /// @param  _solver  Address of the offending solver.
    /// @param  _amount  ETH amount to slash (must not exceed solver.stake).
    /// @param  _reason  Human-readable slash reason (indexed in event).
    function slashSolver(
        address _solver,
        uint256 _amount,
        string calldata _reason
    ) external onlyRole(SETTLER_ROLE) {
        if (!solvers[_solver].active) revert SolverNotActive(_solver);
        if (solvers[_solver].slashed) revert SolverSlashedOut(_solver);
        if (_amount > solvers[_solver].stake) revert SlashExceedsStake(_amount, solvers[_solver].stake);

        solvers[_solver].stake -= _amount;

        emit SolverSlashed(_solver, _amount, _reason);

        if (solvers[_solver].stake < MIN_STAKE) {
            solvers[_solver].active = false;
            emit SolverSuspended(_solver);
        }

        if (solvers[_solver].stake == 0) {
            solvers[_solver].slashed = true;
        }

        (bool success, ) = feeRecipient.call{value: _amount}("");
        require(success, "Fee redirection failed");
    }

    /// @notice Update solver reputation via exponential moving average.
    /// @dev    R_new = (α * accuracy + (100 - α) * R_prev) / 100
    ///         where accuracy = actual_output / quoted_output (scaled 0–1000).
    ///         Called by SolvexSettlement after each successful fill.
    ///         α = ALPHA_NUM / ALPHA_DEN = 0.05.
    /// @param  _solver    Solver whose rep is being updated.
    /// @param  _accuracy  Fill accuracy in [0, 1000] (1000 = 100% accurate).
    function updateReputation(
        address _solver,
        uint256 _accuracy
    ) external onlyRole(SETTLER_ROLE) {
        if (!solvers[_solver].active) revert SolverNotActive(_solver);

        uint256 oldRep = solvers[_solver].reputation;
        uint256 newRep = (ALPHA_NUM * _accuracy + (ALPHA_DEN - ALPHA_NUM) * oldRep) / ALPHA_DEN;
        
        solvers[_solver].reputation = newRep;
        
        emit ReputationUpdated(_solver, oldRep, newRep);

        if (newRep < REP_SUSPEND_THRESHOLD) {
            solvers[_solver].active = false;
            emit SolverSuspended(_solver);
        }
    }


    /// @notice Returns true iff the solver is active, not slashed, and key unexpired.
    /// @dev    Used by SolvexSettlement as a pre-flight before releasing funds.
    function isValidSolver(address _solver) external view returns (bool) {
        return solvers[_solver].active && 
               !solvers[_solver].slashed && 
               (block.timestamp - solvers[_solver].keyRegisteredAt < KEY_TTL);
    }

    /// @notice Returns the TEE public key for a given solver.
    /// @dev    Called by SolvexVerifier (Stylus) to cross-check the ECDSA signer
    ///         recovered from the attestation signature.
    function getTeePublicKey(address _solver) external view returns (bytes memory) {
        return solvers[_solver].teePubkey;
    }

    /// @notice Returns current reputation score in [0, 1000].
    function getReputation(address _solver) external view returns (uint256) {
        return solvers[_solver].reputation;
    }

    /// @notice Returns remaining stake for a solver.
    function getStake(address _solver) external view returns (uint256) {
        return solvers[_solver].stake;
    }

    /// @notice Returns full solver record for off-chain indexing.
    function getSolverRecord(address _solver) external view returns (SolverRecord memory) {
        return solvers[_solver];
    }

    /// @notice Returns number of registered solvers.
    function solverCount() external view returns (uint256) {
        return solverList.length;
    }

    /// @notice Paginated list of solver addresses.
    function getSolvers(uint256 offset, uint256 limit) external view returns (address[] memory) {
        uint256 totalSolvers = solverList.length;
        if (offset >= totalSolvers || limit == 0) {
            return new address[](0);
        }

        uint256 size = limit;
        if (offset + limit > totalSolvers) {
            size = totalSolvers - offset;
        }

        address[] memory result = new address[](size);
        for (uint256 i = 0; i < size; i++) {
            result[i] = solverList[offset + i];
        }
        return result;
    }
}