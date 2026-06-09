// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

interface ISolverRegistry {
    // ─────────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────────

    struct SolverRecord {
        bytes   teePubkey;   
        uint256 keyRegisteredAt;      
        uint256 stake;        
        uint256 reputation;      
        bool    slashed;     
        bool    active;             
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events & Errors
    // ─────────────────────────────────────────────────────────────────────────

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
    // State Variables / Constants Getters
    // ─────────────────────────────────────────────────────────────────────────

    function SETTLER_ROLE() external view returns (bytes32);
    function MIN_STAKE() external view returns (uint256);
    function KEY_TTL() external view returns (uint256);
    function ALPHA_NUM() external view returns (uint256);
    function ALPHA_DEN() external view returns (uint256);
    function REP_SUSPEND_THRESHOLD() external view returns (uint256);
    function REP_PREMIUM_THRESHOLD() external view returns (uint256);
    function feeRecipient() external view returns (address);
    function solverList(uint256 index) external view returns (address);

    // ─────────────────────────────────────────────────────────────────────────
    // Mutative Core Functions
    // ─────────────────────────────────────────────────────────────────────────

    function registerSolver(
        address _solver,
        bytes calldata _teePubkey,
        bytes calldata _gcpAttestation
    ) external payable;

    function rotateTeeKey(bytes calldata _newPubkey) external;

    function addStake() external payable;

    function withdrawStake() external;

    function slashSolver(
        address _solver,
        uint256 _amount,
        string calldata _reason
    ) external;

    function updateReputation(address _solver, uint256 _accuracy) external;

    // ─────────────────────────────────────────────────────────────────────────
    // View Functions
    // ─────────────────────────────────────────────────────────────────────────

    function isValidSolver(address _solver) external view returns (bool);
    function getTeePublicKey(address _solver) external view returns (bytes memory);
    function getReputation(address _solver) external view returns (uint256);
    function getStake(address _solver) external view returns (uint256);
    function getSolverRecord(address _solver) external view returns (SolverRecord memory);
    function solverCount() external view returns (uint256);
    function getSolvers(uint256 offset, uint256 limit) external view returns (address[] memory);
    function solvers(address _solver) external view returns (
        bytes memory teePubkey,
        uint256 keyRegisteredAt,
        uint256 stake,
        uint256 reputation,
        bool slashed,
        bool active
    );
}