// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

interface IIntentPool {

    enum IntentState { NONEXISTING, PENDING, FILLED, EXPIRED, CANCELLED }

    struct Intent {
        address user;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOutMin;
        uint256 deadline;
        uint256 nonce;
    }

    struct EscrowRecord {
        address     user;
        address     token_in;
        uint256     amount_in;
        uint256     min_amount_out; 
        uint256     deadline;
        IntentState state;
    }

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

    error BadSignature();
    error DeadlineExpired(uint256 deadline, uint256 now_);
    error SameToken(address token);
    error ZeroAmount();
    error Unauthorized(address caller);
    error IntentNotPending(bytes32 intent_hash, IntentState state);
    error DeadlineNotReached(bytes32 intent_hash, uint256 deadline);

    // ─────────────────────────────────────────────────────────────────────────
    // External Functions
    // ─────────────────────────────────────────────────────────────────────────

    function submitIntent(
        Intent calldata _intent,
        bytes calldata _signature
    ) external returns (bytes32 intentHash);

    function markFilled(
        bytes32 _intent_hash,
        address _winner_solver
    ) external returns (address token_in, uint256 amount_in);

    function refundIntent(bytes32 _intent_hash) external;

    function getEscrowRecord(bytes32 _intent_hash) external view returns (EscrowRecord memory);
    
    function escrows(bytes32 _intent_hash) external view returns (
        address user,
        address token_in,
        uint256 amount_in,
        uint256 min_amount_out,
        uint256 deadline,
        IntentState state
    );
    
    function usedNonces(address _user, uint256 _nonce) external view returns (bool);
}