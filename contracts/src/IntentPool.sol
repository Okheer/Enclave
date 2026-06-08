//SPDX-License-Identifier:MIT
pragma solidity ^0.8.33;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title IntentPool
/// @notice Receives EIP712 user intents, validate them and escrows the input tokens until SolvexSettlement releases or refunds them.
/// @dev This is the entrypoint for the user intent. Submitted intents moves thorugh state: PENDING ->Filled or PENDING -> EXPIRED(Refunded after deadline). 
   
contract IntentPool {
   using ECDSA     for bytes32;
   using SafeERC20 for IERC20;

  bytes32 private DOMAIN_SEPARATOR;
  address private immutable settlement;

  //typehashes 
  bytes32 private constant INTENT_TYPEHASH = keccak256("Intent(address user,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOutMin,uint256 deadline,uint256 nonce)"); 
  bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
  
  struct Intent{
    address user;
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 amountOutMin;
    uint256 deadline;
    uint256 nonce;
  }

  //Disgest
  struct EIP721Domain{
    string name;
    string version;
    uint256 chainId;
    address verifyingContract;
  }

  /// @dev Internal escrow record stored per intent_hash.
    struct EscrowRecord {
        address     user;
        address     token_in;
        uint256     amount_in;
        uint256      deadline;
        IntentState state;
    }

  enum IntentState{
    NONEXISTING,
    PENDING,
    FILLED,
    EXPIRED,
    CANCELLED
  }

  mapping(bytes32 => EscrowRecord) public escrows;
  mapping(address => mapping(uint64 => bool)) public usedNonces;
  
  event IntentSubmitted(
        bytes32 indexed intent_hash,
        address indexed user,
        address token_in,
        address token_out,
        uint256 amount_in,
        uint256 min_amount_out,
        uint256  deadline
    );
  event IntentFilled(bytes32 indexed intent_hash, address indexed winner_solver);

  error BadSignature();
  error DeadlineExpired(uint256 deadline, uint256 now_);
  error SameToken(address token);
  error ZeroAmount();
  error Unauthorized(address caller);
  error IntentNotPending(bytes32 intent_hash, IntentState state);
  error DeadlineNotReached(bytes32 intent_hash, uint256 deadline);

  constructor(address _settlement){
    DOMAIN_SEPARATOR = _hashDomain(EIP721Domain("IntentPool","1",block.chainid,address(this)));
    settlement = _settlement;
  }

  /// @notice Submit a signed intent and escrow token_in.
  /// @dev    Flow:
  ///           1. Validate fields (non-zero amounts, token_in ≠ token_out, deadline in range)
  ///           2. Recompute EIP-712 struct hash → domain-separated digest
  ///           3. Recover signer from _signature; must equal _intent.user
  ///           4. Mark nonce used
  ///           5. Pull token_in from user via transferFrom (must pre-approve)
  ///           6. Write EscrowRecord{PENDING}
  ///           7. Emit IntentSubmitted
  /// @param  _intent     The Intent struct exactly as signed by the user.
  /// @param  _signature  EIP-712 signature over the intent struct hash.
  ///  returns intent_hash keccak256 of the encoded intent (used as canonical ID).

  function submitIntent(
    Intent calldata _intent ,
    bytes calldata _signature
  ) external returns (bytes32 intentHash){

    require(block.timestamp <= _intent.deadline,DeadlineExpired(_intent.deadline,block.timestamp));
    require(_intent.tokenIn != _intent.tokenOut,SameToken(_intent.tokenIn));
    require(_intent.amountIn >= 0,ZeroAmount());
    
     intentHash= keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            _hashmessage(_intent)
        ));

      //Signer reocvery
      address signer = ECDSA.recover(intentHash, _signature);

      require(signer == _intent.user,BadSignature());

      //SafeToken transfer from 
      IERC20(_intent.tokenIn).safeTransferFrom(_intent.user, address(this), _intent.amountIn);
      emit IntentSubmitted(intentHash, _intent.user, _intent.tokenIn, _intent.tokenOut, _intent.amountIn, _intent.amountOutMin, _intent.deadline);

  }

  // ─────────────────────────────────────────────────────────────────────────
  // Settlement Interface (called by SolvexSettlement only)
  // ─────────────────────────────────────────────────────────────────────────

  /// @notice Mark an intent as filled and release escrowed tokens to settlement.
  /// @dev    Only callable by the SolvexSettlement contract (checked via
  ///         `msg.sender == settlement`). Settlement contract then handles
  ///         forwarding to the solver and distributing fees.
  ///         Reverts if intent is not in PENDING state.
  /// @param  _intent_hash    The canonical intent ID.
  /// @param  _winner_solver  Winning solver address (for event indexing).
  ///          token_in        ERC-20 address of the escrowed asset.
  ///         amount_in       Amount released to settlement.

  function markfilled(
    bytes32 _intent_hash,
    address _winner_solver) 
    external {
    
    require(msg.sender== settlement, Unauthorized(msg.sender));

    if (escrows[_intent_hash].state == IntentState.PENDING){

     escrows[_intent_hash].state = IntentState.FILLED;

     IERC20(escrows[_intent_hash].token_in).safeTransfer(settlement, escrows[_intent_hash].amount_in);

     emit IntentFilled(_intent_hash, _winner_solver);
    }    

  }

  /// @notice Reclaim escrowed tokens after intent deadline has passed.
  /// @dev    Callable by anyone (MEV bots can trigger on behalf of user) but
  ///         tokens always return to the original `intent.user`.
  ///         This prevents permanent fund lock if TEE/solver goes offline.
  /// @param  _intent_hash  The intent to refund.

  function refundIntent(bytes32 _intent_hash) external {
    require(block.timestamp > escrows[_intent_hash].deadline, DeadlineNotReached(_intent_hash,escrows[_intent_hash].deadline));

    if(escrows[_intent_hash].state == IntentState.PENDING){
      escrows[_intent_hash].state = IntentState.EXPIRED;

      IERC20(escrows[_intent_hash].token_in).safeTransfer(escrows[_intent_hash].user, escrows[_intent_hash].amount_in);
  }

  }
  ///////////////////////////////////////////////////////////////////////////////////
  ///////////////////////     private functions   ///////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////
  function _hashmessage(Intent calldata _intent) private pure returns (bytes32){
    return keccak256(abi.encode(INTENT_TYPEHASH,_intent.user,_intent.tokenIn,_intent.tokenOut,_intent.amountIn,_intent.amountOutMin,_intent.deadline,_intent.nonce));
  }

  function _hashDomain(EIP721Domain memory _domain) private pure returns (bytes32){
    return keccak256(abi.encode(DOMAIN_TYPEHASH,keccak256(bytes(_domain.name)),keccak256(bytes(_domain.version)),_domain.chainId,_domain.verifyingContract));
  }

}