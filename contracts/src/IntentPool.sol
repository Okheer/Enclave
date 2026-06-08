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

  error BadSignature();
  error DeadlineExpired(uint256 deadline, uint256 now_);
  error SameToken(address token);
  error ZeroAmount();

  constructor(address _settlement){
    DOMAIN_SEPARATOR = _hashDomain(EIP721Domain("IntentPool","1",block.chainid,address(this)));
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


  }

  function markfilled(
    bytes32 _intentHash,
    address _winner_solver) 
    external {
    
  }

  function refundIntent(bytes32 _intentHash) external {
    
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