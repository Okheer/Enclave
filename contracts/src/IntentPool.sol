//SPDX-License-Identifier:MIT
pragma solidity ^0.8.20;

/// @title IntentPool
/// @notice Receives EIP712 user intents, validate them and escrows the input tokens until SolvexSettlement releases or refunds them.
/// @dev This is the entrypoint for the user intent. Submitted intents moves thorugh state: PENDING ->Filled or PENDING -> EXPIRED(Refunded after deadline). 
   
contract IntentPool{
  
  struct Intent{
    address user;
    address tokenIn;
    address tokenout;
    uint256 amountIn;
    uint256 amountOutMin;
    uint256 deadline;
    uint256 nonce;
  }


  function submitIntent(
    Intent calldata _intent ,
    bytes calldata _signature
  ) external returns (bytes32 intentHash){
    
  }

  function markfilled(
    bytes32 _intentHash,
    address _winner_solver) 
    external {
    
  }

  function refundIntent(bytes32 _intentHash) external {
    
  }
}