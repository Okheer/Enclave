//SPDX-License-Identifier:MIT
pragma solidity ^0.8.33;

import {Test, console} from "forge-std/Test.sol";
import {IntentPool} from "../../src/IntentPool.sol";
import {MockToken} from "../SolvexSettlement.t.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract IntentPoolTest is Test {
    IntentPool public pool;
    MockToken public tokenIn;
    MockToken public tokenOut;
    address public settlement = address(0x123);
    address public user = address(0x456);
    uint256 public userPrivKey = 0xabc;

    function setUp() external {
        user = vm.addr(userPrivKey);
        pool = new IntentPool(settlement);
        tokenIn = new MockToken();
        tokenOut = new MockToken();
        tokenIn.mint(user, 1000e18);
        vm.prank(user);
        tokenIn.approve(address(pool), type(uint256).max);
    }

    function test_SubmitIntent_Success() public {
        IntentPool.Intent memory intent = IntentPool.Intent({
            user: user,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            amountIn: 100e18,
            amountOutMin: 90e18,
            deadline: block.timestamp + 1 hours,
            nonce: 1
        });

        bytes32 digest = _getDigest(intent);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        bytes32 intentHash = pool.submitIntent(intent, signature);

        assertEq(intentHash, digest);
        assertEq(tokenIn.balanceOf(address(pool)), 100e18);
        
        IntentPool.EscrowRecord memory rec = pool.getEscrowRecord(intentHash);
        assertEq(rec.user, user);
        assertEq(uint256(rec.state), 1); // PENDING
    }

    function test_MarkFilled_Unauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized(address)", address(this)));
        pool.markFilled(bytes32(0), address(0));
    }

    function _getDigest(IntentPool.Intent memory _intent) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("IntentPool")),
            keccak256(bytes("1")),
            block.chainid,
            address(pool)
        ));
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Intent(address user,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOutMin,uint256 deadline,uint256 nonce)"),
            _intent.user,
            _intent.tokenIn,
            _intent.tokenOut,
            _intent.amountIn,
            _intent.amountOutMin,
            _intent.deadline,
            _intent.nonce
        ));
        
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}