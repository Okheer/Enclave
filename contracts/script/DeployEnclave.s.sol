// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {SolvexSettlement} from "../src/SolvexSettlement.sol";
import {SolverRegistry} from "../src/SolverRegistry.sol";
import {IntentPool} from "../src/IntentPool.sol";

contract DeployEnclave is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address feeRecipient = vm.envAddress("FEE_RECIPIENT");
        address stylusVerifier = vm.envAddress("STYLUS_VERIFIER_ADDR");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Registry
        SolverRegistry registry = new SolverRegistry(feeRecipient);

        // 2. Pre-calculate addresses to break the circular dependency
        // Current nonce = N. Pool will be N, Settlement will be N + 1.
        uint256 nonce = vm.getNonce(deployer);
        address poolAddr = vm.computeCreateAddress(deployer, nonce);
        address settlementAddr = vm.computeCreateAddress(deployer, nonce + 1);

        // 3. Deploy IntentPool (points to future Settlement)
        IntentPool pool = new IntentPool(settlementAddr);
        require(address(pool) == poolAddr, "Address mismatch for Pool");

        // 4. Deploy Settlement (points to actual Pool)
        SolvexSettlement settlement = new SolvexSettlement(
            stylusVerifier,
            address(registry),
            address(pool),
            feeRecipient
        );
        require(address(settlement) == settlementAddr, "Address mismatch for Settlement");

        // 5. Post-deployment initialization
        registry.grantRole(registry.SETTLER_ROLE(), address(settlement));

        vm.stopBroadcast();
    }
}
