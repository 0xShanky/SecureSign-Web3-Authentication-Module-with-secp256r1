// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../contracts/Secp256r1Verifier.sol";

/**
 * @title DeploySecp256r1Verifier
 * @dev Deployment script for Secp256r1Verifier contract
 */
contract DeploySecp256r1Verifier is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        Secp256r1Verifier verifier = new Secp256r1Verifier();

        vm.stopBroadcast();

        console.log("Secp256r1Verifier deployed at:", address(verifier));

        // Verify contract info
        (
            string memory name,
            string memory version,
            uint256 curveOrder
        ) = verifier.getContractInfo();
        console.log("Contract name:", name);
        console.log("Contract version:", version);
        console.log("Curve order:", curveOrder);
    }
}
