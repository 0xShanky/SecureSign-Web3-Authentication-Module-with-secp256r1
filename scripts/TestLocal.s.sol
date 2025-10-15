// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../contracts/Secp256r1Verifier.sol";

/**
 * @title TestLocal
 * @dev Script for testing the contract locally with Anvil
 */
contract TestLocal is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy contract
        Secp256r1Verifier verifier = new Secp256r1Verifier();
        
        vm.stopBroadcast();
        
        console.log("Secp256r1Verifier deployed at:", address(verifier));
        
        // Test basic functionality
        console.log("\n=== Testing Basic Functionality ===");
        
        // Test contract info
        (string memory name, string memory version, uint256 curveOrder) = verifier.getContractInfo();
        console.log("Contract name:", name);
        console.log("Contract version:", version);
        console.log("Curve order:", curveOrder);
        
        // Test user registration
        address testUser = address(0x1234);
        bytes memory testPublicKey = hex"04" 
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
        
        vm.prank(testUser);
        verifier.registerUser(testPublicKey);
        console.log("User registered:", testUser);
        
        // Test signature verification
        bytes32 messageHash = keccak256("Test message");
        bytes memory signature = hex"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                                 "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321";
        
        bool isValid = verifier.verifySignature(messageHash, signature, testPublicKey);
        console.log("Signature verification result:", isValid);
        
        // Test authentication
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, testUser));
        vm.prank(testUser);
        bool authSuccess = verifier.authenticate(messageHash, signature, nonce);
        console.log("Authentication result:", authSuccess);
        
        console.log("\n=== Local Testing Complete ===");
        console.log("Contract address:", address(verifier));
        console.log("You can now interact with the contract using cast or the frontend");
    }
}
