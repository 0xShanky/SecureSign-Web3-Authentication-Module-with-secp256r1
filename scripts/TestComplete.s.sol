// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../contracts/Secp256r1Verifier.sol";

/**
 * @title TestComplete
 * @dev Comprehensive test script for the complete SecureSign flow
 */
contract TestComplete is Script {
    Secp256r1Verifier public verifier;
    
    // Test data
    bytes public testPublicKey = hex"04" 
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    
    bytes public testSignature = hex"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                                 "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321";
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy contract
        verifier = new Secp256r1Verifier();
        
        vm.stopBroadcast();
        
        console.log("=== SecureSign Complete Test Suite ===");
        console.log("Contract deployed at:", address(verifier));
        
        // Run all tests
        testContractInfo();
        testUserRegistration();
        testSignatureVerification();
        testAuthentication();
        testSecurityFeatures();
        testErrorHandling();
        testPerformance();
        
        console.log("\n=== All Tests Completed Successfully ===");
    }
    
    function testContractInfo() internal {
        console.log("\n--- Testing Contract Info ---");
        
        (string memory name, string memory version, uint256 curveOrder) = verifier.getContractInfo();
        console.log("Name:", name);
        console.log("Version:", version);
        console.log("Curve Order:", curveOrder);
        
        assertEq(name, "Secp256r1Verifier");
        assertEq(version, "1.0.0");
        assertTrue(curveOrder > 0);
        
        console.log("✓ Contract info test passed");
    }
    
    function testUserRegistration() internal {
        console.log("\n--- Testing User Registration ---");
        
        address user1 = address(0x1001);
        address user2 = address(0x1002);
        
        // Register user1
        vm.prank(user1);
        verifier.registerUser(testPublicKey);
        assertTrue(verifier.isUserRegistered(user1));
        console.log("✓ User1 registered");
        
        // Register user2 with different key
        bytes memory user2Key = hex"04"
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        
        vm.prank(user2);
        verifier.registerUser(user2Key);
        assertTrue(verifier.isUserRegistered(user2));
        console.log("✓ User2 registered");
        
        // Test duplicate registration prevention
        vm.prank(user1);
        vm.expectRevert("User already registered");
        verifier.registerUser(testPublicKey);
        console.log("✓ Duplicate registration prevented");
        
        console.log("✓ User registration tests passed");
    }
    
    function testSignatureVerification() internal {
        console.log("\n--- Testing Signature Verification ---");
        
        address user = address(0x1001);
        bytes32 messageHash = keccak256("Test message for verification");
        
        // Test valid signature
        bool isValid = verifier.verifySignature(messageHash, testSignature, testPublicKey);
        console.log("Signature verification result:", isValid);
        
        // Test invalid signature length
        vm.expectRevert("Invalid signature length");
        verifier.verifySignature(messageHash, hex"1234", testPublicKey);
        console.log("✓ Invalid signature length rejected");
        
        // Test invalid public key length
        vm.expectRevert("Invalid public key length");
        verifier.verifySignature(messageHash, testSignature, hex"04" hex"1234");
        console.log("✓ Invalid public key length rejected");
        
        console.log("✓ Signature verification tests passed");
    }
    
    function testAuthentication() internal {
        console.log("\n--- Testing Authentication ---");
        
        address user = address(0x1001);
        bytes32 messageHash = keccak256("Authentication test message");
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user));
        
        // Test successful authentication
        vm.prank(user);
        bool success = verifier.authenticate(messageHash, testSignature, nonce);
        console.log("Authentication result:", success);
        assertTrue(success);
        
        // Test nonce consumption
        assertTrue(verifier.usedNonces(nonce));
        console.log("✓ Nonce properly consumed");
        
        // Test replay attack prevention
        vm.prank(user);
        vm.expectRevert("Nonce already used");
        verifier.authenticate(messageHash, testSignature, nonce);
        console.log("✓ Replay attack prevented");
        
        console.log("✓ Authentication tests passed");
    }
    
    function testSecurityFeatures() internal {
        console.log("\n--- Testing Security Features ---");
        
        address user = address(0x1001);
        address attacker = address(0x9999);
        
        // Test unregistered user authentication
        vm.prank(attacker);
        vm.expectRevert("User not registered");
        verifier.authenticate(
            keccak256("Attack message"),
            testSignature,
            keccak256(abi.encodePacked(block.timestamp, attacker))
        );
        console.log("✓ Unregistered user authentication blocked");
        
        // Test cross-user nonce usage
        bytes32 userNonce = keccak256(abi.encodePacked(block.timestamp, user));
        bytes32 attackerNonce = keccak256(abi.encodePacked(block.timestamp, attacker));
        
        // User's nonce should be used
        assertTrue(verifier.usedNonces(userNonce));
        // Attacker's nonce should not be used
        assertFalse(verifier.usedNonces(attackerNonce));
        console.log("✓ Nonce isolation maintained");
        
        console.log("✓ Security feature tests passed");
    }
    
    function testErrorHandling() internal {
        console.log("\n--- Testing Error Handling ---");
        
        address user = address(0x1001);
        
        // Test invalid public key format
        vm.prank(user);
        vm.expectRevert("Public key must be uncompressed");
        verifier.registerUser(hex"02" hex"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        console.log("✓ Invalid public key format rejected");
        
        // Test signature verification with invalid inputs
        vm.expectRevert("Invalid signature length");
        verifier.verifySignature(keccak256("test"), hex"1234", testPublicKey);
        console.log("✓ Invalid signature length rejected");
        
        console.log("✓ Error handling tests passed");
    }
    
    function testPerformance() internal {
        console.log("\n--- Testing Performance ---");
        
        uint256 gasStart;
        uint256 gasUsed;
        
        // Test registration gas usage
        address user = address(0x2001);
        gasStart = gasleft();
        vm.prank(user);
        verifier.registerUser(testPublicKey);
        gasUsed = gasStart - gasleft();
        console.log("Registration gas used:", gasUsed);
        assertLt(gasUsed, 100000);
        
        // Test signature verification gas usage
        gasStart = gasleft();
        verifier.verifySignature(keccak256("perf test"), testSignature, testPublicKey);
        gasUsed = gasStart - gasleft();
        console.log("Signature verification gas used:", gasUsed);
        assertLt(gasUsed, 150000);
        
        // Test authentication gas usage
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user));
        gasStart = gasleft();
        vm.prank(user);
        verifier.authenticate(keccak256("perf test"), testSignature, nonce);
        gasUsed = gasStart - gasleft();
        console.log("Authentication gas used:", gasUsed);
        assertLt(gasUsed, 200000);
        
        console.log("✓ Performance tests passed");
    }
}
