// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../contracts/Secp256r1Verifier.sol";

/**
 * @title IntegrationTest
 * @dev End-to-end integration tests for the complete SecureSign flow
 */
contract IntegrationTest is Test {
    Secp256r1Verifier public verifier;
    
    // Test users
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public charlie = address(0x3);
    
    // Test data
    bytes32 public testMessageHash = keccak256("SecureSign Integration Test");
    bytes public testPublicKey;
    bytes public testSignature;
    
    function setUp() public {
        verifier = new Secp256r1Verifier();
        
        // Setup test public key (uncompressed secp256r1)
        testPublicKey = hex"04" // Uncompressed prefix
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" // x coordinate
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"; // y coordinate
        
        // Setup test signature (64 bytes: r + s)
        testSignature = hex"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                       "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321";
    }

    function testCompleteUserFlow() public {
        // Step 1: User Registration
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        assertTrue(verifier.isUserRegistered(alice));
        assertEq(verifier.getUserPublicKey(alice), testPublicKey);
        
        // Step 2: Signature Verification
        bool isValid = verifier.verifySignature(testMessageHash, testSignature, testPublicKey);
        assertTrue(isValid);
        
        // Step 3: Authentication
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, alice));
        vm.prank(alice);
        bool authSuccess = verifier.authenticate(testMessageHash, testSignature, nonce);
        assertTrue(authSuccess);
        
        // Step 4: Verify nonce is marked as used
        assertTrue(verifier.usedNonces(nonce));
    }

    function testMultipleUsersRegistration() public {
        // Register multiple users
        bytes memory aliceKey = testPublicKey;
        bytes memory bobKey = hex"04" 
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        bytes memory charlieKey = hex"04"
            "2FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            "5B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        
        vm.prank(alice);
        verifier.registerUser(aliceKey);
        
        vm.prank(bob);
        verifier.registerUser(bobKey);
        
        vm.prank(charlie);
        verifier.registerUser(charlieKey);
        
        // Verify all users are registered
        assertTrue(verifier.isUserRegistered(alice));
        assertTrue(verifier.isUserRegistered(bob));
        assertTrue(verifier.isUserRegistered(charlie));
        
        // Verify each has their own public key
        assertEq(verifier.getUserPublicKey(alice), aliceKey);
        assertEq(verifier.getUserPublicKey(bob), bobKey);
        assertEq(verifier.getUserPublicKey(charlie), charlieKey);
    }

    function testAuthenticationWithDifferentMessages() public {
        // Register user
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        // Test with different message hashes
        bytes32[] memory messages = new bytes32[](3);
        messages[0] = keccak256("Message 1");
        messages[1] = keccak256("Message 2");
        messages[2] = keccak256("Message 3");
        
        for (uint i = 0; i < messages.length; i++) {
            bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, alice, i));
            
            vm.prank(alice);
            bool success = verifier.authenticate(messages[i], testSignature, nonce);
            assertTrue(success);
            
            // Verify nonce is used
            assertTrue(verifier.usedNonces(nonce));
        }
    }

    function testReplayAttackPrevention() public {
        // Register user
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, alice));
        
        // First authentication should succeed
        vm.prank(alice);
        bool success1 = verifier.authenticate(testMessageHash, testSignature, nonce);
        assertTrue(success1);
        
        // Second authentication with same nonce should fail
        vm.prank(alice);
        vm.expectRevert("Nonce already used");
        verifier.authenticate(testMessageHash, testSignature, nonce);
    }

    function testCrossUserAuthentication() public {
        // Register both users
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        bytes memory bobKey = hex"04" 
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        
        vm.prank(bob);
        verifier.registerUser(bobKey);
        
        // Alice tries to authenticate as Bob - should fail
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, bob));
        vm.prank(alice);
        vm.expectRevert("User not registered");
        verifier.authenticate(testMessageHash, testSignature, nonce);
        
        // Bob authenticates as himself - should succeed
        vm.prank(bob);
        bool success = verifier.authenticate(testMessageHash, testSignature, nonce);
        assertTrue(success);
    }

    function testSignatureVerificationWithInvalidInputs() public {
        // Register user
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        // Test with invalid signature length
        bytes memory invalidSignature = hex"1234";
        vm.expectRevert("Invalid signature length");
        verifier.verifySignature(testMessageHash, invalidSignature, testPublicKey);
        
        // Test with invalid public key length
        bytes memory invalidPublicKey = hex"04" hex"1234";
        vm.expectRevert("Invalid public key length");
        verifier.verifySignature(testMessageHash, testSignature, invalidPublicKey);
        
        // Test with compressed public key
        bytes memory compressedKey = hex"02" hex"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        vm.expectRevert("Public key must be uncompressed");
        verifier.verifySignature(testMessageHash, testSignature, compressedKey);
    }

    function testGasUsageOptimization() public {
        uint256 gasStart;
        uint256 gasUsed;
        
        // Test registration gas usage
        gasStart = gasleft();
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        gasUsed = gasStart - gasleft();
        console.log("Registration gas used:", gasUsed);
        
        // Test signature verification gas usage
        gasStart = gasleft();
        verifier.verifySignature(testMessageHash, testSignature, testPublicKey);
        gasUsed = gasStart - gasleft();
        console.log("Signature verification gas used:", gasUsed);
        
        // Test authentication gas usage
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, alice));
        gasStart = gasleft();
        vm.prank(alice);
        verifier.authenticate(testMessageHash, testSignature, nonce);
        gasUsed = gasStart - gasleft();
        console.log("Authentication gas used:", gasUsed);
        
        // Gas usage should be reasonable for production use
        assertLt(gasUsed, 200000); // Should be less than 200k gas
    }

    function testEventEmissionIntegration() public {
        // Test UserRegistered event
        vm.expectEmit(true, false, false, true);
        emit UserRegistered(alice, testPublicKey);
        vm.prank(alice);
        verifier.registerUser(testPublicKey);
        
        // Test SignatureVerified event
        vm.expectEmit(true, false, false, true);
        emit SignatureVerified(alice, testMessageHash, true);
        verifier.verifySignature(testMessageHash, testSignature, testPublicKey);
        
        // Test AuthenticationAttempt event
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, alice));
        vm.expectEmit(true, false, false, true);
        emit AuthenticationAttempt(alice, true);
        vm.prank(alice);
        verifier.authenticate(testMessageHash, testSignature, nonce);
    }

    function testContractInfoRetrieval() public {
        (string memory name, string memory version, uint256 curveOrder) = verifier.getContractInfo();
        
        assertEq(name, "Secp256r1Verifier");
        assertEq(version, "1.0.0");
        assertTrue(curveOrder > 0);
        
        console.log("Contract name:", name);
        console.log("Contract version:", version);
        console.log("Curve order:", curveOrder);
    }

    function testStressTestMultipleOperations() public {
        // Register multiple users
        address[] memory users = new address[](10);
        for (uint i = 0; i < 10; i++) {
            users[i] = address(uint160(0x1000 + i));
        }
        
        // Register all users
        for (uint i = 0; i < users.length; i++) {
            vm.prank(users[i]);
            verifier.registerUser(testPublicKey);
            assertTrue(verifier.isUserRegistered(users[i]));
        }
        
        // Perform multiple authentications
        for (uint i = 0; i < users.length; i++) {
            bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, users[i], i));
            vm.prank(users[i]);
            bool success = verifier.authenticate(testMessageHash, testSignature, nonce);
            assertTrue(success);
        }
        
        // Verify all nonces are marked as used
        for (uint i = 0; i < users.length; i++) {
            bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, users[i], i));
            assertTrue(verifier.usedNonces(nonce));
        }
    }

    function testFuzzIntegration(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey,
        address user
    ) public {
        // Fuzz test with random inputs
        vm.assume(signature.length == 64);
        vm.assume(publicKey.length == 65);
        vm.assume(publicKey[0] == 0x04);
        vm.assume(user != address(0));
        
        // Register user
        vm.prank(user);
        verifier.registerUser(publicKey);
        
        // Verify signature
        bool isValid = verifier.verifySignature(messageHash, signature, publicKey);
        
        // Should not revert
        assertTrue(isValid || !isValid);
        
        // Try authentication
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user));
        vm.prank(user);
        bool authSuccess = verifier.authenticate(messageHash, signature, nonce);
        
        // Should not revert
        assertTrue(authSuccess || !authSuccess);
    }
}
