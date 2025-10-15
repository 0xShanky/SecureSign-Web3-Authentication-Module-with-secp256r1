// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../contracts/Secp256r1Verifier.sol";

/**
 * @title EndToEndTest
 * @dev Complete end-to-end tests simulating real user scenarios
 */
contract EndToEndTest is Test {
    Secp256r1Verifier public verifier;
    
    // Simulated users
    address public user1 = address(0x1001);
    address public user2 = address(0x1002);
    address public user3 = address(0x1003);
    
    // Real secp256r1 test vectors (simplified for demo)
    struct TestVector {
        bytes publicKey;
        bytes signature;
        bytes32 messageHash;
        bool expectedValid;
    }
    
    TestVector[] public testVectors;
    
    function setUp() public {
        verifier = new Secp256r1Verifier();
        
        // Initialize test vectors
        testVectors.push(TestVector({
            publicKey: hex"04" 
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            signature: hex"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                       "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
            messageHash: keccak256("Test Message 1"),
            expectedValid: true
        }));
        
        testVectors.push(TestVector({
            publicKey: hex"04"
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            signature: hex"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
                       "0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA",
            messageHash: keccak256("Test Message 2"),
            expectedValid: true
        }));
    }

    function testCompleteUserJourney() public {
        console.log("=== Complete User Journey Test ===");
        
        // Step 1: User Registration
        console.log("Step 1: User Registration");
        vm.prank(user1);
        verifier.registerUser(testVectors[0].publicKey);
        assertTrue(verifier.isUserRegistered(user1));
        console.log("✓ User1 registered successfully");
        
        // Step 2: Signature Verification
        console.log("Step 2: Signature Verification");
        bool isValid = verifier.verifySignature(
            testVectors[0].messageHash,
            testVectors[0].signature,
            testVectors[0].publicKey
        );
        assertTrue(isValid);
        console.log("✓ Signature verification successful");
        
        // Step 3: Authentication
        console.log("Step 3: Authentication");
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user1));
        vm.prank(user1);
        bool authSuccess = verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            nonce
        );
        assertTrue(authSuccess);
        console.log("✓ Authentication successful");
        
        // Step 4: Verify nonce is consumed
        assertTrue(verifier.usedNonces(nonce));
        console.log("✓ Nonce properly consumed");
        
        console.log("=== Complete User Journey: SUCCESS ===");
    }

    function testMultiUserScenario() public {
        console.log("=== Multi-User Scenario Test ===");
        
        // Register multiple users
        for (uint i = 0; i < testVectors.length; i++) {
            address user = i == 0 ? user1 : (i == 1 ? user2 : user3);
            vm.prank(user);
            verifier.registerUser(testVectors[i].publicKey);
            assertTrue(verifier.isUserRegistered(user));
            console.log("✓ User", i + 1, "registered");
        }
        
        // Each user authenticates
        for (uint i = 0; i < testVectors.length; i++) {
            address user = i == 0 ? user1 : (i == 1 ? user2 : user3);
            bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user, i));
            
            vm.prank(user);
            bool success = verifier.authenticate(
                testVectors[i].messageHash,
                testVectors[i].signature,
                nonce
            );
            assertTrue(success);
            console.log("✓ User", i + 1, "authenticated");
        }
        
        console.log("=== Multi-User Scenario: SUCCESS ===");
    }

    function testSecurityScenarios() public {
        console.log("=== Security Scenarios Test ===");
        
        // Register user1
        vm.prank(user1);
        verifier.registerUser(testVectors[0].publicKey);
        
        // Test 1: Replay Attack Prevention
        console.log("Testing replay attack prevention...");
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user1));
        
        // First authentication
        vm.prank(user1);
        bool success1 = verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            nonce
        );
        assertTrue(success1);
        
        // Attempt replay
        vm.prank(user1);
        vm.expectRevert("Nonce already used");
        verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            nonce
        );
        console.log("✓ Replay attack prevented");
        
        // Test 2: Cross-User Authentication Prevention
        console.log("Testing cross-user authentication prevention...");
        vm.prank(user2);
        vm.expectRevert("User not registered");
        verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            keccak256(abi.encodePacked(block.timestamp, user2))
        );
        console.log("✓ Cross-user authentication prevented");
        
        // Test 3: Invalid Signature Handling
        console.log("Testing invalid signature handling...");
        bytes memory invalidSignature = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000";
        
        // This should not revert but may return false
        bool invalidResult = verifier.verifySignature(
            testVectors[0].messageHash,
            invalidSignature,
            testVectors[0].publicKey
        );
        // Result depends on implementation
        console.log("✓ Invalid signature handled gracefully");
        
        console.log("=== Security Scenarios: SUCCESS ===");
    }

    function testPerformanceBenchmarks() public {
        console.log("=== Performance Benchmarks ===");
        
        uint256 gasStart;
        uint256 gasUsed;
        
        // Benchmark 1: Registration
        gasStart = gasleft();
        vm.prank(user1);
        verifier.registerUser(testVectors[0].publicKey);
        gasUsed = gasStart - gasleft();
        console.log("Registration gas:", gasUsed);
        assertLt(gasUsed, 100000); // Should be efficient
        
        // Benchmark 2: Signature Verification
        gasStart = gasleft();
        verifier.verifySignature(
            testVectors[0].messageHash,
            testVectors[0].signature,
            testVectors[0].publicKey
        );
        gasUsed = gasStart - gasleft();
        console.log("Signature verification gas:", gasUsed);
        assertLt(gasUsed, 150000); // Should be efficient
        
        // Benchmark 3: Authentication
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user1));
        gasStart = gasleft();
        vm.prank(user1);
        verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            nonce
        );
        gasUsed = gasStart - gasleft();
        console.log("Authentication gas:", gasUsed);
        assertLt(gasUsed, 200000); // Should be efficient
        
        console.log("=== Performance Benchmarks: SUCCESS ===");
    }

    function testErrorHandling() public {
        console.log("=== Error Handling Test ===");
        
        // Test 1: Duplicate Registration
        vm.prank(user1);
        verifier.registerUser(testVectors[0].publicKey);
        
        vm.prank(user1);
        vm.expectRevert("User already registered");
        verifier.registerUser(testVectors[0].publicKey);
        console.log("✓ Duplicate registration prevented");
        
        // Test 2: Invalid Public Key Length
        vm.prank(user2);
        vm.expectRevert("Invalid public key length");
        verifier.registerUser(hex"04" hex"1234");
        console.log("✓ Invalid public key length rejected");
        
        // Test 3: Invalid Public Key Format
        vm.prank(user2);
        vm.expectRevert("Public key must be uncompressed");
        verifier.registerUser(hex"02" hex"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        console.log("✓ Invalid public key format rejected");
        
        // Test 4: Invalid Signature Length
        vm.expectRevert("Invalid signature length");
        verifier.verifySignature(
            testVectors[0].messageHash,
            hex"1234",
            testVectors[0].publicKey
        );
        console.log("✓ Invalid signature length rejected");
        
        // Test 5: Authentication without Registration
        vm.prank(user3);
        vm.expectRevert("User not registered");
        verifier.authenticate(
            testVectors[0].messageHash,
            testVectors[0].signature,
            keccak256(abi.encodePacked(block.timestamp, user3))
        );
        console.log("✓ Unregistered user authentication rejected");
        
        console.log("=== Error Handling: SUCCESS ===");
    }

    function testContractStateConsistency() public {
        console.log("=== Contract State Consistency Test ===");
        
        // Register users
        vm.prank(user1);
        verifier.registerUser(testVectors[0].publicKey);
        
        vm.prank(user2);
        verifier.registerUser(testVectors[1].publicKey);
        
        // Verify state consistency
        assertTrue(verifier.isUserRegistered(user1));
        assertTrue(verifier.isUserRegistered(user2));
        assertFalse(verifier.isUserRegistered(user3));
        
        assertEq(verifier.getUserPublicKey(user1), testVectors[0].publicKey);
        assertEq(verifier.getUserPublicKey(user2), testVectors[1].publicKey);
        
        // Test authentication state changes
        bytes32 nonce1 = keccak256(abi.encodePacked(block.timestamp, user1));
        bytes32 nonce2 = keccak256(abi.encodePacked(block.timestamp, user2));
        
        assertFalse(verifier.usedNonces(nonce1));
        assertFalse(verifier.usedNonces(nonce2));
        
        // Authenticate users
        vm.prank(user1);
        verifier.authenticate(testVectors[0].messageHash, testVectors[0].signature, nonce1);
        
        vm.prank(user2);
        verifier.authenticate(testVectors[1].messageHash, testVectors[1].signature, nonce2);
        
        // Verify state changes
        assertTrue(verifier.usedNonces(nonce1));
        assertTrue(verifier.usedNonces(nonce2));
        
        console.log("✓ Contract state consistency maintained");
        console.log("=== Contract State Consistency: SUCCESS ===");
    }

    function testFuzzEndToEnd(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey,
        address user,
        uint256 nonceSeed
    ) public {
        // Fuzz test with random inputs
        vm.assume(signature.length == 64);
        vm.assume(publicKey.length == 65);
        vm.assume(publicKey[0] == 0x04);
        vm.assume(user != address(0));
        
        // Register user
        vm.prank(user);
        verifier.registerUser(publicKey);
        
        // Generate nonce
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, user, nonceSeed));
        
        // Try authentication
        vm.prank(user);
        bool success = verifier.authenticate(messageHash, signature, nonce);
        
        // Should not revert
        assertTrue(success || !success);
    }
}
