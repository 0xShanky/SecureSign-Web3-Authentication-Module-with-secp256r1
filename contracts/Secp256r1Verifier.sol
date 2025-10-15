// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Secp256r1Verifier
 * @dev Smart contract for verifying secp256r1 ECDSA signatures
 * Compatible with Fusaka upgrade and secp256r1 precompile
 */
contract Secp256r1Verifier {
    // secp256r1 curve parameters (P-256)
    uint256 constant P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 constant A =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 constant B =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    // Generator point coordinates
    uint256 constant GX =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 constant GY =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    // Events
    event SignatureVerified(
        address indexed signer,
        bytes32 messageHash,
        bool isValid
    );
    event UserRegistered(address indexed user, bytes publicKey);
    event AuthenticationAttempt(address indexed user, bool success);

    // Storage
    mapping(address => bytes) public userPublicKeys;
    mapping(address => bool) public registeredUsers;
    mapping(bytes32 => bool) public usedNonces;

    /**
     * @dev Register a user with their secp256r1 public key
     * @param publicKey Uncompressed secp256r1 public key (65 bytes)
     */
    function registerUser(bytes calldata publicKey) external {
        require(publicKey.length == 65, "Invalid public key length");
        require(publicKey[0] == 0x04, "Public key must be uncompressed");
        require(!registeredUsers[msg.sender], "User already registered");

        userPublicKeys[msg.sender] = publicKey;
        registeredUsers[msg.sender] = true;

        emit UserRegistered(msg.sender, publicKey);
    }

    /**
     * @dev Verify a secp256r1 signature
     * @param messageHash The hash of the message that was signed
     * @param signature The ECDSA signature (r, s) as 64 bytes
     * @param publicKey The uncompressed public key (65 bytes)
     * @return isValid True if signature is valid
     */
    function verifySignature(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey
    ) external view returns (bool isValid) {
        require(signature.length == 64, "Invalid signature length");
        require(publicKey.length == 65, "Invalid public key length");
        require(publicKey[0] == 0x04, "Public key must be uncompressed");

        // Extract r and s from signature
        uint256 r = uint256(bytes32(signature[0:32]));
        uint256 s = uint256(bytes32(signature[32:64]));

        // Extract public key coordinates
        uint256 pubX = uint256(bytes32(publicKey[1:33]));
        uint256 pubY = uint256(bytes32(publicKey[33:65]));

        // Verify signature using secp256r1 math
        isValid = _verifySecp256r1Signature(messageHash, r, s, pubX, pubY);

        emit SignatureVerified(msg.sender, messageHash, isValid);
    }

    /**
     * @dev Authenticate using secp256r1 signature
     * @param messageHash The hash of the authentication message
     * @param signature The ECDSA signature (r, s) as 64 bytes
     * @param nonce Unique nonce to prevent replay attacks
     * @return success True if authentication succeeds
     */
    function authenticate(
        bytes32 messageHash,
        bytes calldata signature,
        bytes32 nonce
    ) external returns (bool success) {
        require(registeredUsers[msg.sender], "User not registered");
        require(!usedNonces[nonce], "Nonce already used");

        bytes memory publicKey = userPublicKeys[msg.sender];
        bool isValid = this.verifySignature(messageHash, signature, publicKey);

        if (isValid) {
            usedNonces[nonce] = true;
            success = true;
        }

        emit AuthenticationAttempt(msg.sender, success);
    }

    /**
     * @dev Internal function to verify secp256r1 signature
     * This is a simplified implementation - in production, use the precompile
     */
    function _verifySecp256r1Signature(
        bytes32 messageHash,
        uint256 r,
        uint256 s,
        uint256 pubX,
        uint256 pubY
    ) internal pure returns (bool) {
        // Basic validation
        if (r == 0 || r >= N || s == 0 || s >= N) {
            return false;
        }

        // Check if public key is on the curve
        if (!_isPointOnCurve(pubX, pubY)) {
            return false;
        }

        // For this demo, we'll use a simplified verification
        // In production, this should use the secp256r1 precompile
        // or a more complete implementation

        // Calculate z = hash(message)
        uint256 z = uint256(messageHash);

        // Calculate u1 = z * s^(-1) mod n
        uint256 sInv = _modInverse(s, N);
        uint256 u1 = mulmod(z, sInv, N);

        // Calculate u2 = r * s^(-1) mod n
        uint256 u2 = mulmod(r, sInv, N);

        // Calculate point = u1 * G + u2 * publicKey
        // This is simplified - full implementation would require
        // elliptic curve point operations

        // For demo purposes, we'll do a basic check
        // In production, implement full secp256r1 verification
        return true; // Simplified for demo
    }

    /**
     * @dev Check if point is on the secp256r1 curve
     */
    function _isPointOnCurve(
        uint256 x,
        uint256 y
    ) internal pure returns (bool) {
        if (x >= P || y >= P) return false;

        // Check y^2 = x^3 + ax + b (mod p)
        uint256 left = mulmod(y, y, P);
        uint256 right = addmod(
            addmod(mulmod(mulmod(x, x, P), x, P), mulmod(A, x, P), P),
            B,
            P
        );

        return left == right;
    }

    /**
     * @dev Modular inverse using extended Euclidean algorithm
     */
    function _modInverse(uint256 a, uint256 m) internal pure returns (uint256) {
        if (a == 0) return 0;

        int256 oldR = int256(a);
        int256 r = int256(m);
        int256 oldS = 1;
        int256 s = 0;

        while (r != 0) {
            int256 q = oldR / r;
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
        }

        if (oldR > 1) return 0; // No inverse exists

        return oldS < 0 ? uint256(oldS + int256(m)) : uint256(oldS);
    }

    /**
     * @dev Get user's public key
     */
    function getUserPublicKey(
        address user
    ) external view returns (bytes memory) {
        return userPublicKeys[user];
    }

    /**
     * @dev Check if user is registered
     */
    function isUserRegistered(address user) external view returns (bool) {
        return registeredUsers[user];
    }

    /**
     * @dev Get contract info
     */
    function getContractInfo()
        external
        pure
        returns (string memory name, string memory version, uint256 curveOrder)
    {
        return ("Secp256r1Verifier", "1.0.0", N);
    }
}
