/**
 * secp256r1 Mathematical Module
 * 
 * Pure software implementation of secp256r1 elliptic curve cryptography
 * including finite field arithmetic, point operations, and ECDSA signing/verification
 */

class Secp256r1 {
    constructor() {
        // secp256r1 curve parameters (P-256)
        this.p = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'); // Prime field
        this.a = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'); // Curve parameter a
        this.b = BigInt('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'); // Curve parameter b
        this.n = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'); // Order of the curve
        this.gx = BigInt('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'); // Generator point x
        this.gy = BigInt('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'); // Generator point y

        this.generator = { x: this.gx, y: this.gy };
    }

    /**
     * Finite field modular arithmetic
     */
    mod(a, p = this.p) {
        return ((a % p) + p) % p;
    }

    /**
     * Modular exponentiation
     */
    modPow(base, exponent, modulus = this.p) {
        let result = BigInt(1);
        base = this.mod(base, modulus);

        while (exponent > 0) {
            if (exponent & BigInt(1)) {
                result = this.mod(result * base, modulus);
            }
            exponent >>= BigInt(1);
            base = this.mod(base * base, modulus);
        }
        return result;
    }

    /**
     * Modular inverse using extended Euclidean algorithm
     */
    modInverse(a, p = this.p) {
        if (a === BigInt(0)) throw new Error('Cannot compute inverse of zero');
        return this.modPow(a, p - BigInt(2), p);
    }

    /**
     * Point addition on elliptic curve
     */
    pointAdd(p1, p2) {
        if (p1 === null) return p2;
        if (p2 === null) return p1;

        const { x: x1, y: y1 } = p1;
        const { x: x2, y: y2 } = p2;

        if (x1 === x2) {
            if (y1 === y2) {
                return this.pointDouble(p1);
            } else {
                return null; // Point at infinity
            }
        }

        const deltaX = this.mod(x2 - x1);
        const deltaY = this.mod(y2 - y1);
        const slope = this.mod(deltaY * this.modInverse(deltaX));

        const x3 = this.mod(slope * slope - x1 - x2);
        const y3 = this.mod(slope * (x1 - x3) - y1);

        return { x: x3, y: y3 };
    }

    /**
     * Point doubling on elliptic curve
     */
    pointDouble(p) {
        if (p === null) return null;

        const { x, y } = p;
        if (y === BigInt(0)) return null; // Point at infinity

        const slope = this.mod((BigInt(3) * x * x + this.a) * this.modInverse(BigInt(2) * y));
        const x3 = this.mod(slope * slope - BigInt(2) * x);
        const y3 = this.mod(slope * (x - x3) - y);

        return { x: x3, y: y3 };
    }

    /**
     * Scalar multiplication: k * P
     */
    scalarMultiply(k, point) {
        if (k === BigInt(0) || point === null) return null;

        let result = null;
        let addend = point;

        while (k > 0) {
            if (k & BigInt(1)) {
                result = this.pointAdd(result, addend);
            }
            addend = this.pointDouble(addend);
            k >>= BigInt(1);
        }

        return result;
    }

    /**
     * Generate a random private key
     */
    generatePrivateKey() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        let key = BigInt('0x' + Array.from(array).map(b => b.toString(16).padStart(2, '0')).join(''));

        // Ensure key is in valid range [1, n-1]
        while (key === BigInt(0) || key >= this.n) {
            crypto.getRandomValues(array);
            key = BigInt('0x' + Array.from(array).map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        return key;
    }

    /**
     * Derive public key from private key
     */
    derivePublicKey(privateKey) {
        return this.scalarMultiply(privateKey, this.generator);
    }

    /**
     * Convert point to uncompressed format (65 bytes)
     */
    pointToUncompressed(point) {
        if (point === null) throw new Error('Cannot convert null point');

        const xBytes = this.bigIntToBytes(point.x, 32);
        const yBytes = this.bigIntToBytes(point.y, 32);
        return new Uint8Array([0x04, ...xBytes, ...yBytes]);
    }

    /**
     * Convert uncompressed point to point object
     */
    uncompressedToPoint(bytes) {
        if (bytes.length !== 65 || bytes[0] !== 0x04) {
            throw new Error('Invalid uncompressed point format');
        }

        const x = this.bytesToBigInt(bytes.slice(1, 33));
        const y = this.bytesToBigInt(bytes.slice(33, 65));

        return { x, y };
    }

    /**
     * Hash function (SHA-256)
     */
    async hash(data) {
        const buffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(buffer);
    }

    /**
     * ECDSA signature generation
     */
    async sign(privateKey, message) {
        const messageHash = await this.hash(message);
        const z = this.bytesToBigInt(messageHash);

        let r, s;
        let k;

        do {
            // Generate random k
            const kArray = new Uint8Array(32);
            crypto.getRandomValues(kArray);
            k = this.bytesToBigInt(kArray);

            // Ensure k is in valid range
            while (k === BigInt(0) || k >= this.n) {
                crypto.getRandomValues(kArray);
                k = this.bytesToBigInt(kArray);
            }

            // Calculate r = (k * G).x mod n
            const kG = this.scalarMultiply(k, this.generator);
            r = this.mod(kG.x, this.n);

            if (r === BigInt(0)) continue;

            // Calculate s = k^(-1) * (z + r * privateKey) mod n
            const kInv = this.modInverse(k, this.n);
            s = this.mod(kInv * (z + r * privateKey), this.n);

        } while (s === BigInt(0));

        return {
            r: this.bigIntToBytes(r, 32),
            s: this.bigIntToBytes(s, 32)
        };
    }

    /**
     * ECDSA signature verification
     */
    async verify(publicKey, message, signature) {
        const { r, s } = signature;
        const rBig = this.bytesToBigInt(r);
        const sBig = this.bytesToBigInt(s);

        // Check signature components are in valid range
        if (rBig === BigInt(0) || rBig >= this.n || sBig === BigInt(0) || sBig >= this.n) {
            return false;
        }

        const messageHash = await this.hash(message);
        const z = this.bytesToBigInt(messageHash);

        // Calculate u1 = z * s^(-1) mod n
        const sInv = this.modInverse(sBig, this.n);
        const u1 = this.mod(z * sInv, this.n);

        // Calculate u2 = r * s^(-1) mod n
        const u2 = this.mod(rBig * sInv, this.n);

        // Calculate point = u1 * G + u2 * publicKey
        const u1G = this.scalarMultiply(u1, this.generator);
        const u2Pub = this.scalarMultiply(u2, publicKey);
        const point = this.pointAdd(u1G, u2Pub);

        if (point === null) return false;

        // Check if r == point.x mod n
        return this.mod(point.x, this.n) === rBig;
    }

    /**
     * Utility: Convert BigInt to bytes
     */
    bigIntToBytes(bigInt, length = 32) {
        const hex = bigInt.toString(16).padStart(length * 2, '0');
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    /**
     * Utility: Convert bytes to BigInt
     */
    bytesToBigInt(bytes) {
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        return BigInt('0x' + hex);
    }

    /**
     * Validate if point is on the curve
     */
    isPointOnCurve(point) {
        if (point === null) return false;

        const { x, y } = point;
        const left = this.mod(y * y);
        const right = this.mod(x * x * x + this.a * x + this.b);

        return left === right;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Secp256r1;
} else if (typeof window !== 'undefined') {
    window.Secp256r1 = Secp256r1;
}
