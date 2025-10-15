/**
 * Software-Based Key Manager
 * 
 * Handles secp256r1 key generation, encryption with AES-GCM,
 * and secure storage in browser keystore
 */

class KeyManager {
    constructor() {
        this.secp256r1 = new Secp256r1();
        this.storageKey = 'securesign_keystore';
    }

    /**
     * Generate a new secp256r1 key pair
     */
    async generateKeyPair() {
        const privateKey = this.secp256r1.generatePrivateKey();
        const publicKey = this.secp256r1.derivePublicKey(privateKey);

        return {
            privateKey: this.secp256r1.bigIntToBytes(privateKey, 32),
            publicKey: this.secp256r1.pointToUncompressed(publicKey),
            privateKeyBigInt: privateKey,
            publicKeyPoint: publicKey
        };
    }

    /**
     * Derive encryption key from password using PBKDF2
     */
    async deriveKeyFromPassword(password, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt private key with password
     */
    async encryptPrivateKey(privateKey, password) {
        // Generate random salt and IV
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Derive key from password
        const key = await this.deriveKeyFromPassword(password, salt);

        // Encrypt the private key
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            privateKey
        );

        return {
            encrypted: new Uint8Array(encrypted),
            salt: salt,
            iv: iv
        };
    }

    /**
     * Decrypt private key with password
     */
    async decryptPrivateKey(encryptedData, password) {
        const { encrypted, salt, iv } = encryptedData;

        // Derive key from password
        const key = await this.deriveKeyFromPassword(password, salt);

        // Decrypt the private key
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encrypted
        );

        return new Uint8Array(decrypted);
    }

    /**
     * Store encrypted key in browser storage
     */
    async storeKey(publicKey, encryptedPrivateKey, metadata = {}) {
        const keystoreEntry = {
            publicKey: Array.from(publicKey),
            encryptedPrivateKey: {
                encrypted: Array.from(encryptedPrivateKey.encrypted),
                salt: Array.from(encryptedPrivateKey.salt),
                iv: Array.from(encryptedPrivateKey.iv)
            },
            metadata: {
                ...metadata,
                createdAt: new Date().toISOString(),
                version: '1.0'
            }
        };

        // Get existing keystore
        const existingKeystore = this.getKeystore();
        existingKeystore[this.publicKeyToAddress(publicKey)] = keystoreEntry;

        // Store updated keystore
        localStorage.setItem(this.storageKey, JSON.stringify(existingKeystore));

        return keystoreEntry;
    }

    /**
     * Retrieve encrypted key from storage
     */
    getStoredKey(address) {
        const keystore = this.getKeystore();
        return keystore[address] || null;
    }

    /**
     * Get all stored key addresses
     */
    getStoredAddresses() {
        const keystore = this.getKeystore();
        return Object.keys(keystore);
    }

    /**
     * Load and decrypt private key
     */
    async loadPrivateKey(address, password) {
        const storedKey = this.getStoredKey(address);
        if (!storedKey) {
            throw new Error('No key found for address');
        }

        const encryptedData = {
            encrypted: new Uint8Array(storedKey.encryptedPrivateKey.encrypted),
            salt: new Uint8Array(storedKey.encryptedPrivateKey.salt),
            iv: new Uint8Array(storedKey.encryptedPrivateKey.iv)
        };

        const privateKey = await this.decryptPrivateKey(encryptedData, password);
        return privateKey;
    }

    /**
     * Delete stored key
     */
    deleteKey(address) {
        const keystore = this.getKeystore();
        delete keystore[address];
        localStorage.setItem(this.storageKey, JSON.stringify(keystore));
    }

    /**
     * Get keystore from localStorage
     */
    getKeystore() {
        const stored = localStorage.getItem(this.storageKey);
        return stored ? JSON.parse(stored) : {};
    }

    /**
     * Clear entire keystore
     */
    clearKeystore() {
        localStorage.removeItem(this.storageKey);
    }

    /**
     * Generate Ethereum-style address from public key
     */
    publicKeyToAddress(publicKey) {
        // Remove the 0x04 prefix and get the uncompressed coordinates
        const coordinates = publicKey.slice(1);
        const x = coordinates.slice(0, 32);
        const y = coordinates.slice(32, 64);

        // Concatenate x and y coordinates
        const combined = new Uint8Array(64);
        combined.set(x);
        combined.set(y, 32);

        // Hash with SHA-256 and take last 20 bytes
        return crypto.subtle.digest('SHA-256', combined).then(hash => {
            const hashBytes = new Uint8Array(hash);
            return '0x' + Array.from(hashBytes.slice(-20))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        });
    }

    /**
     * Sign message with private key
     */
    async signMessage(privateKey, message) {
        const privateKeyBigInt = this.secp256r1.bytesToBigInt(privateKey);
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        return await this.secp256r1.sign(privateKeyBigInt, messageBytes);
    }

    /**
     * Verify signature with public key
     */
    async verifySignature(publicKey, message, signature) {
        const publicKeyPoint = this.secp256r1.uncompressedToPoint(publicKey);
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        return await this.secp256r1.verify(publicKeyPoint, messageBytes, signature);
    }

    /**
     * Export key pair for backup (encrypted)
     */
    async exportKeyPair(address, password, exportPassword) {
        const storedKey = this.getStoredKey(address);
        if (!storedKey) {
            throw new Error('No key found for address');
        }

        const privateKey = await this.loadPrivateKey(address, password);
        const encryptedExport = await this.encryptPrivateKey(privateKey, exportPassword);

        return {
            publicKey: storedKey.publicKey,
            encryptedPrivateKey: {
                encrypted: Array.from(encryptedExport.encrypted),
                salt: Array.from(encryptedExport.salt),
                iv: Array.from(encryptedExport.iv)
            },
            metadata: storedKey.metadata
        };
    }

    /**
     * Import key pair from backup
     */
    async importKeyPair(keyData, importPassword) {
        const publicKey = new Uint8Array(keyData.publicKey);
        const encryptedPrivateKey = {
            encrypted: new Uint8Array(keyData.encryptedPrivateKey.encrypted),
            salt: new Uint8Array(keyData.encryptedPrivateKey.salt),
            iv: new Uint8Array(keyData.encryptedPrivateKey.iv)
        };

        // Decrypt with import password
        const privateKey = await this.decryptPrivateKey(encryptedPrivateKey, importPassword);

        // Re-encrypt with new password (this would be the user's current password)
        // For now, we'll store it as-is
        const address = await this.publicKeyToAddress(publicKey);
        await this.storeKey(publicKey, encryptedPrivateKey, keyData.metadata);

        return address;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = KeyManager;
} else if (typeof window !== 'undefined') {
    window.KeyManager = KeyManager;
}
