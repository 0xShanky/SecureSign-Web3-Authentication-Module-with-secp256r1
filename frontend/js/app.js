/**
 * SecureSign Demo Application
 * 
 * Main application logic for the Web3 authentication demo
 */

class SecureSignApp {
    constructor() {
        this.keyManager = new KeyManager();
        this.secp256r1 = new Secp256r1();
        this.provider = null;
        this.signer = null;
        this.contract = null;
        this.contractAddress = null;
        this.currentUser = null;

        this.init();
    }

    async init() {
        console.log('Initializing SecureSign Demo...');

        // Setup event listeners
        this.setupEventListeners();

        // Load stored keys
        this.loadStoredKeys();

        // Try to connect to Web3 provider
        await this.connectWeb3();

        // Load contract if available
        await this.loadContract();

        console.log('SecureSign Demo initialized');
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Registration
        document.getElementById('generateKeysBtn').addEventListener('click', () => {
            this.handleRegistration();
        });

        // Login
        document.getElementById('loginBtn').addEventListener('click', () => {
            this.handleLogin();
        });

        // Verification
        document.getElementById('signAndVerifyBtn').addEventListener('click', () => {
            this.handleVerification();
        });

        // Key management
        document.getElementById('exportKeysBtn').addEventListener('click', () => {
            this.handleExportKeys();
        });

        document.getElementById('importKeysBtn').addEventListener('click', () => {
            document.getElementById('importFileInput').click();
        });

        document.getElementById('importFileInput').addEventListener('change', (e) => {
            this.handleImportKeys(e);
        });

        document.getElementById('clearKeysBtn').addEventListener('click', () => {
            this.handleClearKeys();
        });

        // Password confirmation
        document.getElementById('registerConfirmPassword').addEventListener('input', (e) => {
            this.validatePasswordConfirmation();
        });
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');

        // Update address selectors
        this.updateAddressSelectors();
    }

    async connectWeb3() {
        try {
            if (typeof window.ethereum !== 'undefined') {
                this.provider = new ethers.BrowserProvider(window.ethereum);
                this.signer = await this.provider.getSigner();

                const network = await this.provider.getNetwork();
                const address = await this.signer.getAddress();

                document.getElementById('walletAddress').textContent = address;
                document.getElementById('networkName').textContent = network.name;

                console.log('Connected to Web3:', address, network.name);
            } else {
                console.log('No Web3 provider found');
                document.getElementById('walletAddress').textContent = 'No Web3 Provider';
            }
        } catch (error) {
            console.error('Failed to connect to Web3:', error);
            document.getElementById('walletAddress').textContent = 'Connection Failed';
        }
    }

    async loadContract() {
        // In a real deployment, this would be the actual contract address
        // For demo purposes, we'll use a placeholder
        this.contractAddress = '0x0000000000000000000000000000000000000000';

        if (this.contractAddress && this.contractAddress !== '0x0000000000000000000000000000000000000000') {
            try {
                // Contract ABI would be loaded here
                // this.contract = new ethers.Contract(this.contractAddress, contractABI, this.signer);
                document.getElementById('contractAddress').textContent = this.contractAddress;
            } catch (error) {
                console.error('Failed to load contract:', error);
                document.getElementById('contractAddress').textContent = 'Contract Not Available';
            }
        } else {
            document.getElementById('contractAddress').textContent = 'Not Deployed';
        }
    }

    async handleRegistration() {
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('registerConfirmPassword').value;

        if (!password || !confirmPassword) {
            this.showError('Please enter a password');
            return;
        }

        if (password !== confirmPassword) {
            this.showError('Passwords do not match');
            return;
        }

        if (password.length < 8) {
            this.showError('Password must be at least 8 characters long');
            return;
        }

        try {
            this.showLoading('generateKeysBtn', 'Generating keys...');

            // Generate key pair
            const keyPair = await this.keyManager.generateKeyPair();

            // Encrypt private key
            const encryptedPrivateKey = await this.keyManager.encryptPrivateKey(keyPair.privateKey, password);

            // Store in keystore
            const address = await this.keyManager.publicKeyToAddress(keyPair.publicKey);
            await this.keyManager.storeKey(keyPair.publicKey, encryptedPrivateKey, {
                algorithm: 'secp256r1',
                keyType: 'ECDSA'
            });

            // Update UI
            document.getElementById('publicKeyDisplay').textContent =
                '0x' + Array.from(keyPair.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
            document.getElementById('addressDisplay').textContent = address;
            document.getElementById('registerResult').style.display = 'block';

            // Clear form
            document.getElementById('registerPassword').value = '';
            document.getElementById('registerConfirmPassword').value = '';

            // Reload stored keys
            this.loadStoredKeys();

            this.showSuccess('Key pair generated and stored successfully!');

        } catch (error) {
            console.error('Registration failed:', error);
            this.showError('Registration failed: ' + error.message);
        } finally {
            this.hideLoading('generateKeysBtn', 'Generate Keys');
        }
    }

    async handleLogin() {
        const address = document.getElementById('loginAddress').value;
        const password = document.getElementById('loginPassword').value;

        if (!address || !password) {
            this.showError('Please select an address and enter your password');
            return;
        }

        try {
            this.showLoading('loginBtn', 'Signing in...');

            // Load and decrypt private key
            const privateKey = await this.keyManager.loadPrivateKey(address, password);

            // Set current user
            this.currentUser = {
                address: address,
                privateKey: privateKey
            };

            // Update UI
            document.getElementById('sessionInfo').textContent =
                `Active session for ${address.substring(0, 10)}...`;
            document.getElementById('loginResult').style.display = 'block';

            // Clear form
            document.getElementById('loginPassword').value = '';

            this.showSuccess('Authentication successful!');

        } catch (error) {
            console.error('Login failed:', error);
            this.showError('Authentication failed: ' + error.message);
        } finally {
            this.hideLoading('loginBtn', 'Sign In');
        }
    }

    async handleVerification() {
        const message = document.getElementById('verifyMessage').value;
        const address = document.getElementById('verifyAddress').value;
        const password = document.getElementById('verifyPassword').value;

        if (!message || !address || !password) {
            this.showError('Please fill in all fields');
            return;
        }

        try {
            this.showLoading('signAndVerifyBtn', 'Signing and verifying...');

            // Load private key
            const privateKey = await this.keyManager.loadPrivateKey(address, password);

            // Sign message
            const messageBytes = new TextEncoder().encode(message);
            const signature = await this.keyManager.signMessage(privateKey, messageBytes);

            // Combine r and s into 64-byte signature
            const signatureBytes = new Uint8Array(64);
            signatureBytes.set(signature.r);
            signatureBytes.set(signature.s, 32);

            // Get public key for verification
            const storedKey = this.keyManager.getStoredKey(address);
            const publicKey = new Uint8Array(storedKey.publicKey);

            // Verify signature locally
            const isValid = await this.keyManager.verifySignature(publicKey, messageBytes, signature);

            // Update UI
            document.getElementById('signatureDisplay').textContent =
                '0x' + Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            document.getElementById('onchainResult').textContent = isValid ? 'Valid' : 'Invalid';
            document.getElementById('onchainResult').className = isValid ? 'value success' : 'value error';
            document.getElementById('verifyResult').style.display = 'block';

            // Clear form
            document.getElementById('verifyMessage').value = '';
            document.getElementById('verifyPassword').value = '';

            this.showSuccess('Signature created and verified successfully!');

        } catch (error) {
            console.error('Verification failed:', error);
            this.showError('Verification failed: ' + error.message);
        } finally {
            this.hideLoading('signAndVerifyBtn', 'Sign & Verify');
        }
    }

    async handleExportKeys() {
        const addresses = this.keyManager.getStoredAddresses();

        if (addresses.length === 0) {
            this.showError('No keys to export');
            return;
        }

        try {
            const exportData = {};

            for (const address of addresses) {
                const password = prompt(`Enter password for ${address}:`);
                if (password) {
                    const keyData = await this.keyManager.exportKeyPair(address, password, 'export_password');
                    exportData[address] = keyData;
                }
            }

            // Create and download file
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'securesign-keys-backup.json';
            a.click();
            URL.revokeObjectURL(url);

            this.showSuccess('Keys exported successfully!');

        } catch (error) {
            console.error('Export failed:', error);
            this.showError('Export failed: ' + error.message);
        }
    }

    async handleImportKeys(event) {
        const file = event.target.files[0];
        if (!file) return;

        try {
            const text = await file.text();
            const importData = JSON.parse(text);

            const importPassword = prompt('Enter import password:');
            if (!importPassword) return;

            let importedCount = 0;

            for (const [address, keyData] of Object.entries(importData)) {
                try {
                    await this.keyManager.importKeyPair(keyData, importPassword);
                    importedCount++;
                } catch (error) {
                    console.error(`Failed to import key for ${address}:`, error);
                }
            }

            // Reload stored keys
            this.loadStoredKeys();

            this.showSuccess(`Imported ${importedCount} keys successfully!`);

        } catch (error) {
            console.error('Import failed:', error);
            this.showError('Import failed: ' + error.message);
        }
    }

    async handleClearKeys() {
        if (confirm('Are you sure you want to clear all stored keys? This action cannot be undone.')) {
            this.keyManager.clearKeystore();
            this.loadStoredKeys();
            this.showSuccess('All keys cleared successfully!');
        }
    }

    loadStoredKeys() {
        const addresses = this.keyManager.getStoredAddresses();
        const keysList = document.getElementById('keysList');
        const loginAddress = document.getElementById('loginAddress');
        const verifyAddress = document.getElementById('verifyAddress');

        // Clear existing options
        keysList.innerHTML = '';
        loginAddress.innerHTML = '<option value="">Select your address</option>';
        verifyAddress.innerHTML = '<option value="">Select your address</option>';

        if (addresses.length === 0) {
            keysList.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No keys stored</p>';
            return;
        }

        addresses.forEach(address => {
            // Add to keys list
            const keyItem = document.createElement('div');
            keyItem.className = 'key-item';
            keyItem.innerHTML = `
                <div>
                    <div class="key-address">${address}</div>
                </div>
                <div class="key-actions-small">
                    <button class="btn btn-small btn-danger" onclick="app.deleteKey('${address}')">Delete</button>
                </div>
            `;
            keysList.appendChild(keyItem);

            // Add to selectors
            const option1 = document.createElement('option');
            option1.value = address;
            option1.textContent = address;
            loginAddress.appendChild(option1);

            const option2 = document.createElement('option');
            option2.value = address;
            option2.textContent = address;
            verifyAddress.appendChild(option2);
        });
    }

    updateAddressSelectors() {
        this.loadStoredKeys();
    }

    async deleteKey(address) {
        if (confirm(`Are you sure you want to delete the key for ${address}?`)) {
            this.keyManager.deleteKey(address);
            this.loadStoredKeys();
            this.showSuccess('Key deleted successfully!');
        }
    }

    validatePasswordConfirmation() {
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('registerConfirmPassword').value;

        if (confirmPassword && password !== confirmPassword) {
            document.getElementById('registerConfirmPassword').style.borderColor = '#e53e3e';
        } else {
            document.getElementById('registerConfirmPassword').style.borderColor = '#e2e8f0';
        }
    }

    showLoading(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.disabled = true;
        button.innerHTML = `<span class="loading"></span> ${text}`;
    }

    hideLoading(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.disabled = false;
        button.textContent = text;
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
            background: ${type === 'success' ? '#38a169' : '#e53e3e'};
        `;

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecureSignApp();
});
