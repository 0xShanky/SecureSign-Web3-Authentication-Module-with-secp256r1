# SecureSign Web3 Authentication Module with secp256r1

A lightweight Web3 authentication module demonstrating passwordless login using secp256r1 elliptic curve cryptography. This project includes a complete software implementation of secp256r1 math, encrypted key management, and onchain signature verification.

## Features

- **secp256r1 Cryptography Module**: Pure software implementation of elliptic curve math and ECDSA
- **Software-Based Key Manager**: Encrypted keystore with AES-GCM and password protection
- **WebAuthn Authentication Emulator**: Challenge-response signing using decrypted keys
- **Solidity secp256r1 Verification Contract**: Onchain signature validation on Sepolia testnet
- **Demo UI**: Browser-based interface for registration, authentication, and blockchain interaction

## Project Structure

```
├── contracts/           # Solidity smart contracts
├── frontend/           # Demo UI and crypto modules
├── tests/             # Foundry and integration tests
├── scripts/           # Deployment and utility scripts
├── foundry.toml       # Foundry configuration
└── package.json       # Node.js dependencies
```

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   forge install
   ```

2. Run local tests:
   ```bash
   forge test
   ```

3. Start demo UI:
   ```bash
   npm run dev
   ```

## Development

- **Cryptography**: Custom secp256r1 implementation with Web Crypto API
- **Smart Contracts**: Foundry + Forge with Anvil local testing
- **Frontend**: Vanilla JS with Ethers.js for blockchain interaction
- **Testing**: Comprehensive test suite including Fusaka precompile simulation

## License

MIT
