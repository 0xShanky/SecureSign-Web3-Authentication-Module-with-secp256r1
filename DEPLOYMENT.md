# SecureSign Deployment Guide

This guide covers deploying the SecureSign Web3 Authentication Module to Sepolia testnet and setting up the complete development environment.

## Prerequisites

- Node.js (v16 or higher)
- Foundry (forge, cast, anvil)
- Git
- Sepolia ETH for deployment
- Infura or Alchemy API key

## Environment Setup

1. **Clone and Install Dependencies**
   ```bash
   git clone <repository-url>
   cd "SecureSign Web3 Authentication Module with secp256r1"
   npm install
   forge install
   ```

2. **Environment Variables**
   ```bash
   cp env.example .env
   ```
   
   Edit `.env` with your values:
   ```env
   PRIVATE_KEY=your_private_key_here
   SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/your_infura_key
   INFURA_API_KEY=your_infura_api_key
   ETHERSCAN_API_KEY=your_etherscan_api_key
   ```

## Local Development

### 1. Start Anvil (Local Testnet)
```bash
# Basic Anvil
anvil

# Anvil with Fusaka precompile simulation
anvil --hardfork shanghai --prestate prestate.json
```

### 2. Run Tests
```bash
# Run all tests
forge test

# Run with coverage
forge coverage

# Run specific test file
forge test --match-path tests/Secp256r1Verifier.t.sol

# Run with gas reporting
forge test --gas-report
```

### 3. Build Contracts
```bash
forge build
```

## Deployment to Sepolia

### 1. Deploy Contract
```bash
# Deploy to Sepolia
forge script scripts/Deploy.s.sol --rpc-url sepolia --broadcast --verify

# Deploy with specific private key
forge script scripts/Deploy.s.sol --rpc-url sepolia --private-key $PRIVATE_KEY --broadcast --verify
```

### 2. Verify Deployment
```bash
# Check deployment
cast call <CONTRACT_ADDRESS> "getContractInfo()" --rpc-url sepolia

# Get contract info
cast call <CONTRACT_ADDRESS> "name()" --rpc-url sepolia
```

### 3. Update Frontend Configuration
After deployment, update the contract address in the frontend:

```javascript
// In frontend/js/app.js
this.contractAddress = '0x<DEPLOYED_CONTRACT_ADDRESS>';
```

## Frontend Deployment

### 1. Local Development Server
```bash
# Start development server
npm run dev

# Access at http://localhost:3000
```

### 2. Production Build
```bash
# Build for production
npm run build

# Serve static files
npx http-server frontend -p 3000 -c-1
```

### 3. Deploy to Static Hosting
The frontend can be deployed to any static hosting service:

- **Vercel**: Connect GitHub repository
- **Netlify**: Drag and drop `frontend` folder
- **GitHub Pages**: Push to `gh-pages` branch
- **IPFS**: Upload to IPFS for decentralized hosting

## Testing the Complete Flow

### 1. Local Testing
1. Start Anvil: `anvil`
2. Deploy contract: `forge script scripts/Deploy.s.sol --rpc-url anvil --broadcast`
3. Start frontend: `npm run dev`
4. Open http://localhost:3000
5. Connect MetaMask to Anvil (http://localhost:8545)
6. Test registration, login, and verification

### 2. Sepolia Testing
1. Deploy to Sepolia: `forge script scripts/Deploy.s.sol --rpc-url sepolia --broadcast --verify`
2. Update contract address in frontend
3. Connect MetaMask to Sepolia network
4. Test with real Sepolia ETH

## Contract Verification

### 1. Automatic Verification
```bash
# Verify during deployment
forge script scripts/Deploy.s.sol --rpc-url sepolia --broadcast --verify
```

### 2. Manual Verification
```bash
# Verify deployed contract
forge verify-contract <CONTRACT_ADDRESS> Secp256r1Verifier --etherscan-api-key $ETHERSCAN_API_KEY --chain sepolia
```

## Monitoring and Maintenance

### 1. Contract Events
Monitor these events for usage analytics:
- `UserRegistered(address indexed user, bytes publicKey)`
- `SignatureVerified(address indexed signer, bytes32 messageHash, bool isValid)`
- `AuthenticationAttempt(address indexed user, bool success)`

### 2. Gas Optimization
- Monitor gas usage for each operation
- Optimize signature verification if needed
- Consider batch operations for multiple users

### 3. Security Considerations
- Regularly audit the contract code
- Monitor for unusual activity patterns
- Keep dependencies updated

## Troubleshooting

### Common Issues

1. **Deployment Fails**
   - Check private key has sufficient ETH
   - Verify RPC URL is correct
   - Ensure network is accessible

2. **Contract Verification Fails**
   - Check compiler version matches
   - Verify constructor parameters
   - Ensure all dependencies are installed

3. **Frontend Connection Issues**
   - Check contract address is correct
   - Verify network configuration
   - Ensure MetaMask is connected

4. **Signature Verification Issues**
   - Check public key format (uncompressed)
   - Verify signature length (64 bytes)
   - Ensure message hash is correct

### Debug Commands

```bash
# Check contract state
cast call <CONTRACT_ADDRESS> "isUserRegistered(address)" <USER_ADDRESS> --rpc-url sepolia

# Get user public key
cast call <CONTRACT_ADDRESS> "getUserPublicKey(address)" <USER_ADDRESS> --rpc-url sepolia

# Check nonce usage
cast call <CONTRACT_ADDRESS> "usedNonces(bytes32)" <NONCE> --rpc-url sepolia
```

## Production Considerations

### 1. Security
- Use hardware wallets for deployment keys
- Implement proper access controls
- Regular security audits
- Monitor for vulnerabilities

### 2. Scalability
- Consider gas optimization
- Implement batch operations
- Monitor contract size limits
- Plan for upgrade mechanisms

### 3. Monitoring
- Set up event monitoring
- Track gas usage patterns
- Monitor for failed transactions
- Implement alerting systems

## Support

For issues and questions:
- Check the test suite for examples
- Review the integration tests
- Consult the Foundry documentation
- Check the contract source code

## License

This project is licensed under the MIT License. See LICENSE file for details.
