# Account Abstraction Implementation TODO (Hybrid Web2/Web3 Architecture)

## CRITICAL DESIGN PRINCIPLE

**Account Abstraction is implemented as an ADDITIVE layer on top of existing Web2 authentication. All existing Web2 functionality must remain unchanged and fully operational.**

### Core Requirements
- **Web2 Backward Compatibility**: ALL existing authentication methods (JWT, OAuth, OTP) must remain fully functional
- **Zero Impact Migration**: Web3 features are opt-in extensions that don't affect existing users
- **Data Preservation**: All existing user data, preferences, and authentication history must be preserved
- **Seamless Transition**: Users can upgrade from Web2 to Web3 without losing access or data
- **Dual Authentication**: Support both Web2 and Web3 authentication methods simultaneously on the same account
- **Fallback Guarantee**: Web2 authentication must always be available as fallback for Web3 users

## Phase 1: Smart Contract Development (2-3 weeks)

### 1.1 Project Setup and Environment
- [ ] Set up Hardhat/Foundry development environment
- [ ] Configure network settings (testnet and mainnet)
- [ ] Install required dependencies (OpenZeppelin contracts, ERC-4337 libraries)
- [ ] Set up deployment scripts and configuration files

### 1.2 Smart Account Contract Development
- [ ] Create base `SmartAccount.sol` contract implementing IAccount interface
  - [ ] Implement `validateUserOp` function for signature validation
  - [ ] Add multi-signature support with configurable threshold
  - [ ] Implement `execute` function for single transactions
  - [ ] Implement `executeBatch` function for batch operations
  - [ ] Add session key validation logic
  - [ ] Implement owner management (add/remove owners)
  - [ ] Add recovery mechanism with time-locked recovery
  - [ ] Include event emissions for all critical operations

### 1.3 Smart Account Factory Contract
- [ ] Create `SmartAccountFactory.sol` contract
  - [ ] Implement `createAccount` function with CREATE2 for deterministic addresses
  - [ ] Add `getAddress` function to calculate account addresses
  - [ ] Include initialization parameter handling
  - [ ] Add account registry for tracking deployed accounts
  - [ ] Implement version control for account implementations

### 1.4 Paymaster Contract Development
- [ ] Create `BlockAuthPaymaster.sol` contract
  - [ ] Implement `validatePaymasterUserOp` function
  - [ ] Add subscription validation logic
  - [ ] Implement gas credit system
  - [ ] Add plan tier validation (Free, Premium, Enterprise)
  - [ ] Include usage tracking and rate limiting
  - [ ] Add deposit/withdrawal functions for gas funds
  - [ ] Implement admin controls for subscription management

### 1.5 Contract Testing
- [ ] Write comprehensive unit tests for SmartAccount
  - [ ] Test signature validation with different signature schemes
  - [ ] Test batch execution functionality
  - [ ] Test multi-signature operations
  - [ ] Test session key functionality
  - [ ] Test recovery mechanisms
- [ ] Write unit tests for SmartAccountFactory
  - [ ] Test deterministic address generation
  - [ ] Test account creation with different parameters
- [ ] Write unit tests for Paymaster
  - [ ] Test subscription validation
  - [ ] Test gas sponsorship logic
  - [ ] Test rate limiting functionality
- [ ] Integration tests for complete user operation flow
- [ ] Gas optimization tests and analysis

### 1.6 Contract Deployment and Verification
- [ ] Deploy contracts to testnet (Sepolia/Goerli)
- [ ] Verify contracts on Etherscan
- [ ] Set up monitoring and alerting for contract events
- [ ] Create deployment documentation with contract addresses

## Phase 2: Python Integration Layer (2-3 weeks)

### 2.1 Enhanced User Model (ADDITIVE ONLY - NO BREAKING CHANGES)
- [ ] Create `AAUserMixin` abstract model class with OPTIONAL fields only
  ```python
  # blockauth/models/aa_user.py
  class AAUserMixin(models.Model):
      # CRITICAL: ALL fields must be nullable and optional
      smart_account_address = models.CharField(max_length=42, unique=True, null=True, blank=True)
      account_salt = models.CharField(max_length=64, null=True, blank=True)
      is_account_deployed = models.BooleanField(default=False)
      is_aa_enabled = models.BooleanField(default=False)  # User opt-in flag
      preferred_auth_method = models.CharField(max_length=10, default='WEB2', choices=[
          ('WEB2', 'Web2 Only'),
          ('WEB3', 'Web3 Only'), 
          ('HYBRID', 'Both Web2 and Web3')
      ])
      recovery_addresses = models.JSONField(default=list, blank=True)
      session_keys = models.JSONField(default=list, blank=True)
      
      # Web2 to Web3 migration tracking
      migrated_from_web2 = models.BooleanField(default=False)
      migration_timestamp = models.DateTimeField(null=True, blank=True)
      web2_backup_enabled = models.BooleanField(default=True)  # Always keep Web2 as backup
      
      class Meta:
          abstract = True
  ```
- [ ] Add OPTIONAL migration for new fields (must not affect existing data)
- [ ] Extend existing `BlockUser` model to include OPTIONAL AA fields
- [ ] Add helper methods for account address calculation (Web2 compatible)
- [ ] Implement account deployment tracking with Web2 fallback
- [ ] **CRITICAL**: Add migration compatibility layer preserving all existing Web2 functionality

### 2.2 Web3 Infrastructure Components
- [ ] Create `SmartAccountManager` class
  ```python
  # blockauth/utils/web3/smart_account.py
  class SmartAccountManager:
      def __init__(self, web3_provider, factory_address, entry_point_address)
      def get_smart_account_address(self, user_id, salt)
      def deploy_smart_account(self, user_id, owners, threshold)
      def is_account_deployed(self, address)
      def get_account_nonce(self, address)
  ```
- [ ] Create `UserOperationBuilder` class
  ```python
  # blockauth/utils/web3/user_operation.py
  class UserOperationBuilder:
      def build_user_op(self, sender, nonce, init_code, call_data, signature)
      def estimate_gas(self, user_op)
      def sign_user_operation(self, user_op, private_key)
      def validate_user_operation(self, user_op)
  ```
- [ ] Create `PaymasterManager` class
  ```python
  # blockauth/utils/web3/paymaster.py
  class PaymasterManager:
      def validate_subscription(self, user_id, operation_cost)
      def get_paymaster_data(self, user_id, user_op)
      def deduct_gas_credits(self, user_id, gas_used)
      def check_plan_limits(self, user_id, operation_type)
  ```

### 2.3 Bundler Integration
- [ ] Create `BundlerClient` class for communication with bundler services
  ```python
  # blockauth/utils/web3/bundler.py
  class BundlerClient:
      def submit_user_operation(self, user_op)
      def get_user_operation_receipt(self, user_op_hash)
      def estimate_user_operation_gas(self, user_op)
      def get_supported_entry_points()
  ```
- [ ] Add configuration for multiple bundler endpoints
- [ ] Implement fallback logic for bundler failures
- [ ] Add monitoring and health checks for bundler services

### 2.4 Hybrid Authentication System (CRITICAL: Web2 FIRST)
- [ ] Create `HybridAuthenticationRouter` class that preserves Web2 authentication
  ```python
  # blockauth/authentication_hybrid.py
  class HybridAuthenticationRouter(BaseAuthentication):
      """
      CRITICAL: Routes authentication to Web2 or Web3 based on user preference
      Web2 authentication MUST always work and be the default
      """
      def authenticate(self, request):
          # 1. Try Web2 authentication first (backward compatibility)
          web2_result = self._try_web2_authentication(request)
          if web2_result:
              return web2_result
              
          # 2. Try Web3 authentication only if user has opted in
          if self._user_has_web3_enabled(request):
              return self._try_web3_authentication(request)
              
          return None
      
      def _try_web2_authentication(self, request):
          # Use existing JWTAuthentication class - NO CHANGES
          return JWTAuthentication().authenticate(request)
      
      def _try_web3_authentication(self, request):
          # New AA authentication logic
          pass
  ```
- [ ] Create `AccountAbstractionAuthentication` as OPTIONAL enhancement
  ```python
  # blockauth/authentication_aa.py  
  class AccountAbstractionAuthentication(BaseAuthentication):
      def authenticate(self, request)
      def _verify_user_operation(self, user_op)
      def _get_user_from_smart_account(self, account_address)
      def _fallback_to_web2(self, user_id)  # CRITICAL: Always provide Web2 fallback
  ```
- [ ] Implement UserOperation signature validation with Web2 fallback
- [ ] Add support for session key authentication (Web3 users only)
- [ ] Create middleware for AA-based request processing that preserves Web2 flows
- [ ] **MANDATORY**: Ensure 100% backward compatibility with existing JWT authentication
- [ ] Add migration detection and seamless Web2/Web3 authentication bridging

### 2.5 Configuration and Settings
- [ ] Add AA-related settings to Django configuration
  ```python
  # Settings to add
  ACCOUNT_ABSTRACTION = {
      'ENTRY_POINT_ADDRESS': '0x...',
      'FACTORY_ADDRESS': '0x...',
      'PAYMASTER_ADDRESS': '0x...',
      'BUNDLER_URLS': ['https://bundler1.com', 'https://bundler2.com'],
      'DEFAULT_GAS_LIMITS': {...},
      'SUBSCRIPTION_PLANS': {...}
  }
  ```
- [ ] Create configuration validation
- [ ] Add environment-specific settings (dev, staging, prod)

### 2.6 Web2 to Web3 Migration Service (CRITICAL COMPONENT)
- [ ] Create `Web2ToWeb3MigrationService` class
  ```python
  # blockauth/services/migration.py
  class Web2ToWeb3MigrationService:
      """
      Handles seamless migration from Web2 to Web3 while preserving all data
      """
      def initiate_migration(self, user_id, migration_options):
          # Preserve all existing Web2 data and preferences
          pass
      
      def link_smart_account(self, user_id, smart_account_address):
          # Link Web3 account while keeping Web2 active
          pass
      
      def rollback_migration(self, user_id):
          # Rollback to Web2-only mode without data loss
          pass
      
      def verify_migration_integrity(self, user_id):
          # Ensure all data preserved and accessible
          pass
  ```
- [ ] Implement data preservation algorithms for all user preferences and history
- [ ] Add migration progress tracking with rollback capabilities
- [ ] Create migration validation and integrity checks
- [ ] Implement gradual feature activation (progressive enhancement)
- [ ] Add migration analytics and monitoring for success rates

### 2.7 Compatibility Layer (MANDATORY)
- [ ] Create Web2 compatibility middleware ensuring zero impact on existing flows
- [ ] Add feature flag system for gradual Web3 feature rollout
- [ ] Implement authentication method fallback chains (Web3 → Web2 → Error)
- [ ] Create unified API response format supporting both Web2 and Web3 data
- [ ] Add comprehensive logging for hybrid authentication events
- [ ] Implement performance monitoring to ensure Web2 performance not degraded

## Phase 3: API Endpoints Enhancement (1-2 weeks) - ADDITIVE ONLY

### 3.1 Migration and Hybrid Account Management Endpoints (NEW ENDPOINTS ONLY)
- [ ] Create `Web2ToWeb3MigrationView`
  - [ ] POST `/api/auth/migrate/initiate/` - Initiate Web2 to Web3 migration
  - [ ] Preserve all existing Web2 authentication and data
  - [ ] Return migration progress and smart account information
  - [ ] **CRITICAL**: Maintain Web2 authentication as fallback during migration
- [ ] Create `MigrationStatusView`
  - [ ] GET `/api/auth/migrate/status/` - Get migration progress status
  - [ ] Return migration stage, data integrity status, rollback options
- [ ] Create `MigrationRollbackView`
  - [ ] POST `/api/auth/migrate/rollback/` - Rollback to Web2-only mode
  - [ ] Preserve all data and restore Web2-only authentication
- [ ] Create `SmartAccountCreateView` (OPTIONAL - for Web3 users only)
  - [ ] POST `/api/aa/account/create/` - Create smart account (Web3 users)
  - [ ] Validate user has opted into Web3 features
  - [ ] Handle account deployment while maintaining Web2 access
  - [ ] Return account address and deployment status
- [ ] Create `SmartAccountStatusView` (OPTIONAL)
  - [ ] GET `/api/aa/account/status/` - Get account deployment status
  - [ ] Return account address, deployment status, nonce
  - [ ] Include Web2 fallback authentication status
- [ ] Create `AuthMethodPreferenceView`
  - [ ] GET/POST `/api/auth/preference/` - Manage authentication method preferences
  - [ ] Allow users to choose Web2, Web3, or Hybrid authentication
  - [ ] Always preserve Web2 as available option

### 3.2 User Operation Endpoints
- [ ] Create `UserOperationCreateView`
  - [ ] POST `/api/aa/userop/create/` - Build user operation
  - [ ] Validate operation parameters
  - [ ] Return unsigned user operation
- [ ] Create `UserOperationSubmitView`
  - [ ] POST `/api/aa/userop/submit/` - Submit signed user operation
  - [ ] Validate signature
  - [ ] Submit to bundler
  - [ ] Return operation hash and status
- [ ] Create `UserOperationStatusView`
  - [ ] GET `/api/aa/userop/status/<hash>/` - Get operation status
  - [ ] Return execution status and receipt

### 3.3 Batch Operations Endpoints
- [ ] Create `BatchOperationView`
  - [ ] POST `/api/aa/batch/` - Execute multiple operations
  - [ ] Validate batch operations
  - [ ] Optimize gas usage
  - [ ] Handle partial failures

### 3.4 Gas Estimation Endpoints
- [ ] Create `GasEstimationView`
  - [ ] POST `/api/aa/gas/estimate/` - Estimate gas for operations
  - [ ] Return gas estimates with buffer
  - [ ] Include paymaster gas costs

### 3.5 Recovery Endpoints
- [ ] Create `RecoveryInitiateView`
  - [ ] POST `/api/aa/recovery/initiate/` - Start recovery process
  - [ ] Validate recovery guardians
  - [ ] Implement time-lock mechanism
- [ ] Create `RecoveryExecuteView`
  - [ ] POST `/api/aa/recovery/execute/` - Execute recovery
  - [ ] Validate time-lock expiry
  - [ ] Update account ownership

## Phase 4: Subscription Integration (1-2 weeks)

### 4.1 Subscription Service Communication
- [ ] Create `SubscriptionClient` for microservice communication
  ```python
  # blockauth/utils/subscription_client.py
  class SubscriptionClient:
      def validate_plan(self, user_id, operation_type)
      def get_gas_credits(self, user_id)
      def deduct_credits(self, user_id, amount)
      def get_plan_limits(self, user_id)
  ```
- [ ] Implement API endpoints for subscription validation
- [ ] Add caching layer for subscription data
- [ ] Handle subscription service failures gracefully

### 4.2 Plan-Based Feature Controls
- [ ] Implement plan validation in paymaster
- [ ] Add rate limiting based on subscription tiers
  - [ ] Free tier: 10 operations/day, basic features only
  - [ ] Premium tier: 1000 operations/day, gas sponsorship
  - [ ] Enterprise tier: Unlimited operations, custom paymaster
- [ ] Create plan upgrade/downgrade handling
- [ ] Add usage analytics and reporting

### 4.3 Gas Credits System
- [ ] Implement gas credits tracking in database
- [ ] Create credit allocation based on plans
- [ ] Add credit refill mechanisms
- [ ] Implement credit expiry handling
- [ ] Create credit usage analytics

## Phase 5: Testing and Quality Assurance (1-2 weeks)

### 5.1 Integration Testing
- [ ] End-to-end testing of complete AA flow
- [ ] Test with real bundler services on testnet
- [ ] Cross-browser compatibility testing
- [ ] Mobile wallet integration testing
- [ ] Performance testing under load

### 5.2 Security Testing
- [ ] Smart contract security audit
- [ ] Penetration testing of API endpoints
- [ ] Signature validation security testing
- [ ] Recovery mechanism security validation
- [ ] Rate limiting and DoS protection testing

### 5.3 User Acceptance Testing
- [ ] Create test scenarios for different user types
- [ ] Test subscription tier limitations
- [ ] Validate user experience flows
- [ ] Test error handling and edge cases

## Phase 6: Documentation and Migration (1 week)

### 6.1 Documentation
- [ ] Update API documentation with AA endpoints
- [ ] Create developer integration guide
- [ ] Write smart contract documentation
- [ ] Create troubleshooting guide
- [ ] Update deployment documentation

### 6.2 Migration Strategy
- [ ] Create data migration scripts for existing users
- [ ] Implement gradual rollout plan
- [ ] Create rollback procedures
- [ ] Set up monitoring and alerting
- [ ] Train support team on AA features

### 6.3 Monitoring and Analytics
- [ ] Set up contract event monitoring
- [ ] Create user operation analytics dashboard
- [ ] Implement error tracking and alerting
- [ ] Add gas usage monitoring
- [ ] Create subscription usage analytics

## Phase 7: Deployment and Launch (1 week)

### 7.1 Testnet Deployment
- [ ] Deploy all contracts to testnet
- [ ] Deploy updated backend services
- [ ] Configure bundler services
- [ ] Run full integration tests
- [ ] Load testing with realistic scenarios

### 7.2 Mainnet Deployment
- [ ] Deploy contracts to mainnet
- [ ] Update production configuration
- [ ] Enable AA features for beta users
- [ ] Monitor system performance
- [ ] Gradual rollout to all users

### 7.3 Post-Launch Activities
- [ ] Monitor contract gas usage and optimize
- [ ] Collect user feedback and iterate
- [ ] Scale bundler infrastructure as needed
- [ ] Regular security reviews and updates
- [ ] Performance optimization based on usage patterns

---

## Prerequisites and Dependencies

### Technical Requirements
- **Blockchain**: Ethereum mainnet/testnet access
- **Node Provider**: Alchemy/Infura RPC endpoints
- **Bundler**: Stackup, Biconomy, or custom bundler service
- **Database**: PostgreSQL with JSON field support
- **Python**: Django 4.0+, Web3.py, eth-account
- **Smart Contracts**: Solidity 0.8.19+, Hardhat/Foundry

### External Services
- **Subscription Service**: API for plan validation
- **Monitoring**: Datadog/New Relic for system monitoring
- **Analytics**: Mixpanel/Amplitude for user analytics
- **Error Tracking**: Sentry for error monitoring

### Team Requirements
- **Smart Contract Developer**: Solidity, security best practices
- **Backend Developer**: Django, Web3 integration
- **Frontend Developer**: Web3 wallet integration
- **DevOps Engineer**: Deployment and monitoring
- **Product Manager**: Feature coordination and testing

## Success Metrics

### Technical Metrics
- **UserOperation Success Rate**: > 95%
- **Average Gas Savings**: > 50% for sponsored transactions
- **API Response Time**: < 500ms for all endpoints
- **Contract Gas Efficiency**: Optimized for minimal gas usage

### Business Metrics
- **User Adoption**: 60% of users using AA features within 3 months
- **Subscription Conversion**: 25% increase in premium subscriptions
- **Support Tickets**: 40% reduction in gas-related issues
- **User Satisfaction**: > 4.5/5 rating for AA features

## Risk Mitigation

### Technical Risks
- **Smart Contract Bugs**: Comprehensive testing and audits
- **Bundler Failures**: Multiple bundler fallbacks
- **Gas Price Volatility**: Dynamic gas price adjustments
- **Network Congestion**: Priority bundling for premium users

### Business Risks
- **User Confusion**: Comprehensive onboarding and documentation
- **High Gas Costs**: Efficient contract design and batching
- **Regulatory Changes**: Compliance monitoring and adaptation
- **Competition**: Unique features and superior user experience

This TODO provides a comprehensive, step-by-step implementation guide that can be tracked and executed systematically. Each phase builds upon the previous one and includes specific deliverables and acceptance criteria.

## Implementation Guidelines

### Development Environment Setup

#### Required Tools and Dependencies
```bash
# Smart Contract Development
npm install -g hardhat
npm install @openzeppelin/contracts @account-abstraction/contracts
npm install @nomicfoundation/hardhat-toolbox
npm install dotenv ethers

# Python Dependencies
pip install web3 eth-account eth-typing
pip install django-cors-headers django-extensions
pip install celery redis  # For background tasks
pip install prometheus-client  # For metrics
```

#### Environment Configuration
```bash
# .env file
INFURA_API_KEY=your_infura_api_key
PRIVATE_KEY=your_deployment_private_key
ETHERSCAN_API_KEY=your_etherscan_api_key
BUNDLER_API_KEY=your_bundler_api_key

# Database
DATABASE_URL=postgresql://user:pass@localhost/blockauth_aa
REDIS_URL=redis://localhost:6379

# Account Abstraction
AA_NETWORK=sepolia
AA_ENTRY_POINT=0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
AA_FACTORY_ADDRESS=  # Will be set after deployment
AA_PAYMASTER_ADDRESS=  # Will be set after deployment
```

### Smart Contract Development Standards

#### Code Quality Requirements
- **Solidity Version**: Use pragma solidity ^0.8.19 for all contracts
- **Testing Coverage**: Minimum 95% test coverage for all contracts
- **Gas Optimization**: All functions must be gas-optimized with proper comments
- **Security**: Follow OpenZeppelin standards and best practices
- **Documentation**: Comprehensive NatSpec documentation for all functions

#### Contract Architecture Patterns

```solidity
// Example: Upgradeable Contract Pattern
// contracts/SmartAccount.sol
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@account-abstraction/contracts/interfaces/IAccount.sol";

contract SmartAccount is Initializable, IAccount {
    // State variables
    IEntryPoint private immutable _entryPoint;
    address[] public owners;
    uint256 public threshold;
    mapping(address => bool) public isOwner;
    uint256 public nonce;
    
    // Events
    event SmartAccountInitialized(address[] owners, uint256 threshold);
    event TransactionExecuted(bytes32 indexed txHash, bool success);
    
    constructor(IEntryPoint entryPoint) {
        _entryPoint = entryPoint;
        _disableInitializers();
    }
    
    function initialize(
        address[] memory _owners,
        uint256 _threshold
    ) public initializer {
        require(_owners.length > 0, "No owners provided");
        require(_threshold > 0 && _threshold <= _owners.length, "Invalid threshold");
        
        owners = _owners;
        threshold = _threshold;
        
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
        }
        
        emit SmartAccountInitialized(_owners, _threshold);
    }
}
```

### Python Development Standards

#### Code Structure and Patterns

```python
# blockauth/utils/web3/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from web3 import Web3
from eth_typing import Address
import logging

class BaseWeb3Manager(ABC):
    """Base class for Web3 managers"""
    
    def __init__(self, web3: Web3, logger: Optional[logging.Logger] = None):
        self.web3 = web3
        self.logger = logger or logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate manager configuration"""
        pass
    
    def get_contract(self, address: Address, abi: List[Dict[str, Any]]):
        """Get contract instance"""
        return self.web3.eth.contract(address=address, abi=abi)
    
    def wait_for_transaction(self, tx_hash: str, timeout: int = 300) -> Dict[str, Any]:
        """Wait for transaction confirmation"""
        try:
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            return {
                'success': receipt.status == 1,
                'receipt': dict(receipt),
                'gas_used': receipt.gasUsed
            }
        except Exception as e:
            self.logger.error(f"Transaction failed: {e}")
            return {'success': False, 'error': str(e)}
```

#### Error Handling Strategy

```python
# blockauth/utils/aa_decorators.py
from functools import wraps
from typing import Callable, Any
import time
import logging
from blockauth.utils.aa_exceptions import *
from blockauth.utils.aa_metrics import AAMetrics

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Retry decorator for AA operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    start_time = time.time()
                    result = await func(*args, **kwargs)
                    
                    # Record success metrics
                    duration = time.time() - start_time
                    AAMetrics.record_user_operation(
                        operation_type=func.__name__,
                        status='success',
                        user_tier='unknown',
                        duration=duration
                    )
                    
                    return result
                    
                except (BundlerException, AAException) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
                        logging.warning(f"Retrying {func.__name__} (attempt {attempt + 1}): {e}")
                    continue
            
            # Record failure metrics
            AAMetrics.record_user_operation(
                operation_type=func.__name__,
                status='failed',
                user_tier='unknown',
                duration=0
            )
            
            raise last_exception
        
        return wrapper
    return decorator

def validate_user_operation(func: Callable) -> Callable:
    """Validate UserOperation before processing"""
    @wraps(func)
    async def wrapper(self, user_operation: UserOperation, *args, **kwargs):
        # Validate required fields
        if not user_operation.sender:
            raise InvalidSignatureException("Missing sender address")
        
        if not user_operation.signature:
            raise InvalidSignatureException("Missing signature")
        
        # Validate gas limits
        if user_operation.callGasLimit < 21000:
            raise AAException("Call gas limit too low")
        
        return await func(self, user_operation, *args, **kwargs)
    
    return wrapper
```

### Testing Methodology

#### Smart Contract Testing Framework

```javascript
// hardhat.config.js
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000000
      }
    }
  },
  networks: {
    sepolia: {
      url: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: [process.env.PRIVATE_KEY]
    },
    mainnet: {
      url: `https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: [process.env.PRIVATE_KEY]
    }
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY
  },
  gasReporter: {
    enabled: true,
    currency: 'USD',
    gasPrice: 20
  },
  mocha: {
    timeout: 60000
  }
};
```

#### Python Testing Configuration

```python
# pytest.ini
[tool:pytest]
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*
addopts = 
    --cov=blockauth
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=85
    --asyncio-mode=auto
    --tb=short
env =
    DJANGO_SETTINGS_MODULE = blockauth.settings.test
    AA_NETWORK = sepolia
    CELERY_ALWAYS_EAGER = True

# conftest.py
import pytest
import asyncio
from unittest.mock import Mock
from web3 import Web3
from blockauth.models.user import BlockUser

@pytest.fixture
def web3_mock():
    """Mock Web3 instance"""
    mock_web3 = Mock(spec=Web3)
    mock_web3.eth.chain_id = 11155111  # Sepolia
    mock_web3.eth.gas_price = 20000000000  # 20 gwei
    return mock_web3

@pytest.fixture
def test_user():
    """Create test user with AA fields"""
    user = BlockUser.objects.create(
        username="testuser",
        email="test@example.com",
        wallet_address="0x1234567890123456789012345678901234567890"
    )
    return user

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
```

### Security Checklist

#### Smart Contract Security
- [ ] Reentrancy protection on all external calls
- [ ] Integer overflow/underflow protection
- [ ] Access control for all privileged functions
- [ ] Proper event emission for all state changes
- [ ] Gas limit validation for user operations
- [ ] Signature validation against replay attacks
- [ ] Time-lock mechanisms for recovery functions
- [ ] Multi-signature validation for ownership changes
- [ ] Proper error handling and revert messages
- [ ] Storage collision prevention in proxy contracts

#### API Security
- [ ] Rate limiting on all AA endpoints
- [ ] Input validation and sanitization
- [ ] Authentication for all protected endpoints
- [ ] Encryption of sensitive data in transit
- [ ] Audit logging for all operations
- [ ] CORS configuration for frontend integration
- [ ] SQL injection prevention
- [ ] XSS protection in responses
- [ ] API versioning for backward compatibility
- [ ] Monitoring and alerting for anomalies

### Performance Benchmarks

#### Target Performance Metrics
- **User Operation Processing**: < 2 seconds end-to-end
- **Smart Account Deployment**: < 30 seconds on testnet
- **Bundler Response Time**: < 5 seconds average
- **Database Query Performance**: < 100ms for AA queries
- **API Response Time**: < 500ms for all AA endpoints
- **Gas Optimization**: < 500k gas for account deployment
- **Batch Operations**: Support up to 10 operations per batch

#### Load Testing Scenarios

```python
# scripts/load_test.py
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor

async def simulate_user_operation(session, user_id: int):
    """Simulate a single user operation"""
    url = "http://localhost:8000/api/aa/userop/create/"
    payload = {
        "sender": f"0x{'0' * 40}",
        "callData": "0x",
        "value": "0"
    }
    
    start_time = time.time()
    async with session.post(url, json=payload) as response:
        result = await response.json()
        duration = time.time() - start_time
        
        return {
            "user_id": user_id,
            "status_code": response.status,
            "duration": duration,
            "success": response.status == 200
        }

async def run_load_test(concurrent_users: int = 100, operations_per_user: int = 10):
    """Run load test with specified parameters"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        for user_id in range(concurrent_users):
            for op_id in range(operations_per_user):
                task = simulate_user_operation(session, user_id)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze results
        successful = sum(1 for r in results if isinstance(r, dict) and r["success"])
        failed = len(results) - successful
        avg_duration = sum(r["duration"] for r in results if isinstance(r, dict)) / len(results)
        
        print(f"Load Test Results:")
        print(f"Total operations: {len(results)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success rate: {successful/len(results)*100:.2f}%")
        print(f"Average duration: {avg_duration:.3f}s")

if __name__ == "__main__":
    asyncio.run(run_load_test())
```

### Deployment Checklist

#### Pre-deployment
- [ ] All tests passing (unit, integration, security)
- [ ] Code review completed and approved
- [ ] Security audit completed (for mainnet)
- [ ] Gas optimization analysis completed
- [ ] Load testing completed with acceptable results
- [ ] Documentation updated and reviewed
- [ ] Monitoring and alerting configured
- [ ] Backup and recovery procedures tested
- [ ] Rollback plan prepared and tested

#### Deployment Steps
1. **Testnet Deployment**
   - Deploy contracts to Sepolia testnet
   - Verify contracts on Etherscan
   - Configure bundler services
   - Deploy backend services to staging
   - Run integration tests against testnet
   - Performance testing on testnet

2. **Mainnet Preparation**
   - Security audit review and fixes
   - Gas cost analysis and optimization
   - Prepare deployment scripts
   - Set up production monitoring
   - Configure production bundler services
   - Prepare communication plan

3. **Mainnet Deployment**
   - Deploy contracts during low-traffic period
   - Verify contracts immediately
   - Deploy backend services with feature flags
   - Enable AA features for beta users only
   - Monitor system health and performance
   - Gradual rollout to all users

#### Post-deployment
- [ ] System health monitoring active
- [ ] Performance metrics being collected
- [ ] User feedback collection active
- [ ] Security monitoring active
- [ ] Documentation published and accessible
- [ ] Support team trained on AA features
- [ ] Incident response procedures activated

---

## DETAILED WEEKLY TASK BREAKDOWN (Hybrid Web2/Web3 Implementation)

### Week 1: Foundation Setup & Web2 Preservation
**Primary Goal**: Set up development environment while ensuring zero impact on existing Web2 authentication

#### Day 1-2: Environment Setup
- [ ] **Morning**: Set up Hardhat/Foundry development environment
- [ ] **Afternoon**: Configure network settings (Sepolia testnet)
- [ ] Install ERC-4337 dependencies and OpenZeppelin contracts
- [ ] Create git feature branch: `feature/hybrid-account-abstraction`
- [ ] **CRITICAL**: Verify all existing Web2 tests still pass

#### Day 3-4: Smart Contract Foundation
- [ ] **Morning**: Create basic `SmartAccount.sol` contract skeleton
- [ ] **Afternoon**: Implement `IAccount` interface with basic validateUserOp
- [ ] Add multi-signature support structure
- [ ] Write initial unit tests for signature validation
- [ ] **Evening**: Deploy test contracts to Sepolia

#### Day 5: Smart Account Factory
- [ ] **Morning**: Create `SmartAccountFactory.sol` with CREATE2 support
- [ ] **Afternoon**: Implement deterministic address calculation
- [ ] Add account registry for tracking deployed accounts
- [ ] Write factory unit tests
- [ ] **End of Day**: All smart contract tests passing

**Week 1 Deliverables**:
- ✅ Development environment fully configured
- ✅ Basic smart contracts deployed to testnet
- ✅ All existing Web2 functionality unchanged and tested
- ✅ Initial smart contract test suite

### Week 2: Paymaster Development & Web2 Integration Planning
**Primary Goal**: Complete smart contract development while planning Web2 integration

#### Day 1-2: Paymaster Contract
- [ ] **Morning**: Create `BlockAuthPaymaster.sol` contract
- [ ] **Afternoon**: Implement subscription validation logic
- [ ] Add gas credit system with plan tier support
- [ ] Implement usage tracking and rate limiting
- [ ] Write comprehensive paymaster tests

#### Day 3-4: Contract Integration Testing
- [ ] **Morning**: Write end-to-end smart contract integration tests
- [ ] **Afternoon**: Gas optimization analysis and improvements
- [ ] Deploy complete contract suite to testnet
- [ ] Verify all contracts on Etherscan
- [ ] **Evening**: Performance benchmarking

#### Day 5: Web2 Preservation Analysis
- [ ] **Morning**: Analyze existing Web2 authentication flows
- [ ] **Afternoon**: Design hybrid authentication architecture
- [ ] Create Web2 compatibility requirements document
- [ ] Plan database migration strategy (additive fields only)
- [ ] Design migration rollback procedures

**Week 2 Deliverables**:
- ✅ Complete smart contract suite deployed and verified
- ✅ Comprehensive test coverage (>95%)
- ✅ Web2 preservation strategy documented
- ✅ Migration plan with rollback procedures

### Week 3: Python Integration Layer - Web2 Compatible Models
**Primary Goal**: Extend Python models while maintaining full Web2 compatibility

#### Day 1-2: Enhanced User Model
- [ ] **Morning**: Create `AAUserMixin` with nullable/optional fields only
- [ ] **Afternoon**: Add migration tracking fields for Web2→Web3 transition
- [ ] Create database migration (must not affect existing users)
- [ ] **CRITICAL**: Verify existing Web2 authentication still works
- [ ] Add helper methods for account address calculation

#### Day 3-4: Web3 Infrastructure Components  
- [ ] **Morning**: Create `SmartAccountManager` class
- [ ] **Afternoon**: Implement `UserOperationBuilder` class
- [ ] Create `PaymasterManager` with subscription integration
- [ ] Add comprehensive error handling and Web2 fallbacks
- [ ] Write unit tests for all new components

#### Day 5: Migration Service Foundation
- [ ] **Morning**: Create `Web2ToWeb3MigrationService` skeleton
- [ ] **Afternoon**: Implement data preservation algorithms
- [ ] Add migration progress tracking
- [ ] Create migration validation and integrity checks
- [ ] **End of Day**: All Web2 tests still passing

**Week 3 Deliverables**:
- ✅ Extended user models with optional AA fields
- ✅ Core Web3 infrastructure components
- ✅ Migration service foundation
- ✅ 100% backward compatibility with Web2

### Week 4: Hybrid Authentication System
**Primary Goal**: Implement dual authentication system with Web2 as primary

#### Day 1-2: Authentication Router
- [ ] **Morning**: Create `HybridAuthenticationRouter` class
- [ ] **Afternoon**: Implement Web2-first authentication logic
- [ ] Add Web3 authentication as optional enhancement
- [ ] **CRITICAL**: Ensure Web2 authentication unchanged
- [ ] Add user preference detection logic

#### Day 3-4: Account Abstraction Authentication
- [ ] **Morning**: Create `AccountAbstractionAuthentication` class
- [ ] **Afternoon**: Implement UserOperation signature validation
- [ ] Add session key authentication support
- [ ] Implement Web2 fallback mechanisms
- [ ] Write comprehensive authentication tests

#### Day 5: Authentication Middleware
- [ ] **Morning**: Create hybrid authentication middleware
- [ ] **Afternoon**: Add feature flag system for gradual rollout
- [ ] Implement authentication method fallback chains
- [ ] Add comprehensive logging and monitoring
- [ ] **End of Day**: Integration testing complete

**Week 4 Deliverables**:
- ✅ Hybrid authentication system functional
- ✅ Web2 authentication preserved and primary
- ✅ Web3 authentication as opt-in enhancement
- ✅ Comprehensive fallback mechanisms

### Week 5: API Endpoints & Migration Tools
**Primary Goal**: Create migration APIs and user preference management

#### Day 1-2: Migration API Endpoints
- [ ] **Morning**: Create `Web2ToWeb3MigrationView`
- [ ] **Afternoon**: Implement `MigrationStatusView` and `MigrationRollbackView`
- [ ] Add comprehensive validation and error handling
- [ ] **CRITICAL**: Test data preservation during migration
- [ ] Add migration analytics and monitoring

#### Day 3-4: User Preference Management
- [ ] **Morning**: Create `AuthMethodPreferenceView`
- [ ] **Afternoon**: Implement smart account management endpoints (optional)
- [ ] Add user experience APIs for progressive disclosure
- [ ] Create unified API response format supporting both Web2/Web3
- [ ] Write API documentation with examples

#### Day 5: Bundler Integration
- [ ] **Morning**: Create `BundlerClient` class
- [ ] **Afternoon**: Implement multiple bundler fallbacks
- [ ] Add bundler health checks and monitoring
- [ ] Test user operation submission flows
- [ ] **End of Day**: Complete API integration testing

**Week 5 Deliverables**:
- ✅ Complete migration API suite
- ✅ User preference management system
- ✅ Bundler integration with fallbacks
- ✅ Comprehensive API documentation

### Week 6: Testing & Quality Assurance
**Primary Goal**: Comprehensive testing ensuring Web2 compatibility and security

#### Day 1-2: Integration Testing
- [ ] **Morning**: End-to-end testing of hybrid authentication flows
- [ ] **Afternoon**: Migration testing with real user data scenarios
- [ ] Test rollback procedures and data integrity
- [ ] **CRITICAL**: Verify Web2 performance not degraded
- [ ] Load testing with mixed Web2/Web3 users

#### Day 3-4: Security Testing
- [ ] **Morning**: Security audit of hybrid authentication system
- [ ] **Afternoon**: Penetration testing of migration endpoints
- [ ] Test authentication bypass attempts
- [ ] Validate audit logging across Web2/Web3 operations
- [ ] Review smart contract security (prepare for audit)

#### Day 5: User Acceptance Testing
- [ ] **Morning**: Test user migration scenarios end-to-end
- [ ] **Afternoon**: Validate user experience flows
- [ ] Test error handling and edge cases
- [ ] Performance benchmarking against targets
- [ ] **End of Day**: UAT sign-off and documentation complete

**Week 6 Deliverables**:
- ✅ Complete test coverage with security validation
- ✅ Performance benchmarks met
- ✅ User acceptance testing completed
- ✅ Security audit preparation complete

### Week 7: Documentation & Deployment Preparation
**Primary Goal**: Production readiness with comprehensive documentation

#### Day 1-2: Documentation Complete
- [ ] **Morning**: Update all API documentation with hybrid examples
- [ ] **Afternoon**: Create developer integration guide
- [ ] Document smart contract interactions and gas costs
- [ ] Create troubleshooting guide for hybrid authentication
- [ ] Write migration runbook for operations team

#### Day 3-4: Deployment Preparation
- [ ] **Morning**: Create infrastructure-as-code templates
- [ ] **Afternoon**: Set up monitoring and alerting systems
- [ ] Configure contract event monitoring
- [ ] Create deployment scripts for smart contracts
- [ ] **CRITICAL**: Test deployment on staging environment

#### Day 5: Production Deployment
- [ ] **Morning**: Deploy smart contracts to mainnet (if ready)
- [ ] **Afternoon**: Deploy backend services with feature flags OFF
- [ ] Configure production bundler services  
- [ ] Enable hybrid authentication for beta users only
- [ ] **End of Day**: Monitor system health and performance

**Week 7 Deliverables**:
- ✅ Complete documentation suite
- ✅ Production deployment infrastructure
- ✅ Monitoring and alerting systems
- ✅ Beta deployment with feature flags

### Week 8: Monitoring & Gradual Rollout
**Primary Goal**: Production stability and gradual feature activation

#### Day 1-2: System Monitoring
- [ ] **Morning**: Monitor system performance and error rates
- [ ] **Afternoon**: Analyze user behavior and adoption metrics
- [ ] Fine-tune performance based on real usage patterns
- [ ] **CRITICAL**: Ensure Web2 users unaffected
- [ ] Collect feedback from beta users

#### Day 3-4: Gradual Feature Rollout
- [ ] **Morning**: Enable migration features for 10% of users
- [ ] **Afternoon**: Monitor migration success rates and rollbacks
- [ ] Analyze gas costs and paymaster usage
- [ ] Optimize smart contract interactions based on real usage
- [ ] Address any issues discovered in production

#### Day 5: Full Feature Activation
- [ ] **Morning**: Enable hybrid authentication for all eligible users
- [ ] **Afternoon**: Monitor system performance under full load
- [ ] Document lessons learned and optimization opportunities
- [ ] Plan next iteration improvements
- [ ] **End of Day**: Production deployment complete

**Week 8 Deliverables**:
- ✅ Stable production system with hybrid authentication
- ✅ Successful gradual rollout completed
- ✅ Performance optimization based on real usage
- ✅ Complete monitoring and analytics pipeline

## CRITICAL SUCCESS METRICS

### Web2 Compatibility Metrics
- **100%** of existing Web2 authentication flows must continue working
- **0%** degradation in Web2 authentication performance
- **100%** data preservation during Web2→Web3 migration
- **100%** successful rollback capability from Web3 to Web2

### Migration Success Metrics
- **>95%** successful migration completion rate
- **<2 minutes** average migration time
- **0** data loss incidents during migration
- **>90%** user satisfaction with migration process

### System Performance Metrics
- **<500ms** API response time for all endpoints
- **>99.9%** uptime for authentication services
- **<2 seconds** end-to-end user operation processing
- **<50ms** additional latency for hybrid authentication

### User Experience Metrics
- **>80%** user retention after Web3 feature introduction
- **>60%** opt-in rate for Web3 features within 3 months
- **<5%** support tickets related to authentication confusion
- **>4.5/5** user satisfaction rating for hybrid system

This detailed weekly breakdown ensures systematic implementation while maintaining absolute backward compatibility with Web2 authentication systems.