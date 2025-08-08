# Hybrid Web2/Web3 Account Abstraction Implementation Plan for BlockAuth

## Overview

This document outlines the implementation plan for integrating Account Abstraction (ERC-4337) into the BlockAuth package as an **additive enhancement** to existing Web2 authentication, ensuring seamless migration and dual-authentication capabilities.

## CRITICAL DESIGN PRINCIPLE

**Account Abstraction is implemented as a HYBRID system where Web2 authentication remains the foundation and primary authentication method, with Web3 Account Abstraction serving as an optional, additive layer that users can opt into without losing their existing Web2 capabilities.**

### Hybrid Architecture Goals
- **Zero Breaking Changes**: All existing Web2 authentication flows remain unchanged
- **Seamless Migration**: Users can upgrade from Web2 to Web3 without data loss
- **Dual Authentication**: Support both Web2 and Web3 authentication simultaneously  
- **Progressive Enhancement**: Web3 features are opt-in enhancements, not replacements
- **Fallback Guarantee**: Web2 authentication always available as fallback

## Current Architecture Analysis

### Current Web2 Components
- **JWT Authentication**: Traditional token-based authentication (`authentication.py:20`)
- **Wallet Signature Verification**: Basic signature verification (`wallet.py:40`)
- **User Model**: Django-based user model with wallet address field (`user.py:19`)
- **Authentication Types**: Multiple auth methods (EMAIL, WALLET, GOOGLE, etc.) (`user.py:10`)

### Current Strengths to Preserve
1. **Robust Web2 Authentication**: JWT tokens work reliably for millions of users
2. **Multi-Authentication Support**: Email, social, wallet authentication already supported
3. **Proven Scalability**: Current system handles high load with low latency
4. **Enterprise Integration**: Existing SSO and compliance integrations
5. **User Experience**: Familiar authentication patterns users understand

### Enhancement Opportunities (Without Breaking Web2)
1. **Gas Sponsorship**: [Paymaster contracts](./PAYMASTER_INTEGRATION.md) for sponsored transactions (Web3 users only)
2. **Batch Operations**: [Signature Aggregation](./SIGNATURE_AGGREGATOR_INTEGRATION.md) for multiple operations in single transaction (Web3 enhancement)
3. **Smart Recovery**: Advanced recovery mechanisms via smart contracts (Web3 users only)
4. **Session Keys**: Temporary authentication for better UX (Web3 enhancement)
5. **Programmable Authentication**: Custom validation logic (Web3 advanced features)

## Hybrid Account Abstraction Architecture

### Core Components to Implement (ADDITIVE ONLY)

#### 1. Hybrid Authentication Router (CRITICAL COMPONENT)
```python
# Location: blockauth/authentication_hybrid.py
class HybridAuthenticationRouter:
    """
    Routes authentication between Web2 and Web3 based on user preferences.
    Web2 ALWAYS works and is the default. Web3 is an optional enhancement.
    """
    def authenticate(self, request):
        # 1. Try Web2 authentication first (preserve existing functionality)
        web2_result = self._authenticate_web2(request)
        if web2_result:
            return web2_result
        
        # 2. Try Web3 only for users who opted in
        if self._user_has_aa_enabled(request):
            return self._authenticate_web3(request)
        
        return None
```

#### 2. Migration Service (CRITICAL FOR DATA PRESERVATION)
```python
# Location: blockauth/services/migration.py
class Web2ToWeb3MigrationService:
    """
    Handles seamless migration from Web2 to Web3 while preserving all data.
    Ensures zero data loss and maintains Web2 fallback capability.
    """
    def initiate_migration(self, user_id):
        # Link Web3 smart account to existing Web2 user
        # Preserve all existing authentication methods
        # Enable dual authentication mode
        pass
    
    def rollback_migration(self, user_id):
        # Disable Web3 features, return to Web2-only
        # Preserve all user data and history
        pass
```

#### 3. Smart Account Factory Contract (WEB3 ENHANCEMENT)
```solidity
// Location: contracts/SmartAccountFactory.sol
contract SmartAccountFactory {
    // Deploys new smart accounts linked to existing Web2 users
    // Implements deterministic address generation using user_id
    // Handles initialization parameters from Web2 user data
    // CRITICAL: Links to existing BlockAuth user accounts
}
```

#### 4. Smart Account Contract (WEB3 ENHANCEMENT)
```solidity
// Location: contracts/SmartAccount.sol
contract SmartAccount {
    // Implements IAccount interface with Web2 fallback support
    // Custom validation logic that can verify Web2 JWT signatures
    // Multi-signature support for enhanced security
    // Recovery mechanisms that can fallback to Web2 email recovery
    // CRITICAL: Always allow Web2 authentication as fallback
}
```

#### 5. BlockAuth Paymaster Contract (WEB3 ENHANCEMENT)
See [Paymaster Integration Plan](./PAYMASTER_INTEGRATION.md) for more details.
```solidity
// Location: contracts/BlockAuthPaymaster.sol
contract BlockAuthPaymaster {
    // Sponsors gas fees for authenticated users
    // Integrates with subscription model
    // Implements fee validation logic
}
```

#### 4. Python Integration Layer

##### Smart Account Manager
```python
# Location: blockauth/utils/web3/smart_account.py
class SmartAccountManager:
    def __init__(self, entry_point_address, factory_address):
        # Initialize with EntryPoint and Factory contracts
        
    async def create_user_operation(self, user, call_data):
        # Create UserOperation for smart account
        
    async def execute_user_operation(self, user_op):
        # Submit UserOperation to bundler
        
    def get_smart_account_address(self, user_id):
        # Get deterministic smart account address
```

##### User Operation Builder
```python
# Location: blockauth/utils/web3/user_operation.py
class UserOperationBuilder:
    def build_user_op(self, sender, nonce, init_code, call_data, signature):
        # Build UserOperation structure
        
    def sign_user_operation(self, user_op, private_key):
        # Sign UserOperation
        
    def estimate_gas(self, user_op):
        # Estimate gas for UserOperation
```

#### 5. Enhanced Authentication System

##### Account Abstraction Authenticator
```python
# Location: blockauth/authentication_aa.py
class AccountAbstractionAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Verify UserOperation signature
        # Validate smart account ownership
        # Return user and validated operation
```

##### Smart Account User Model Extension
```python
# Location: blockauth/models/aa_user.py
class AAUserMixin(models.Model):
    smart_account_address = models.CharField(max_length=42, unique=True, null=True)
    account_salt = models.CharField(max_length=64, null=True)
    is_account_deployed = models.BooleanField(default=False)
    
    class Meta:
        abstract = True
        
    def get_smart_account_address(self):
        # Calculate deterministic address
        
    def deploy_smart_account(self):
        # Deploy smart account if not exists
```

## Advanced Features

### Signature Aggregation

For details on how BlockAuth can bundle multiple user operations into a single transaction, see the [Signature Aggregator Integration Plan](./SIGNATURE_AGGREGATOR_INTEGRATION.md).

## Implementation Phases

### Phase 1: Smart Contract Development
**Duration**: 2-3 weeks

1. **EntryPoint Integration**
   - Use existing EntryPoint contract or deploy custom one
   - Configure EntryPoint address in settings

2. **Smart Account Factory**
   - Implement factory pattern for account creation
   - Add deterministic address generation
   - Configure initialization parameters

3. **Smart Account Implementation**
   - Implement IAccount interface
   - Add custom validation logic
   - Support multiple authentication methods
   - Implement recovery mechanisms

4. **Paymaster Development**
   - Create subscription-based paymaster
   - Integrate with existing subscription microservice
   - Implement gas sponsorship logic

### Phase 2: Python Integration Layer
**Duration**: 2-3 weeks

1. **Web3 Infrastructure**
   - Add account abstraction utilities
   - Implement UserOperation handling
   - Create bundler integration

2. **Enhanced User Model**
   - Extend BlockUser with smart account fields
   - Add account deployment tracking
   - Implement address calculation

3. **Authentication System**
   - Create AA-based authentication class
   - Implement UserOperation validation
   - Maintain backward compatibility

### Phase 3: API Endpoints Enhancement
**Duration**: 1-2 weeks

1. **Smart Account Management**
   - Account creation endpoint
   - Account deployment endpoint
   - Account recovery endpoints

2. **User Operations**
   - Batch transaction endpoint
   - Operation status tracking
   - Gas estimation endpoint

3. **Subscription Integration**
   - Paymaster configuration
   - Subscription validation
   - Gas credit management

### Phase 4: Migration and Testing
**Duration**: 2 weeks

1. **Migration Strategy**
   - Gradual rollout plan
   - Legacy system compatibility
   - Data migration scripts

2. **Testing Framework**
   - Unit tests for all components
   - Integration tests with blockchain
   - Load testing for bundler operations

## Subscription Module Integration

### Architecture Overview
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Auth-Pack      │    │  Subscription    │    │  Smart Contracts│
│  (This Repo)    │    │  Microservice    │    │  (Blockchain)   │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • AA Auth       │───▶│ • Plan Validation│───▶│ • Paymaster     │
│ • Smart Account │    │ • Gas Credits    │    │ • EntryPoint    │
│ • UserOp Builder│    │ • Usage Tracking │    │ • Smart Account │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Integration Points

1. **Paymaster Configuration**
   ```python
   # blockauth/utils/web3/paymaster.py
   class SubscriptionPaymaster:
       async def validate_subscription(self, user_id, operation_cost):
           # Call subscription service to validate plan
           # Check gas credits availability
           # Return validation result
   ```

2. **Gas Credit System**
   - Track gas usage per user operation
   - Deduct credits from subscription balance
   - Handle subscription tier limitations

3. **Plan-Based Features**
   - Free tier: Basic smart account features
   - Premium tier: Gas sponsorship, batch operations
   - Enterprise tier: Custom paymaster, priority bundling

## User Flow Diagram

### Current Web2 Flow
```
User Wallet → Sign Message → Verify Signature → Issue JWT → API Access
```

### New Web3 Account Abstraction Flow
```
User Intent → Create UserOperation → Smart Account Validation → 
Paymaster Check → Bundler Submission → Blockchain Execution → 
Result Confirmation
```

## Benefits of Implementation

### For Users
- **Gasless Transactions**: Paymaster handles gas fees
- **Batch Operations**: Multiple actions in single transaction
- **Enhanced Security**: Smart contract-based validation
- **Recovery Options**: Social recovery, multi-sig support
- **Better UX**: No need to hold ETH for gas

### For Developers
- **Flexible Authentication**: Custom validation logic
- **Programmable Accounts**: Smart contract capabilities
- **Subscription Integration**: Built-in monetization
- **Scalability**: Reduced on-chain footprint
- **Future-Proof**: ERC-4337 standard compliance

## Technical Considerations

### Security
- Multi-signature validation for sensitive operations
- Time-locked recovery mechanisms
- Rate limiting for operations
- Secure key management for paymaster

### Performance
- Efficient UserOperation batching
- Optimized gas estimation
- Bundler selection strategies
- Caching for repeated operations

### Monitoring
- UserOperation success rates
- Gas usage analytics
- Paymaster balance tracking
- Subscription usage metrics

## Migration Strategy

### Backward Compatibility
- Maintain existing JWT authentication
- Gradual user migration to smart accounts
- Dual authentication support during transition

### Rollout Plan
1. **Testnet Deployment** (Week 1-2)
2. **Limited Beta** (Week 3-4) 
3. **Gradual Rollout** (Week 5-8)
4. **Full Migration** (Week 9-12)

## Cost Analysis

### Development Costs
- Smart contract development: ~40 hours
- Python integration: ~60 hours
- Testing and deployment: ~30 hours
- Documentation: ~10 hours

### Operational Costs
- Gas costs for paymaster operations
- Bundler service costs
- Blockchain node infrastructure
- Monitoring and analytics tools

## Success Metrics

### Technical Metrics
- UserOperation success rate > 95%
- Average gas savings per user > 50%
- Transaction confirmation time < 30 seconds
- System uptime > 99.9%

### Business Metrics
- User adoption of AA features > 60%
- Subscription conversion rate increase > 25%
- Support ticket reduction > 40%
- User satisfaction score > 4.5/5

## Next Steps

1. **Smart Contract Architecture Review**
   - Finalize contract specifications
   - Security audit planning
   - Testnet deployment strategy

2. **Infrastructure Setup**
   - Bundler service selection
   - Blockchain node configuration
   - Monitoring system setup

3. **Development Team Coordination**
   - Resource allocation
   - Timeline establishment
   - Integration with subscription service

4. **Risk Assessment**
   - Identify potential blockers
   - Mitigation strategies
   - Fallback plans

This implementation will position BlockAuth as a leading Web3 authentication solution while maintaining compatibility with existing systems and providing a smooth migration path for users.

## Detailed Technical Specifications

### Smart Contract Interfaces

#### IAccount Interface Implementation
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

interface ISmartAccount is IAccount {
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }
    
    event AccountInitialized(address indexed account, address[] owners);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event RecoveryInitiated(address indexed newOwner, uint256 executeAfter);
    event RecoveryExecuted(address indexed newOwner);
    
    function initialize(address[] memory _owners, uint256 _threshold) external;
    function addOwner(address owner) external;
    function removeOwner(address owner) external;
    function changeThreshold(uint256 newThreshold) external;
    function getOwners() external view returns (address[] memory);
    function isOwner(address owner) external view returns (bool);
    function getThreshold() external view returns (uint256);
}
```

#### Factory Interface
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ISmartAccountFactory {
    event AccountCreated(address indexed account, address indexed owner, uint256 salt);
    
    function createAccount(
        address[] memory owners,
        uint256 threshold,
        uint256 salt
    ) external returns (address account);
    
    function getAddress(
        address[] memory owners,
        uint256 threshold,
        uint256 salt
    ) external view returns (address);
    
    function accountImplementation() external view returns (address);
}
```

#### Paymaster Interface
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/interfaces/IPaymaster.sol";

interface IBlockAuthPaymaster is IPaymaster {
    struct PaymasterData {
        address subscriber;
        uint256 validUntil;
        uint256 validAfter;
        uint256 maxCost;
        bytes signature;
    }
    
    event GasSponsored(address indexed account, uint256 actualGasCost);
    event SubscriptionValidated(address indexed subscriber, uint256 planTier);
    
    function validateSubscription(
        address subscriber,
        uint256 maxCost
    ) external view returns (bool valid, uint256 planTier);
    
    function addDeposit() external payable;
    function withdrawDeposit(address payable withdrawAddress, uint256 amount) external;
}
```

### Python Class Specifications

#### Enhanced User Model Schema
```python
# blockauth/models/aa_user.py
from django.db import models
from django.contrib.postgres.fields import ArrayField
import json

class AAUserMixin(models.Model):
    """Account Abstraction User Mixin for extending existing user models"""
    
    # Smart Account Fields
    smart_account_address = models.CharField(
        max_length=42, 
        unique=True, 
        null=True, 
        blank=True,
        db_index=True,
        help_text="The deployed smart account address"
    )
    
    account_salt = models.CharField(
        max_length=64, 
        null=True, 
        blank=True,
        help_text="Salt used for deterministic address generation"
    )
    
    is_account_deployed = models.BooleanField(
        default=False,
        help_text="Whether the smart account has been deployed on-chain"
    )
    
    account_owners = models.JSONField(
        default=list,
        help_text="List of owner addresses for multi-sig functionality"
    )
    
    signature_threshold = models.PositiveIntegerField(
        default=1,
        help_text="Number of signatures required for transactions"
    )
    
    recovery_addresses = models.JSONField(
        default=list,
        help_text="List of recovery guardian addresses"
    )
    
    session_keys = models.JSONField(
        default=list,
        help_text="Active session keys with their permissions and expiry"
    )
    
    # Operational Fields
    account_nonce = models.BigIntegerField(
        default=0,
        help_text="Current nonce for the smart account"
    )
    
    gas_credits_balance = models.DecimalField(
        max_digits=20,
        decimal_places=8,
        default=0,
        help_text="Available gas credits for sponsored transactions"
    )
    
    last_operation_hash = models.CharField(
        max_length=66,
        null=True,
        blank=True,
        help_text="Hash of the last user operation"
    )
    
    # Metadata
    aa_enabled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When Account Abstraction was enabled for this user"
    )
    
    account_version = models.CharField(
        max_length=10,
        default="1.0.0",
        help_text="Version of the smart account implementation"
    )
    
    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['smart_account_address']),
            models.Index(fields=['is_account_deployed']),
            models.Index(fields=['aa_enabled_at']),
        ]
    
    def get_smart_account_address(self, factory_address: str, owners: list, threshold: int, salt: int) -> str:
        """Calculate deterministic smart account address"""
        from blockauth.utils.web3.smart_account import SmartAccountManager
        manager = SmartAccountManager()
        return manager.calculate_address(factory_address, owners, threshold, salt)
    
    def is_smart_account_owner(self, address: str) -> bool:
        """Check if address is an owner of the smart account"""
        return address.lower() in [owner.lower() for owner in self.account_owners]
    
    def get_active_session_keys(self) -> list:
        """Get currently active session keys"""
        import time
        current_time = int(time.time())
        return [
            key for key in self.session_keys 
            if key.get('expires_at', 0) > current_time
        ]
```

#### Web3 Infrastructure Classes

```python
# blockauth/utils/web3/types.py
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from eth_typing import Address, HexStr

@dataclass
class UserOperation:
    """UserOperation structure matching ERC-4337 specification"""
    sender: Address
    nonce: int
    initCode: HexStr
    callData: HexStr
    callGasLimit: int
    verificationGasLimit: int
    preVerificationGas: int
    maxFeePerGas: int
    maxPriorityFeePerGas: int
    paymasterAndData: HexStr
    signature: HexStr
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'sender': self.sender,
            'nonce': hex(self.nonce),
            'initCode': self.initCode,
            'callData': self.callData,
            'callGasLimit': hex(self.callGasLimit),
            'verificationGasLimit': hex(self.verificationGasLimit),
            'preVerificationGas': hex(self.preVerificationGas),
            'maxFeePerGas': hex(self.maxFeePerGas),
            'maxPriorityFeePerGas': hex(self.maxPriorityFeePerGas),
            'paymasterAndData': self.paymasterAndData,
            'signature': self.signature,
        }

@dataclass
class GasEstimate:
    """Gas estimation for user operations"""
    callGasLimit: int
    verificationGasLimit: int
    preVerificationGas: int
    maxFeePerGas: int
    maxPriorityFeePerGas: int
    
@dataclass
class BundlerResponse:
    """Standardized bundler response"""
    userOpHash: str
    success: bool
    error: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = None
```

### Configuration Schema

```python
# blockauth/conf/aa_settings.py
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class NetworkConfig:
    """Network-specific configuration"""
    name: str
    rpc_url: str
    chain_id: int
    entry_point_address: str
    factory_address: str
    paymaster_address: str
    bundler_urls: List[str]
    explorer_url: str
    
@dataclass
class GasLimits:
    """Default gas limits for operations"""
    call_gas_limit: int = 200000
    verification_gas_limit: int = 700000
    pre_verification_gas: int = 21000
    
@dataclass
class SubscriptionTier:
    """Subscription tier configuration"""
    name: str
    max_operations_per_day: int
    max_gas_per_operation: int
    sponsored_gas: bool
    batch_operations: bool
    priority_bundling: bool
    custom_paymaster: bool
    
class AASettings:
    """Account Abstraction Settings"""
    
    NETWORKS: Dict[str, NetworkConfig] = {
        'sepolia': NetworkConfig(
            name='Sepolia Testnet',
            rpc_url='https://sepolia.infura.io/v3/{api_key}',
            chain_id=11155111,
            entry_point_address='0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
            factory_address='0x...',  # To be deployed
            paymaster_address='0x...',  # To be deployed
            bundler_urls=['https://bundler.biconomy.io', 'https://api.stackup.sh'],
            explorer_url='https://sepolia.etherscan.io'
        ),
        'mainnet': NetworkConfig(
            name='Ethereum Mainnet',
            rpc_url='https://mainnet.infura.io/v3/{api_key}',
            chain_id=1,
            entry_point_address='0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
            factory_address='0x...',  # To be deployed
            paymaster_address='0x...',  # To be deployed
            bundler_urls=['https://bundler.biconomy.io', 'https://api.stackup.sh'],
            explorer_url='https://etherscan.io'
        )
    }
    
    SUBSCRIPTION_TIERS: Dict[str, SubscriptionTier] = {
        'free': SubscriptionTier(
            name='Free Tier',
            max_operations_per_day=10,
            max_gas_per_operation=100000,
            sponsored_gas=False,
            batch_operations=False,
            priority_bundling=False,
            custom_paymaster=False
        ),
        'premium': SubscriptionTier(
            name='Premium Tier',
            max_operations_per_day=1000,
            max_gas_per_operation=500000,
            sponsored_gas=True,
            batch_operations=True,
            priority_bundling=False,
            custom_paymaster=False
        ),
        'enterprise': SubscriptionTier(
            name='Enterprise Tier',
            max_operations_per_day=-1,  # Unlimited
            max_gas_per_operation=2000000,
            sponsored_gas=True,
            batch_operations=True,
            priority_bundling=True,
            custom_paymaster=True
        )
    }
    
    DEFAULT_GAS_LIMITS = GasLimits()
    
    # Security Settings
    MAX_SESSION_KEY_DURATION = 86400 * 7  # 7 days
    RECOVERY_TIME_LOCK = 86400 * 2  # 2 days
    MAX_OWNERS = 10
    MAX_BATCH_SIZE = 10
    
    # Rate Limiting
    RATE_LIMIT_WINDOW = 3600  # 1 hour
    RATE_LIMIT_FREE_TIER = 10
    RATE_LIMIT_PREMIUM_TIER = 100
    RATE_LIMIT_ENTERPRISE_TIER = 1000
```

## Error Handling and Recovery

### Error Classification

```python
# blockauth/utils/aa_exceptions.py
class AAException(Exception):
    """Base exception for Account Abstraction operations"""
    pass

class SmartAccountNotDeployedException(AAException):
    """Smart account has not been deployed yet"""
    pass

class InsufficientGasCreditsException(AAException):
    """User has insufficient gas credits for operation"""
    pass

class InvalidSignatureException(AAException):
    """UserOperation signature validation failed"""
    pass

class BundlerException(AAException):
    """Bundler service error"""
    pass

class PaymasterRejectionException(AAException):
    """Paymaster rejected the operation"""
    pass

class SubscriptionExpiredException(AAException):
    """User subscription has expired"""
    pass

class RateLimitExceededException(AAException):
    """Rate limit exceeded for user tier"""
    pass
```

### Recovery Strategies

```python
# blockauth/utils/web3/recovery.py
class RecoveryManager:
    """Manages account recovery operations"""
    
    def initiate_recovery(self, user_id: str, new_owner: str, guardians: List[str]) -> str:
        """Initiate account recovery process"""
        # 1. Validate guardian signatures
        # 2. Create time-locked recovery transaction
        # 3. Store recovery state
        # 4. Emit recovery event
        pass
    
    def execute_recovery(self, user_id: str, recovery_id: str) -> bool:
        """Execute a time-locked recovery"""
        # 1. Validate time-lock expiry
        # 2. Execute ownership change
        # 3. Update user model
        # 4. Invalidate old session keys
        pass
    
    def cancel_recovery(self, user_id: str, recovery_id: str) -> bool:
        """Cancel pending recovery"""
        # 1. Validate current owner
        # 2. Cancel recovery transaction
        # 3. Update recovery state
        pass
```

## Monitoring and Observability

### Metrics Collection

```python
# blockauth/utils/aa_metrics.py
from prometheus_client import Counter, Histogram, Gauge
from typing import Dict, Any

# Operation Metrics
user_operations_total = Counter(
    'aa_user_operations_total',
    'Total number of user operations',
    ['status', 'operation_type', 'user_tier']
)

user_operation_duration = Histogram(
    'aa_user_operation_duration_seconds',
    'Time spent processing user operations',
    ['operation_type']
)

gas_usage_total = Counter(
    'aa_gas_usage_total',
    'Total gas used for operations',
    ['sponsored']
)

# Bundler Metrics
bundler_requests_total = Counter(
    'aa_bundler_requests_total',
    'Total bundler requests',
    ['bundler', 'status']
)

bundler_response_time = Histogram(
    'aa_bundler_response_time_seconds',
    'Bundler response time',
    ['bundler']
)

# Account Metrics
smart_accounts_deployed = Gauge(
    'aa_smart_accounts_deployed',
    'Number of deployed smart accounts'
)

active_session_keys = Gauge(
    'aa_active_session_keys',
    'Number of active session keys'
)

class AAMetrics:
    """Account Abstraction metrics collector"""
    
    @staticmethod
    def record_user_operation(operation_type: str, status: str, user_tier: str, duration: float):
        user_operations_total.labels(status=status, operation_type=operation_type, user_tier=user_tier).inc()
        user_operation_duration.labels(operation_type=operation_type).observe(duration)
    
    @staticmethod
    def record_gas_usage(gas_amount: int, sponsored: bool):
        gas_usage_total.labels(sponsored=str(sponsored).lower()).inc(gas_amount)
    
    @staticmethod
    def record_bundler_request(bundler: str, status: str, response_time: float):
        bundler_requests_total.labels(bundler=bundler, status=status).inc()
        bundler_response_time.labels(bundler=bundler).observe(response_time)
```

### Health Checks

```python
# blockauth/utils/aa_health.py
from typing import Dict, Any, List
import asyncio
from web3 import Web3

class AAHealthChecker:
    """Health checker for Account Abstraction infrastructure"""
    
    async def check_bundler_health(self, bundler_urls: List[str]) -> Dict[str, Any]:
        """Check bundler service health"""
        results = {}
        for url in bundler_urls:
            try:
                # Check bundler endpoint
                results[url] = {'status': 'healthy', 'response_time': 0.1}
            except Exception as e:
                results[url] = {'status': 'unhealthy', 'error': str(e)}
        return results
    
    async def check_contract_health(self, web3: Web3, contracts: Dict[str, str]) -> Dict[str, Any]:
        """Check smart contract health"""
        results = {}
        for name, address in contracts.items():
            try:
                # Check contract exists and is responsive
                code = web3.eth.get_code(address)
                if code != '0x':
                    results[name] = {'status': 'healthy', 'address': address}
                else:
                    results[name] = {'status': 'unhealthy', 'error': 'No code at address'}
            except Exception as e:
                results[name] = {'status': 'unhealthy', 'error': str(e)}
        return results
    
    async def check_paymaster_balance(self, web3: Web3, paymaster_address: str) -> Dict[str, Any]:
        """Check paymaster has sufficient balance"""
        try:
            balance = web3.eth.get_balance(paymaster_address)
            min_balance = web3.to_wei(0.1, 'ether')  # Minimum 0.1 ETH
            
            return {
                'status': 'healthy' if balance > min_balance else 'warning',
                'balance_wei': balance,
                'balance_eth': web3.from_wei(balance, 'ether'),
                'minimum_eth': web3.from_wei(min_balance, 'ether')
            }
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}
```

## Testing Strategy

### Contract Testing Framework

```javascript
// test/SmartAccount.test.js
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

describe("SmartAccount", function () {
  async function deploySmartAccountFixture() {
    const [owner1, owner2, owner3, attacker] = await ethers.getSigners();
    
    // Deploy EntryPoint
    const EntryPoint = await ethers.getContractFactory("EntryPoint");
    const entryPoint = await EntryPoint.deploy();
    
    // Deploy SmartAccount implementation
    const SmartAccount = await ethers.getContractFactory("SmartAccount");
    const accountImpl = await SmartAccount.deploy(entryPoint.target);
    
    // Deploy Factory
    const SmartAccountFactory = await ethers.getContractFactory("SmartAccountFactory");
    const factory = await SmartAccountFactory.deploy(accountImpl.target);
    
    return {
      entryPoint,
      accountImpl,
      factory,
      owner1,
      owner2,
      owner3,
      attacker
    };
  }
  
  describe("Account Creation", function () {
    it("Should create account with deterministic address", async function () {
      const { factory, owner1 } = await loadFixture(deploySmartAccountFixture);
      
      const owners = [owner1.address];
      const threshold = 1;
      const salt = 12345;
      
      const predictedAddress = await factory.getAddress(owners, threshold, salt);
      const tx = await factory.createAccount(owners, threshold, salt);
      
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => log.topics[0] === factory.interface.getEvent('AccountCreated').topicHash);
      const createdAddress = ethers.getAddress('0x' + event.topics[1].slice(26));
      
      expect(createdAddress).to.equal(predictedAddress);
    });
  });
  
  describe("Multi-Signature Operations", function () {
    it("Should require threshold signatures", async function () {
      // Test multi-sig functionality
    });
  });
  
  describe("Recovery Mechanisms", function () {
    it("Should allow time-locked recovery", async function () {
      // Test recovery functionality
    });
  });
});
```

### Python Integration Tests

```python
# tests/test_aa_integration.py
import pytest
import asyncio
from unittest.mock import Mock, patch
from blockauth.utils.web3.smart_account import SmartAccountManager
from blockauth.utils.web3.user_operation import UserOperationBuilder
from blockauth.models.user import BlockUser

class TestAAIntegration:
    """Integration tests for Account Abstraction"""
    
    @pytest.fixture
    def mock_user(self):
        user = Mock(spec=BlockUser)
        user.id = "test-user-123"
        user.smart_account_address = None
        user.is_account_deployed = False
        user.account_owners = []
        return user
    
    @pytest.fixture
    def smart_account_manager(self):
        return SmartAccountManager(
            web3_provider="http://localhost:8545",
            factory_address="0x1234567890123456789012345678901234567890",
            entry_point_address="0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
        )
    
    @pytest.mark.asyncio
    async def test_account_creation_flow(self, mock_user, smart_account_manager):
        """Test complete account creation flow"""
        # 1. Calculate deterministic address
        owners = ["0xowner1", "0xowner2"]
        threshold = 2
        salt = 12345
        
        predicted_address = smart_account_manager.get_smart_account_address(
            mock_user.id, owners, threshold, salt
        )
        
        # 2. Deploy account
        with patch.object(smart_account_manager, '_deploy_account') as mock_deploy:
            mock_deploy.return_value = predicted_address
            
            deployed_address = await smart_account_manager.deploy_smart_account(
                mock_user.id, owners, threshold
            )
            
            assert deployed_address == predicted_address
    
    @pytest.mark.asyncio
    async def test_user_operation_flow(self, mock_user, smart_account_manager):
        """Test user operation creation and submission"""
        builder = UserOperationBuilder()
        
        # Create user operation
        user_op = builder.build_user_op(
            sender="0x1234567890123456789012345678901234567890",
            nonce=0,
            call_data="0x",
            signature="0x"
        )
        
        assert user_op.sender == "0x1234567890123456789012345678901234567890"
        assert user_op.nonce == 0
    
    def test_subscription_validation(self):
        """Test subscription tier validation"""
        from blockauth.utils.web3.paymaster import PaymasterManager
        
        paymaster = PaymasterManager()
        
        # Test free tier limits
        is_valid = paymaster.validate_subscription(
            user_id="test-user",
            operation_cost=50000,
            user_tier="free"
        )
        
        assert is_valid is False  # Free tier doesn't sponsor gas
```

## Performance Optimizations

### Gas Optimization Strategies

1. **Batch Operations**: Combine multiple operations into single UserOperation
2. **Signature Aggregation**: Use BLS signatures for multiple operations
3. **Storage Optimization**: Use packed structs and minimal storage
4. **Proxy Patterns**: Use minimal proxy for account deployment
5. **Precomputed Addresses**: Cache deterministic addresses

### Caching Strategy

```python
# blockauth/utils/aa_cache.py
from django.core.cache import cache
from typing import Optional, Dict, Any
import json

class AACache:
    """Caching layer for Account Abstraction operations"""
    
    CACHE_TIMEOUTS = {
        'user_operation': 300,  # 5 minutes
        'gas_estimate': 60,     # 1 minute
        'account_address': 3600, # 1 hour
        'subscription_status': 300, # 5 minutes
    }
    
    @staticmethod
    def get_user_operation(user_id: str, op_hash: str) -> Optional[Dict[str, Any]]:
        key = f"aa:userop:{user_id}:{op_hash}"
        cached = cache.get(key)
        return json.loads(cached) if cached else None
    
    @staticmethod
    def set_user_operation(user_id: str, op_hash: str, operation: Dict[str, Any]):
        key = f"aa:userop:{user_id}:{op_hash}"
        cache.set(key, json.dumps(operation), AACache.CACHE_TIMEOUTS['user_operation'])
    
    @staticmethod
    def get_gas_estimate(operation_hash: str) -> Optional[Dict[str, Any]]:
        key = f"aa:gas:{operation_hash}"
        cached = cache.get(key)
        return json.loads(cached) if cached else None
    
    @staticmethod
    def set_gas_estimate(operation_hash: str, estimate: Dict[str, Any]):
        key = f"aa:gas:{operation_hash}"
        cache.set(key, json.dumps(estimate), AACache.CACHE_TIMEOUTS['gas_estimate'])
```

This implementation will position BlockAuth as a leading Web3 authentication solution while maintaining compatibility with existing systems and providing a smooth migration path for users.