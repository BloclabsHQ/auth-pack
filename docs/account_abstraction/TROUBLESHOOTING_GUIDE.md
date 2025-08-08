# BlockAuth Hybrid Web2/Web3 Account Abstraction Troubleshooting Guide

## Overview

This guide provides solutions to common issues encountered when implementing, deploying, and operating the BlockAuth **Hybrid Account Abstraction** system, with special focus on maintaining Web2 authentication integrity during Web3 integration.

## CRITICAL TROUBLESHOOTING PRINCIPLE

**When troubleshooting any Account Abstraction issues, ALWAYS ensure Web2 authentication remains functional. If Web3 features cause any disruption to Web2 users, immediately rollback to Web2-only mode while investigating.**

### Emergency Procedures
1. **Web2 Protection First**: If any AA issues affect Web2 authentication, disable AA features immediately
2. **User Impact Assessment**: Prioritize issues that affect existing Web2 users over Web3-only problems
3. **Rollback Readiness**: Have rollback procedures ready to disable Web3 features instantly
4. **Data Integrity**: Always verify that troubleshooting steps preserve user data and authentication history

## Hybrid Authentication Issues (MOST CRITICAL)

### 1. Web2 Authentication Stopped Working After AA Deployment

**Issue:** Existing Web2 users cannot authenticate after Account Abstraction deployment
```
Error: JWT authentication failing for existing users
Status: 401 Unauthorized
```

**EMERGENCY SOLUTION (IMMEDIATE):**
```python
# 1. Disable AA features immediately
BLOCK_AUTH_SETTINGS = {
    'FEATURES': {
        # Disable AA features to restore Web2 functionality
        'ACCOUNT_ABSTRACTION': False,  
        'WEB3_MIGRATION': False,
        
        # Ensure all Web2 features remain enabled
        'BASIC_LOGIN': True,
        'PASSWORDLESS_LOGIN': True,
        'SOCIAL_AUTH': True,
        # ... all other Web2 features
    }
}

# 2. Force Web2 authentication only
AUTHENTICATION_CLASSES = [
    'blockauth.authentication.JWTAuthentication',  # Original Web2 auth only
    # Remove: 'blockauth.authentication_hybrid.HybridAuthenticationRouter',
]
```

**Root Cause Investigation:**
```python
# Check if hybrid router is incorrectly blocking Web2 auth
def debug_authentication_failure(request):
    # Test Web2 authentication directly
    web2_auth = JWTAuthentication()
    result = web2_auth.authenticate(request)
    if not result:
        print("Web2 authentication failed - check JWT token validity")
    
    # Check if AA migration corrupted user data
    user = get_user_model().objects.get(id=user_id)
    print(f"User AA fields: {user.is_aa_enabled}, {user.preferred_auth_method}")
    if user.preferred_auth_method == 'WEB3' and not user.is_aa_enabled:
        # Fix corrupted state - reset to Web2
        user.preferred_auth_method = 'WEB2'
        user.is_aa_enabled = False
        user.save()
```

### 2. Migration Process Corrupted User Data

**Issue:** Users lost access during Web2→Web3 migration
```
Error: User data inconsistent after migration
Migration status: Failed
```

**EMERGENCY SOLUTION:**
```python
# Rollback migration for affected users
class EmergencyMigrationRollback:
    def rollback_user_migration(self, user_id):
        user = get_user_model().objects.get(id=user_id)
        
        # Restore Web2-only state
        user.is_aa_enabled = False
        user.preferred_auth_method = 'WEB2'
        user.smart_account_address = None
        user.migration_timestamp = None
        user.migrated_from_web2 = False
        user.web2_backup_enabled = True
        
        # Preserve all Web2 authentication data
        # (email, password hash, social auth tokens, etc. should be untouched)
        
        user.save()
        
        # Log rollback for audit
        logger.info(f"Emergency rollback completed for user {user_id}")
```

### 3. Hybrid Authentication Router Errors

**Issue:** Authentication router causing performance degradation
```
Error: Timeout in hybrid authentication
Response time: >5 seconds (should be <500ms)
```

**SOLUTION:**
```python
# Optimize authentication router with caching and timeouts
class OptimizedHybridAuthenticationRouter:
    def __init__(self):
        self.web2_cache = {}  # Cache Web2 auth results briefly
        self.timeout = 0.5  # Max 500ms for authentication
    
    def authenticate(self, request):
        start_time = time.time()
        
        # Always try Web2 first with timeout
        try:
            with timeout(self.timeout):
                web2_result = self._authenticate_web2_fast(request)
                if web2_result:
                    return web2_result
        except TimeoutError:
            logger.warning("Web2 auth timeout - investigate performance")
            return None  # Fail fast to avoid blocking
        
        # Check timeout before trying Web3
        elapsed = time.time() - start_time
        if elapsed > self.timeout / 2:
            return None  # Don't risk Web3 auth if Web2 already slow
        
        # Try Web3 only if time remaining and user opted in
        if self._user_has_aa_enabled_cached(request):
            with timeout(self.timeout - elapsed):
                return self._authenticate_web3(request)
```

## Common Issues and Solutions

### Smart Contract Issues

#### 1. Contract Deployment Failures

**Issue:** Contract deployment fails with "out of gas" error
```
Error: Transaction reverted: function call ran out of gas
```

**Solution:**
```javascript
// Increase gas limit in deployment script
const smartAccount = await SmartAccount.deploy(entryPointAddress, {
  gasLimit: 8000000  // Increase from default
});

// Or use gas estimation
const gasEstimate = await SmartAccount.signer.estimateGas.deploy(entryPointAddress);
const smartAccount = await SmartAccount.deploy(entryPointAddress, {
  gasLimit: gasEstimate.mul(120).div(100)  // Add 20% buffer
});
```

**Issue:** Contract verification fails on Etherscan
```
Error: Contract source code already verified
```

**Solution:**
```bash
# Use different constructor args or check if already verified
npx hardhat verify --network sepolia DEPLOYED_CONTRACT_ADDRESS "constructor_arg1"

# For proxy contracts, verify implementation separately
npx hardhat verify --network sepolia IMPLEMENTATION_ADDRESS
```

#### 2. UserOperation Validation Failures

**Issue:** UserOperation fails with "AA23 reverted (or OOG)"
```
Error: AA23 reverted (or OOG)
```

**Diagnosis:**
```solidity
// Add debug logging to validateUserOp
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external override returns (uint256 validationData) {
    require(_validateSignature(userOp, userOpHash), "Invalid signature");
    // Add more specific error messages
    _payPrefund(missingAccountFunds);
    return 0;
}
```

**Solution:**
- Check signature validation logic
- Verify account has sufficient balance for prefund
- Ensure correct nonce is used
- Validate gas limits are sufficient

#### 3. Paymaster Rejection Issues

**Issue:** Paymaster rejects operations with "AA33 reverted"
```
Error: AA33 reverted: paymaster validation failed
```

**Solution:**
```python
# Check paymaster validation in Python
def validate_paymaster_operation(self, user_operation, max_cost):
    # Verify subscription status
    subscription = self.get_user_subscription(user_operation.sender)
    if not subscription.is_active:
        raise PaymasterRejectionException("Subscription expired")
    
    # Check gas credits
    if subscription.gas_credits < max_cost:
        raise PaymasterRejectionException("Insufficient gas credits")
    
    # Validate operation limits
    daily_ops = self.get_daily_operation_count(user_operation.sender)
    if daily_ops >= subscription.daily_limit:
        raise PaymasterRejectionException("Daily operation limit exceeded")
    
    return True
```

### Python/Django Issues

#### 1. Web3 Connection Errors

**Issue:** Cannot connect to Ethereum node
```
ConnectionError: HTTPSConnectionPool(host='mainnet.infura.io', port=443)
```

**Solution:**
```python
# Add connection retry logic
from web3 import Web3
import time
import requests.adapters

def create_web3_connection(rpc_url, max_retries=3):
    for attempt in range(max_retries):
        try:
            # Configure session with retries
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                max_retries=requests.adapters.Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504]
                )
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            
            web3 = Web3(Web3.HTTPProvider(rpc_url, session=session))
            
            if web3.isConnected():
                return web3
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)  # Exponential backoff
    
    raise ConnectionError("Failed to connect to Ethereum node")
```

#### 2. Database Migration Issues

**Issue:** Migration fails with foreign key constraint
```
django.db.utils.IntegrityError: FOREIGN KEY constraint failed
```

**Solution:**
```python
# Create data migration to handle existing users
# migrations/0002_migrate_existing_users.py
from django.db import migrations

def migrate_existing_users(apps, schema_editor):
    BlockUser = apps.get_model('blockauth', 'BlockUser')
    
    for user in BlockUser.objects.all():
        # Initialize AA fields for existing users
        user.smart_account_address = None
        user.is_account_deployed = False
        user.account_owners = []
        user.signature_threshold = 1
        user.save()

def reverse_migration(apps, schema_editor):
    pass

class Migration(migrations.Migration):
    dependencies = [
        ('blockauth', '0001_initial'),
    ]
    
    operations = [
        migrations.RunPython(migrate_existing_users, reverse_migration),
    ]
```

#### 3. Serialization Errors

**Issue:** Cannot serialize UserOperation to JSON
```
TypeError: Object of type 'HexBytes' is not JSON serializable
```

**Solution:**
```python
import json
from web3 import Web3

class UserOperationEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

# Usage
user_op_json = json.dumps(user_operation, cls=UserOperationEncoder)

# Or convert HexBytes to string
def serialize_user_operation(user_op):
    return {
        'sender': user_op.sender,
        'nonce': hex(user_op.nonce) if isinstance(user_op.nonce, int) else user_op.nonce,
        'callData': user_op.callData.hex() if isinstance(user_op.callData, bytes) else user_op.callData,
        # ... other fields
    }
```

### Bundler Integration Issues

#### 1. Bundler Connection Timeouts

**Issue:** Bundler requests timeout or fail
```
TimeoutError: Request to bundler timed out after 30 seconds
```

**Solution:**
```python
import asyncio
import aiohttp
from typing import List, Optional

class BundlerClient:
    def __init__(self, bundler_urls: List[str]):
        self.bundler_urls = bundler_urls
        self.current_bundler_index = 0
    
    async def submit_user_operation_with_fallback(self, user_op: dict) -> dict:
        last_exception = None
        
        for i, bundler_url in enumerate(self.bundler_urls):
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        f"{bundler_url}/eth_sendUserOperation",
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_sendUserOperation",
                            "params": [user_op, "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
                            "id": 1
                        }
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            if 'error' not in result:
                                self.current_bundler_index = i  # Update preferred bundler
                                return result
                            else:
                                raise BundlerException(result['error']['message'])
                        else:
                            raise BundlerException(f"HTTP {response.status}")
                            
            except Exception as e:
                last_exception = e
                logger.warning(f"Bundler {bundler_url} failed: {e}")
                continue
        
        raise BundlerException(f"All bundlers failed. Last error: {last_exception}")
```

#### 2. Invalid UserOperation Format

**Issue:** Bundler rejects UserOperation with format error
```
Error: Invalid UserOperation format
```

**Solution:**
```python
def validate_user_operation_format(user_op: dict) -> bool:
    required_fields = [
        'sender', 'nonce', 'initCode', 'callData',
        'callGasLimit', 'verificationGasLimit', 'preVerificationGas',
        'maxFeePerGas', 'maxPriorityFeePerGas', 'paymasterAndData', 'signature'
    ]
    
    # Check all required fields exist
    for field in required_fields:
        if field not in user_op:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate hex strings
    hex_fields = ['initCode', 'callData', 'paymasterAndData', 'signature']
    for field in hex_fields:
        if not isinstance(user_op[field], str) or not user_op[field].startswith('0x'):
            raise ValueError(f"Field {field} must be hex string starting with 0x")
    
    # Validate numeric fields are hex strings
    numeric_fields = [
        'nonce', 'callGasLimit', 'verificationGasLimit', 
        'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas'
    ]
    for field in numeric_fields:
        if isinstance(user_op[field], int):
            user_op[field] = hex(user_op[field])
        elif not isinstance(user_op[field], str) or not user_op[field].startswith('0x'):
            raise ValueError(f"Field {field} must be hex string or integer")
    
    return True
```

### Authentication Issues

#### 1. JWT Token Validation Fails

**Issue:** JWT authentication fails intermittently
```
Error: Token signature verification failed
```

**Solution:**
```python
import jwt
from datetime import datetime, timedelta
from django.conf import settings

class JWTAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Add token refresh logic
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                # Decode with leeway for clock skew
                payload = jwt.decode(
                    token, 
                    settings.JWT_SECRET, 
                    algorithms=['HS256'],
                    leeway=timedelta(seconds=10)  # 10 second leeway
                )
                request.jwt_payload = payload
                
                # Check if token expires soon and add refresh header
                exp = datetime.fromtimestamp(payload.get('exp', 0))
                if exp - datetime.now() < timedelta(minutes=5):
                    response = self.get_response(request)
                    response['X-Token-Refresh-Needed'] = 'true'
                    return response
                    
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid token'}, status=401)
        
        return self.get_response(request)
```

#### 2. Account Abstraction Authentication Issues

**Issue:** UserOperation signature validation fails
```
Error: Invalid UserOperation signature
```

**Solution:**
```python
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address
import eth_account

def validate_user_operation_signature(user_op: dict, signature: str, expected_signer: str) -> bool:
    try:
        # Recreate the message hash that was signed
        user_op_hash = calculate_user_operation_hash(user_op)
        
        # Handle different signature formats
        if signature.startswith('0x'):
            signature_bytes = bytes.fromhex(signature[2:])
        else:
            signature_bytes = bytes.fromhex(signature)
        
        # Recover signer address
        message = encode_defunct(primitive=user_op_hash)
        recovered_address = eth_account.Account.recover_message(message, signature=signature_bytes)
        
        # Compare addresses (case-insensitive)
        return to_checksum_address(recovered_address) == to_checksum_address(expected_signer)
        
    except Exception as e:
        logger.error(f"Signature validation error: {e}")
        return False

def calculate_user_operation_hash(user_op: dict) -> bytes:
    # Implement EIP-4337 UserOperation hash calculation
    from eth_abi import encode_packed
    
    # Encode UserOperation according to EIP-4337
    packed_data = encode_packed(
        ['address', 'uint256', 'bytes32', 'bytes32', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes32'],
        [
            user_op['sender'],
            int(user_op['nonce'], 16),
            Web3.keccak(bytes.fromhex(user_op['initCode'][2:])),
            Web3.keccak(bytes.fromhex(user_op['callData'][2:])),
            int(user_op['callGasLimit'], 16),
            int(user_op['verificationGasLimit'], 16),
            int(user_op['preVerificationGas'], 16),
            int(user_op['maxFeePerGas'], 16),
            int(user_op['maxPriorityFeePerGas'], 16),
            Web3.keccak(bytes.fromhex(user_op['paymasterAndData'][2:]))
        ]
    )
    
    return Web3.keccak(packed_data)
```

### Performance Issues

#### 1. Slow API Response Times

**Issue:** API endpoints respond slowly
```
Warning: API response time > 2000ms
```

**Solution:**
```python
# Add database query optimization
from django.db import models
from django.core.cache import cache

class SmartAccountManager(models.Manager):
    def get_account_with_cache(self, user_id: str):
        cache_key = f"smart_account:{user_id}"
        account = cache.get(cache_key)
        
        if account is None:
            account = self.select_related('user').filter(
                user_id=user_id
            ).first()
            
            if account:
                cache.set(cache_key, account, timeout=300)  # Cache for 5 minutes
        
        return account

# Add async database operations
import asyncio
from asgiref.sync import sync_to_async

class AsyncSmartAccountManager:
    @sync_to_async
    def get_account(self, user_id: str):
        return SmartAccount.objects.get(user_id=user_id)
    
    async def process_user_operation(self, user_id: str, operation: dict):
        # Fetch account data asynchronously
        account = await self.get_account(user_id)
        
        # Process operation
        return await self.submit_to_bundler(operation)
```

#### 2. High Memory Usage

**Issue:** Memory usage increases over time
```
Warning: Memory usage > 2GB
```

**Solution:**
```python
# Add connection pooling and resource cleanup
import gc
from contextlib import contextmanager

@contextmanager
def managed_web3_connection():
    web3 = None
    try:
        web3 = create_web3_connection()
        yield web3
    finally:
        if web3:
            # Close connection
            if hasattr(web3.provider, 'session'):
                web3.provider.session.close()
        gc.collect()  # Force garbage collection

# Use connection manager
async def process_operations():
    with managed_web3_connection() as web3:
        # Process operations
        pass
```

### Gas Estimation Issues

#### 1. Inaccurate Gas Estimates

**Issue:** Transactions fail due to insufficient gas
```
Error: Transaction ran out of gas
```

**Solution:**
```python
class GasEstimator:
    def __init__(self, web3: Web3):
        self.web3 = web3
        self.gas_buffer_percentage = 20  # 20% buffer
    
    async def estimate_user_operation_gas(self, user_op: dict) -> dict:
        try:
            # Use eth_estimateUserOperationGas if available
            if hasattr(self.bundler_client, 'estimate_user_operation_gas'):
                estimate = await self.bundler_client.estimate_user_operation_gas(user_op)
                return self._add_gas_buffer(estimate)
            
            # Fallback to manual estimation
            base_gas = 21000  # Base transaction cost
            call_gas = await self._estimate_call_gas(user_op)
            verification_gas = await self._estimate_verification_gas(user_op)
            
            return {
                'callGasLimit': call_gas,
                'verificationGasLimit': verification_gas,
                'preVerificationGas': base_gas
            }
            
        except Exception as e:
            # Use conservative defaults if estimation fails
            logger.warning(f"Gas estimation failed: {e}")
            return {
                'callGasLimit': 500000,
                'verificationGasLimit': 1000000,
                'preVerificationGas': 50000
            }
    
    def _add_gas_buffer(self, estimate: dict) -> dict:
        buffer_multiplier = (100 + self.gas_buffer_percentage) / 100
        
        return {
            field: int(value * buffer_multiplier)
            for field, value in estimate.items()
        }
```

### Recovery and Session Key Issues

#### 1. Recovery Process Fails

**Issue:** Account recovery cannot be executed
```
Error: Recovery execution failed - time lock not expired
```

**Solution:**
```python
from datetime import datetime, timedelta

class RecoveryManager:
    def validate_recovery_execution(self, recovery_id: str) -> bool:
        recovery = AccountRecovery.objects.get(id=recovery_id)
        
        # Check time lock
        if datetime.now() < recovery.execute_after:
            time_remaining = recovery.execute_after - datetime.now()
            raise RecoveryException(
                f"Recovery time lock not expired. {time_remaining.total_seconds()} seconds remaining"
            )
        
        # Check guardian signatures
        if recovery.confirmed_guardians < recovery.required_confirmations:
            raise RecoveryException(
                f"Insufficient guardian confirmations: {recovery.confirmed_guardians}/{recovery.required_confirmations}"
            )
        
        return True
    
    async def execute_recovery(self, recovery_id: str) -> dict:
        self.validate_recovery_execution(recovery_id)
        
        recovery = AccountRecovery.objects.get(id=recovery_id)
        
        # Create user operation for owner change
        user_op = await self.create_recovery_operation(recovery)
        
        # Submit to bundler
        result = await self.bundler_client.submit_user_operation(user_op)
        
        # Update recovery status
        recovery.status = 'COMPLETED'
        recovery.executed_at = datetime.now()
        recovery.transaction_hash = result['userOpHash']
        recovery.save()
        
        return result
```

#### 2. Session Key Validation Issues

**Issue:** Session key operations fail validation
```
Error: Session key expired or invalid
```

**Solution:**
```python
import time

class SessionKeyManager:
    def validate_session_key(self, session_key: str, user_id: str, operation: dict) -> bool:
        session = SessionKey.objects.filter(
            address=session_key,
            user_id=user_id,
            status='ACTIVE'
        ).first()
        
        if not session:
            raise SessionKeyException("Session key not found or inactive")
        
        # Check expiration
        if time.time() > session.expires_at:
            session.status = 'EXPIRED'
            session.save()
            raise SessionKeyException("Session key expired")
        
        # Check permissions
        required_permission = self.get_required_permission(operation)
        if required_permission not in session.permissions:
            raise SessionKeyException(f"Session key lacks {required_permission} permission")
        
        # Check spending limits
        if 'value' in operation and operation['value'] != '0':
            value_wei = int(operation['value'], 16)
            if session.spending_used_wei + value_wei > session.spending_limit_wei:
                raise SessionKeyException("Session key spending limit exceeded")
        
        # Check allowed targets
        if session.allowed_targets and operation.get('to') not in session.allowed_targets:
            raise SessionKeyException("Target address not allowed for session key")
        
        return True
```

## Debugging Tools

### 1. Debug Mode Configuration

```python
# settings/debug.py
DEBUG_AA = True

if DEBUG_AA:
    LOGGING['loggers']['blockauth.aa'] = {
        'handlers': ['console'],
        'level': 'DEBUG',
        'propagate': False,
    }
    
    # Enable SQL query logging
    LOGGING['loggers']['django.db.backends'] = {
        'handlers': ['console'],
        'level': 'DEBUG',
        'propagate': False,
    }
```

### 2. UserOperation Debugging

```python
def debug_user_operation(user_op: dict) -> dict:
    """Debug helper to validate UserOperation structure"""
    debug_info = {
        'validation_errors': [],
        'warnings': [],
        'gas_analysis': {}
    }
    
    # Validate structure
    required_fields = [
        'sender', 'nonce', 'initCode', 'callData',
        'callGasLimit', 'verificationGasLimit', 'preVerificationGas',
        'maxFeePerGas', 'maxPriorityFeePerGas', 'paymasterAndData', 'signature'
    ]
    
    for field in required_fields:
        if field not in user_op:
            debug_info['validation_errors'].append(f"Missing field: {field}")
    
    # Check gas limits
    if user_op.get('callGasLimit'):
        call_gas = int(user_op['callGasLimit'], 16)
        if call_gas < 21000:
            debug_info['warnings'].append("Call gas limit very low")
        if call_gas > 10000000:
            debug_info['warnings'].append("Call gas limit very high")
    
    # Analyze signature
    if user_op.get('signature') == '0x':
        debug_info['warnings'].append("Empty signature - operation not signed")
    
    return debug_info
```

### 3. Contract Event Monitoring

```javascript
// Monitor contract events for debugging
async function monitorContractEvents() {
  const smartAccount = await ethers.getContractAt("SmartAccount", accountAddress);
  
  // Listen for events
  smartAccount.on("TransactionExecuted", (txHash, success, event) => {
    console.log("Transaction executed:", {
      hash: txHash,
      success: success,
      blockNumber: event.blockNumber
    });
  });
  
  smartAccount.on("OwnerAdded", (owner, event) => {
    console.log("Owner added:", owner);
  });
  
  smartAccount.on("RecoveryInitiated", (newOwner, executeAfter, event) => {
    console.log("Recovery initiated:", {
      newOwner: newOwner,
      executeAfter: new Date(executeAfter * 1000)
    });
  });
}
```

## Monitoring and Alerts

### 1. Health Check Endpoints

```python
from django.http import JsonResponse
from django.views import View

class AAHealthCheckView(View):
    async def get(self, request):
        health_status = {
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'components': {}
        }
        
        try:
            # Check database
            await User.objects.filter(id=1).aexists()
            health_status['components']['database'] = 'healthy'
        except Exception as e:
            health_status['components']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        try:
            # Check Redis
            cache.set('health_check', 'ok', 60)
            cache.get('health_check')
            health_status['components']['redis'] = 'healthy'
        except Exception as e:
            health_status['components']['redis'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        try:
            # Check bundler
            bundler_status = await self.check_bundler_health()
            health_status['components']['bundler'] = bundler_status
        except Exception as e:
            health_status['components']['bundler'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return JsonResponse(health_status, status=status_code)
```

### 2. Custom Metrics

```python
from prometheus_client import Counter, Histogram, generate_latest

# Define custom metrics
user_operation_errors = Counter(
    'aa_user_operation_errors_total',
    'Total user operation errors',
    ['error_type', 'user_tier']
)

recovery_operations = Counter(
    'aa_recovery_operations_total',
    'Total recovery operations',
    ['status']
)

def track_user_operation_error(error_type: str, user_tier: str):
    user_operation_errors.labels(
        error_type=error_type,
        user_tier=user_tier
    ).inc()
```

This troubleshooting guide covers the most common issues you'll encounter when implementing and operating the BlockAuth Account Abstraction system, along with practical solutions and debugging tools to resolve them quickly.