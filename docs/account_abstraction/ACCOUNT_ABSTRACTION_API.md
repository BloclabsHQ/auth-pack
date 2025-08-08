# BlockAuth Hybrid Web2/Web3 Account Abstraction API Documentation

## Overview

This document provides comprehensive API documentation for BlockAuth's **Hybrid Account Abstraction** implementation. The API maintains full backward compatibility with existing Web2 authentication while providing optional Web3 Account Abstraction enhancements.

## CRITICAL DESIGN PRINCIPLE

**All Account Abstraction APIs are ADDITIVE enhancements that work alongside existing Web2 authentication. Users can migrate to Web3 seamlessly while maintaining full access to their Web2 authentication methods.**

### Hybrid API Design Goals
- **100% Web2 Compatibility**: All existing Web2 APIs continue working unchanged
- **Optional Web3 Enhancement**: AA features are opt-in extensions for users who choose them
- **Seamless Migration**: APIs support gradual migration from Web2 to Web3
- **Dual Authentication**: Users can authenticate via Web2 or Web3 methods interchangeably
- **Zero Breaking Changes**: Existing integrations continue working without modification

## Base URL

- **Development**: `http://localhost:8000/api/aa/`
- **Staging**: `https://api-staging.blockauth.io/api/aa/`
- **Production**: `https://api.blockauth.io/api/aa/`

## Authentication (HYBRID SUPPORT)

All AA endpoints support **BOTH** Web2 and Web3 authentication methods. Users can use either method interchangeably.

### Web2 Authentication (PRESERVED - DEFAULT)
```http
Authorization: Bearer <jwt_token>
```
This is the existing authentication method that continues to work for all users, including those with Web3 features enabled.

### Web3 Account Abstraction Authentication (OPTIONAL ENHANCEMENT)
```http
X-AA-Signature: <user_operation_signature>
X-AA-UserOp: <base64_encoded_user_operation>
```
This is available only for users who have opted into Web3 features.

### Hybrid Authentication Response Format
All API responses include both Web2 and Web3 user context when available:
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "web2_auth": {
      "authentication_types": ["EMAIL", "GOOGLE"],
      "is_verified": true
    },
    "web3_auth": {
      "smart_account_address": "0x1234...",
      "is_aa_enabled": true,
      "preferred_auth_method": "HYBRID"
    }
  }
}
```

## API Endpoints

### 🔄 Migration APIs (NEW - CRITICAL FOR WEB2/WEB3 TRANSITION)

#### Initiate Web2 to Web3 Migration
Seamlessly migrate an existing Web2 user to Web3 without data loss.

```http
POST /api/auth/migrate/initiate/
```

**Request Body:**
```json
{
  "migration_options": {
    "preserve_web2_auth": true,  // ALWAYS true - Web2 auth must be preserved
    "enable_gas_sponsorship": true,
    "deployment_preference": "lazy"  // "immediate" or "lazy"
  }
}
```

**Response:**
```json
{
  "migration_id": "mig_1234567890",
  "smart_account_address": "0x1234567890123456789012345678901234567890",
  "status": "initiated",
  "web2_auth_preserved": true,
  "estimated_completion": "2024-01-15T10:30:00Z",
  "rollback_available": true
}
```

#### Migration Status
Check the progress of an ongoing migration.

```http
GET /api/auth/migrate/status/
```

**Response:**
```json
{
  "migration_id": "mig_1234567890",
  "status": "in_progress",
  "progress": 75,
  "current_step": "linking_smart_account",
  "web2_auth_status": "preserved_and_active",
  "web3_auth_status": "partially_enabled",
  "data_integrity_check": "passed",
  "rollback_available": true
}
```

#### Rollback Migration
Return to Web2-only mode while preserving all data.

```http
POST /api/auth/migrate/rollback/
```

**Response:**
```json
{
  "rollback_id": "rb_1234567890",
  "status": "completed",
  "web2_auth_status": "fully_restored",
  "web3_features_disabled": true,
  "data_preserved": true,
  "message": "Successfully rolled back to Web2-only authentication"
}
```

### 🔧 Authentication Preference Management (NEW)

#### Get Authentication Preferences
Retrieve user's authentication method preferences.

```http
GET /api/auth/preference/
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "preferred_auth_method": "HYBRID",  // "WEB2", "WEB3", "HYBRID"
  "available_methods": {
    "web2": {
      "enabled": true,
      "methods": ["EMAIL", "GOOGLE", "FACEBOOK"]
    },
    "web3": {
      "enabled": true,
      "smart_account_deployed": true,
      "gas_sponsorship": true
    }
  },
  "fallback_method": "WEB2"  // Always Web2 for safety
}
```

#### Update Authentication Preferences
Change user's authentication method preferences.

```http
POST /api/auth/preference/
```

**Request Body:**
```json
{
  "preferred_auth_method": "HYBRID",
  "web2_backup_enabled": true,  // CANNOT be disabled - safety requirement
  "enable_gas_sponsorship": true
}
```

### 🏗️ Smart Account Management (OPTIONAL - WEB3 USERS ONLY)

#### Create Smart Account (OPTIONAL ENHANCEMENT)
Creates a new smart account for users who have opted into Web3 features.

```http
POST /api/aa/account/create/
```

**Request Body:**
```json
{
  "link_to_web2_user": true,  // ALWAYS true - must link to existing Web2 user
  "owners": [
    "0x1234567890123456789012345678901234567890"
  ],
  "threshold": 1,
  "salt": 12345,
  "deploy_immediately": false,
  "preserve_web2_auth": true  // ALWAYS true
}
```

**Response:**
```json
{
  "smart_account_address": "0x1234567890123456789012345678901234567890",
  "deployment_status": "pending",
  "linked_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "web2_auth_preserved": true,
  "migration_completed": true,
  "gas_sponsorship_enabled": true
}
```

**Parameters:**
- `owners` (array, required): Array of owner addresses
- `threshold` (integer, required): Number of signatures required (1 ≤ threshold ≤ owners.length)
- `salt` (integer, optional): Salt for deterministic address generation
- `deploy_immediately` (boolean, optional): Whether to deploy the account immediately (default: false)

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "smart_account_address": "0x3456789012345678901234567890123456789012",
    "is_deployed": true,
    "deployment_tx_hash": "0xabcdef...",
    "owners": [
      "0x1234567890123456789012345678901234567890",
      "0x2345678901234567890123456789012345678901"
    ],
    "threshold": 2,
    "salt": 12345,
    "predicted_address": "0x3456789012345678901234567890123456789012"
  },
  "message": "Smart account created successfully"
}
```

**Error Responses:**
```json
// 400 Bad Request
{
  "success": false,
  "error": "INVALID_OWNERS",
  "message": "Owner addresses must be valid Ethereum addresses",
  "details": {
    "invalid_addresses": ["0xinvalid"]
  }
}

// 409 Conflict
{
  "success": false,
  "error": "ACCOUNT_EXISTS",
  "message": "Smart account already exists for this user",
  "data": {
    "existing_address": "0x3456789012345678901234567890123456789012"
  }
}
```

#### Get Smart Account Status
Retrieves the current status of the user's smart account.

```http
GET /api/aa/account/status/
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "smart_account_address": "0x3456789012345678901234567890123456789012",
    "is_deployed": true,
    "owners": [
      "0x1234567890123456789012345678901234567890",
      "0x2345678901234567890123456789012345678901"
    ],
    "threshold": 2,
    "nonce": 5,
    "balance_wei": "1000000000000000000",
    "balance_eth": "1.0",
    "active_session_keys": [
      {
        "address": "0x4567890123456789012345678901234567890123",
        "permissions": ["EXECUTE"],
        "expires_at": 1699123456
      }
    ],
    "pending_recovery": null
  }
}
```

#### Manage Account Owners
Add or remove owners from the smart account.

```http
POST /api/aa/account/owners/
```

**Request Body (Add Owner):**
```json
{
  "action": "add",
  "owner_address": "0x4567890123456789012345678901234567890123",
  "new_threshold": 3
}
```

**Request Body (Remove Owner):**
```json
{
  "action": "remove",
  "owner_address": "0x2345678901234567890123456789012345678901",
  "new_threshold": 1
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user_operation_hash": "0xdef123...",
    "owners": [
      "0x1234567890123456789012345678901234567890",
      "0x4567890123456789012345678901234567890123"
    ],
    "threshold": 2,
    "tx_hash": null
  },
  "message": "Owner management operation submitted"
}
```

### User Operations

#### Create User Operation
Creates a new user operation for execution.

```http
POST /api/aa/userop/create/
```

**Request Body:**
```json
{
  "to": "0x5678901234567890123456789012345678901234",
  "value": "1000000000000000000",
  "data": "0xa9059cbb...",
  "operation_type": "CALL",
  "batch_operations": [
    {
      "to": "0x6789012345678901234567890123456789012345",
      "value": "0",
      "data": "0x095ea7b3..."
    }
  ]
}
```

**Parameters:**
- `to` (string, required): Target contract address
- `value` (string, optional): ETH value to send (in wei)
- `data` (string, optional): Encoded function call data
- `operation_type` (string, required): Type of operation ("CALL", "DELEGATECALL", "CREATE")
- `batch_operations` (array, optional): Array of operations to batch together

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "user_operation": {
      "sender": "0x3456789012345678901234567890123456789012",
      "nonce": "0x5",
      "initCode": "0x",
      "callData": "0xa9059cbb...",
      "callGasLimit": "0x30d40",
      "verificationGasLimit": "0xaae60",
      "preVerificationGas": "0x5208",
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "paymasterAndData": "0x7890123456789012345678901234567890123456...",
      "signature": "0x"
    },
    "user_operation_hash": "0x789abc...",
    "gas_estimates": {
      "total_gas_limit": 1000000,
      "estimated_gas_cost_eth": "0.02",
      "sponsored": true
    }
  },
  "message": "User operation created successfully"
}
```

#### Submit User Operation
Submits a signed user operation to the bundler.

```http
POST /api/aa/userop/submit/
```

**Request Body:**
```json
{
  "user_operation": {
    "sender": "0x3456789012345678901234567890123456789012",
    "nonce": "0x5",
    "initCode": "0x",
    "callData": "0xa9059cbb...",
    "callGasLimit": "0x30d40",
    "verificationGasLimit": "0xaae60",
    "preVerificationGas": "0x5208",
    "maxFeePerGas": "0x4a817c800",
    "maxPriorityFeePerGas": "0x3b9aca00",
    "paymasterAndData": "0x7890123456789012345678901234567890123456...",
    "signature": "0x1b4f7e3c..."
  }
}
```

**Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "user_operation_hash": "0x789abc...",
    "bundler_response": {
      "hash": "0x789abc...",
      "receipt": null
    },
    "status": "PENDING",
    "estimated_confirmation_time": 30
  },
  "message": "User operation submitted to bundler"
}
```

#### Get User Operation Status
Retrieves the status of a submitted user operation.

```http
GET /api/aa/userop/status/{user_operation_hash}/
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user_operation_hash": "0x789abc...",
    "status": "CONFIRMED",
    "transaction_hash": "0xdef456...",
    "block_number": 18500000,
    "gas_used": 250000,
    "gas_cost_eth": "0.005",
    "sponsored": true,
    "receipt": {
      "status": 1,
      "gasUsed": 250000,
      "logs": [...]
    },
    "confirmed_at": "2023-11-01T12:00:00Z"
  }
}
```

### Batch Operations

#### Execute Batch Operations
Executes multiple operations in a single user operation.

```http
POST /api/aa/batch/
```

**Request Body:**
```json
{
  "operations": [
    {
      "to": "0x5678901234567890123456789012345678901234",
      "value": "0",
      "data": "0x095ea7b3...",
      "operation_type": "CALL"
    },
    {
      "to": "0x6789012345678901234567890123456789012345",
      "value": "1000000000000000000",
      "data": "0xa9059cbb...",
      "operation_type": "CALL"
    }
  ],
  "atomic": true
}
```

**Parameters:**
- `operations` (array, required): Array of operations to execute
- `atomic` (boolean, optional): Whether all operations must succeed (default: true)

**Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "batch_id": "batch_123456",
    "user_operation_hash": "0x890bcd...",
    "operations_count": 2,
    "estimated_gas": 450000,
    "status": "PENDING"
  },
  "message": "Batch operations submitted"
}
```

### Gas Estimation

#### Estimate Gas Costs
Estimates gas costs for a user operation.

```http
POST /api/aa/gas/estimate/
```

**Request Body:**
```json
{
  "to": "0x5678901234567890123456789012345678901234",
  "value": "1000000000000000000",
  "data": "0xa9059cbb...",
  "batch_operations": []
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "gas_estimates": {
      "callGasLimit": 200000,
      "verificationGasLimit": 700000,
      "preVerificationGas": 21000,
      "maxFeePerGas": 20000000000,
      "maxPriorityFeePerGas": 1000000000
    },
    "cost_breakdown": {
      "execution_cost": "0.004",
      "verification_cost": "0.014",
      "bundler_fee": "0.0005",
      "total_cost_eth": "0.0185"
    },
    "paymaster_sponsored": true,
    "user_tier": "premium",
    "credits_required": 185
  }
}
```

### Recovery Operations

#### Initiate Account Recovery
Initiates the recovery process for a smart account.

```http
POST /api/aa/recovery/initiate/
```

**Request Body:**
```json
{
  "new_owner": "0x7890123456789012345678901234567890123456",
  "guardian_signatures": [
    {
      "guardian_address": "0x8901234567890123456789012345678901234567",
      "signature": "0x1c2d3e4f..."
    },
    {
      "guardian_address": "0x9012345678901234567890123456789012345678",
      "signature": "0x2d3e4f5a..."
    }
  ]
}
```

**Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "recovery_id": "recovery_789012",
    "new_owner": "0x7890123456789012345678901234567890123456",
    "execute_after": "2023-11-03T12:00:00Z",
    "time_lock_seconds": 172800,
    "required_confirmations": 2,
    "confirmed_guardians": 2,
    "status": "PENDING"
  },
  "message": "Recovery process initiated. Will be executable after time-lock period."
}
```

#### Execute Account Recovery
Executes a time-locked recovery operation.

```http
POST /api/aa/recovery/execute/
```

**Request Body:**
```json
{
  "recovery_id": "recovery_789012"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "recovery_id": "recovery_789012",
    "transaction_hash": "0xbcd123...",
    "new_owner": "0x7890123456789012345678901234567890123456",
    "executed_at": "2023-11-03T12:30:00Z",
    "status": "COMPLETED"
  },
  "message": "Account recovery executed successfully"
}
```

### Session Key Management

#### Create Session Key
Creates a temporary session key for the smart account.

```http
POST /api/aa/session/create/
```

**Request Body:**
```json
{
  "session_key": "0xa012345678901234567890123456789012345678",
  "permissions": ["EXECUTE", "TRANSFER"],
  "expires_in_seconds": 86400,
  "spending_limit_wei": "1000000000000000000",
  "allowed_targets": [
    "0xb123456789012345678901234567890123456789"
  ]
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "session_id": "session_456789",
    "session_key": "0xa012345678901234567890123456789012345678",
    "permissions": ["EXECUTE", "TRANSFER"],
    "expires_at": "2023-11-02T12:00:00Z",
    "spending_limit_wei": "1000000000000000000",
    "spending_used_wei": "0",
    "allowed_targets": [
      "0xb123456789012345678901234567890123456789"
    ],
    "status": "ACTIVE"
  },
  "message": "Session key created successfully"
}
```

#### Revoke Session Key
Revokes an active session key.

```http
DELETE /api/aa/session/{session_id}/
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "session_id": "session_456789",
    "status": "REVOKED",
    "revoked_at": "2023-11-01T15:30:00Z"
  },
  "message": "Session key revoked successfully"
}
```

### Subscription and Credits

#### Get Subscription Status
Retrieves the user's subscription status and gas credits.

```http
GET /api/aa/subscription/status/
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "subscription_tier": "premium",
    "plan_name": "Premium Plan",
    "expires_at": "2024-01-01T00:00:00Z",
    "gas_credits": {
      "balance": 5000,
      "monthly_allocation": 10000,
      "used_this_month": 5000,
      "resets_at": "2023-12-01T00:00:00Z"
    },
    "usage_limits": {
      "max_operations_per_day": 1000,
      "operations_used_today": 45,
      "max_gas_per_operation": 500000,
      "sponsored_gas": true,
      "batch_operations": true,
      "priority_bundling": false
    }
  }
}
```

#### Purchase Gas Credits
Allows users to purchase additional gas credits.

```http
POST /api/aa/subscription/credits/purchase/
```

**Request Body:**
```json
{
  "credits_amount": 1000,
  "payment_method": "stripe",
  "payment_token": "tok_1234567890"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "purchase_id": "purchase_123456",
    "credits_amount": 1000,
    "cost_usd": 10.00,
    "new_balance": 6000,
    "transaction_id": "ch_1234567890"
  },
  "message": "Gas credits purchased successfully"
}
```

## WebSocket Events

For real-time updates on user operations and account status, the API provides WebSocket connections.

### Connection
```javascript
const ws = new WebSocket('wss://api.blockauth.io/ws/aa/');
```

### Authentication
```javascript
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your_jwt_token'
}));
```

### Event Types

#### User Operation Status Update
```json
{
  "type": "user_operation_update",
  "data": {
    "user_operation_hash": "0x789abc...",
    "status": "CONFIRMED",
    "transaction_hash": "0xdef456...",
    "gas_used": 250000
  }
}
```

#### Account Balance Update
```json
{
  "type": "account_balance_update",
  "data": {
    "smart_account_address": "0x3456...",
    "balance_wei": "2000000000000000000",
    "balance_eth": "2.0"
  }
}
```

#### Gas Credits Update
```json
{
  "type": "gas_credits_update",
  "data": {
    "balance": 4850,
    "used_amount": 150,
    "operation_hash": "0x789abc..."
  }
}
```

## Error Handling

### Standard Error Response Format
```json
{
  "success": false,
  "error": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {
    "field": "Additional error details"
  },
  "timestamp": "2023-11-01T12:00:00Z",
  "request_id": "req_1234567890"
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_SIGNATURE` | UserOperation signature is invalid | 400 |
| `INSUFFICIENT_CREDITS` | User has insufficient gas credits | 402 |
| `RATE_LIMIT_EXCEEDED` | API rate limit exceeded | 429 |
| `ACCOUNT_NOT_DEPLOYED` | Smart account not deployed | 404 |
| `BUNDLER_ERROR` | Bundler service error | 502 |
| `PAYMASTER_REJECTED` | Paymaster rejected the operation | 403 |
| `SUBSCRIPTION_EXPIRED` | User subscription has expired | 402 |
| `INVALID_PARAMETERS` | Request parameters are invalid | 400 |
| `UNAUTHORIZED` | Authentication required | 401 |
| `FORBIDDEN` | Operation not permitted | 403 |
| `NOT_FOUND` | Resource not found | 404 |
| `CONFLICT` | Resource already exists | 409 |
| `INTERNAL_ERROR` | Internal server error | 500 |

## Rate Limiting

API endpoints are rate-limited based on subscription tiers:

| Tier | Requests/Hour | Burst Limit |
|------|---------------|-------------|
| Free | 100 | 10 |
| Premium | 1,000 | 50 |
| Enterprise | 10,000 | 200 |

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1699123456
```

## SDK Examples

### JavaScript/TypeScript
```typescript
import { BlockAuthAA } from '@blockauth/aa-sdk';

const aa = new BlockAuthAA({
  apiKey: 'your_api_key',
  network: 'sepolia'
});

// Create smart account
const account = await aa.createSmartAccount({
  owners: ['0x1234...'],
  threshold: 1
});

// Submit user operation
const userOp = await aa.createUserOperation({
  to: '0x5678...',
  value: '1000000000000000000',
  data: '0x'
});

const signature = await signer.signUserOperation(userOp);
const result = await aa.submitUserOperation({
  ...userOp,
  signature
});
```

### Python
```python
from blockauth_aa import BlockAuthAA

aa = BlockAuthAA(
    api_key='your_api_key',
    network='sepolia'
)

# Create smart account
account = await aa.create_smart_account(
    owners=['0x1234...'],
    threshold=1
)

# Submit user operation
user_op = await aa.create_user_operation(
    to='0x5678...',
    value='1000000000000000000',
    data='0x'
)

signature = await signer.sign_user_operation(user_op)
result = await aa.submit_user_operation({
    **user_op,
    'signature': signature
})
```

This API documentation provides comprehensive coverage of all Account Abstraction endpoints and functionality available in the BlockAuth system.