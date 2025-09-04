# JWT Extension Guide: Custom Claims Support

## Overview

This guide explains the JWT extension implementation that allows any service to add custom claims to JWT tokens without modifying the core blockauth system. The implementation follows the "decentralized AWS" vision by maintaining clean separation of concerns.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  blockauth (opensource)                  │
│                                                          │
│  ┌────────────────────────────────────────────────┐     │
│  │         JWT Token Manager                       │     │
│  │                                                 │     │
│  │  1. Base Claims (user_id, email)              │     │
│  │  2. Custom Claims Provider Interface ←─────────┼─────┼── Fabric-Auth injects
│  │  3. Generate Token with merged claims          │     │    custom claims
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

## Implementation Details

### 1. Custom Claims Provider Interface

**File**: `blockauth/jwt/interfaces.py`

```python
from abc import ABC, abstractmethod
from typing import Dict, Any

class CustomClaimsProvider(ABC):
    @abstractmethod
    def get_custom_claims(self, user) -> Dict[str, Any]:
        """Return custom claims to be added to the JWT token."""
        pass

    @abstractmethod
    def validate_custom_claims(self, claims: Dict[str, Any]) -> bool:
        """Validate custom claims during token verification."""
        return True
```

### 2. Enhanced JWT Token Manager

**File**: `blockauth/jwt/token_manager.py`

The `JWTTokenManager` class provides:
- Registration/unregistration of claims providers
- Token generation with merged base and custom claims
- Token validation with custom claims verification
- Backward compatibility with existing token system

### 3. Example Claims Provider (fabric-auth)

**File**: `fabric_auth/blockchain/jwt_claims.py`

```python
class SmartAccountClaimsProvider(CustomClaimsProvider):
    def get_custom_claims(self, user) -> Dict[str, Any]:
        # Returns smart account address and chain deployments
        return {
            'smart_account': smart_account.smart_account_address,
            'smart_account_status': smart_account.status,
            'deployed_chains': list(deployments),
            'kdf_wallet': smart_account.kdf_wallet.wallet_address if smart_account.kdf_wallet else None,
        }
```

**Note**: This is just an example implementation in fabric-auth. The blockauth library itself is completely generic and doesn't know about smart accounts or any specific data types.

## Usage Examples

### For Developers Using blockauth

```python
# Create your own claims provider
class MyCustomClaimsProvider(CustomClaimsProvider):
    def get_custom_claims(self, user):
        return {
            'organization': user.organization.name,
            'role': user.role,
            'permissions': user.get_permissions(),
        }

    def validate_custom_claims(self, claims):
        return True

# Register it
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider(MyCustomClaimsProvider())
```

### Token Generation

```python
# Enhanced token generation with custom claims
from blockauth.utils.token import generate_auth_token_with_custom_claims

access_token, refresh_token = generate_auth_token_with_custom_claims(
    token_class=AUTH_TOKEN_CLASS(),
    user_id=str(user.id)
)
```

### Token Decoding

```python
# Decode token and access custom claims
from blockauth.jwt.token_manager import jwt_manager

claims = jwt_manager.decode_token(token)
smart_account = claims.get('smart_account')
deployed_chains = claims.get('deployed_chains', [])
```

## Resulting JWT Token Structure

```json
{
  "user_id": "123",
  "email": "user@example.com",
  "username": "user@example.com",
  "exp": 1704067200,
  "iat": 1704063600,
  "type": "access",

  // Custom claims from any provider (example from fabric-auth)
  "smart_account": "0xABC123...",
  "smart_account_status": "ACTIVE",
  "deployed_chains": ["ethereum_sepolia", "base_sepolia"],
  "kdf_wallet": "0xDEF456...",

  // Custom claims from any other provider
  "organization": "Acme Corp",
  "role": "admin",
  "permissions": ["read", "write", "delete"]
}
```

## Configuration

### blockauth Configuration

The enhanced JWT system uses existing blockauth configuration:

```python
# settings.py
JWT_SECRET_KEY = 'your-secret-key'  # Optional, falls back to SECRET_KEY
ALGORITHM = 'HS256'  # JWT signing algorithm
ACCESS_TOKEN_LIFETIME = timedelta(hours=1)  # Token lifetime
```

### Registration in Django Apps

```python
# apps.py
class MyAppConfig(AppConfig):
    def ready(self):
        from blockauth.jwt.token_manager import jwt_manager
        from .my_claims_provider import MyClaimsProvider
        
        provider = MyClaimsProvider()
        jwt_manager.register_claims_provider(provider)
```

## Benefits

1. **Completely Generic**: blockauth library doesn't know about any specific data types
2. **Open Source Friendly**: blockauth remains generic and reusable for any use case
3. **Extensible**: Any service can add custom claims without modifying blockauth
4. **Backwards Compatible**: Existing code continues to work
5. **Clean Separation**: blockauth is completely agnostic to what data gets added to tokens
6. **Type Safe**: Interface ensures proper implementation
7. **Error Resilient**: Failed providers don't break token generation

## Testing

Run the test script to verify the implementation:

```bash
cd services/auth-pack
python test_jwt_extension.py
```

## Migration Guide

### Existing Code

Existing code using `generate_auth_token()` will continue to work without changes. The system automatically falls back to the original implementation if the enhanced system is not available.

### New Code

For new code that needs custom claims:

1. Use `generate_auth_token_with_custom_claims()` instead of `generate_auth_token()`
2. Create and register custom claims providers
3. Access custom claims from decoded tokens

## Error Handling

The system is designed to be resilient:

- Failed claims providers don't break token generation
- Invalid custom claims are logged but don't prevent token creation
- The system falls back to original implementation if enhanced system is unavailable

## Security Considerations

1. **Claims Validation**: Custom claims are validated during token verification
2. **No Override**: Custom claims cannot override base claims (user_id, exp, iat, type)
3. **Error Logging**: All errors are logged for monitoring
4. **Graceful Degradation**: System works even if custom claims fail

## Future Enhancements

1. **Claims Caching**: Cache custom claims to improve performance
2. **Claims Versioning**: Support for different versions of claims
3. **Claims Encryption**: Encrypt sensitive custom claims
4. **Claims Analytics**: Track usage of different claims providers

## Troubleshooting

### Common Issues

1. **Claims Provider Not Registered**: Check that the provider is registered in the app's `ready()` method
2. **Import Errors**: Ensure blockauth is properly installed and configured
3. **Claims Not Appearing**: Verify the provider's `get_custom_claims()` method returns data
4. **Validation Failures**: Check the provider's `validate_custom_claims()` method

### Debug Mode

Enable debug logging to see detailed information about claims processing:

```python
import logging
logging.getLogger('blockauth.jwt').setLevel(logging.DEBUG)
```

## API Reference

### JWTTokenManager

- `register_claims_provider(provider)`: Register a custom claims provider
- `unregister_claims_provider(provider)`: Unregister a claims provider
- `generate_token(user_id, token_type, token_lifetime, user_data)`: Generate token with custom claims
- `decode_token(token)`: Decode and validate token
- `get_custom_claims(token)`: Extract only custom claims from token

### CustomClaimsProvider

- `get_custom_claims(user)`: Return custom claims for a user
- `validate_custom_claims(claims)`: Validate custom claims during verification
