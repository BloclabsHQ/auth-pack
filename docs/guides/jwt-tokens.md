# JWT Tokens

BlockAuth uses JWT (JSON Web Tokens) for stateless authentication. Tokens are signed with HS256 by default, with RS256 and ES256 support for asymmetric signing.

## Token Structure

### Access Token Payload

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "access"
}
```

### Refresh Token Payload

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "refresh"
}
```

Access tokens are short-lived (default: 1 hour). Refresh tokens are longer-lived (default: 1 day) and used to obtain new token pairs.

## Token Generation

```python
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

access_token, refresh_token = generate_auth_token(
    token_class=AUTH_TOKEN_CLASS(),
    user_id=str(user.id),
)
```

## Token Decoding

```python
from blockauth.utils.token import AUTH_TOKEN_CLASS

token_instance = AUTH_TOKEN_CLASS()
payload = token_instance.decode_token(access_token)

user_id = payload['user_id']
token_type = payload['type']  # "access" or "refresh"
```

## Custom Token Configuration

```python
from blockauth.utils.token import Token
from datetime import timedelta

custom_token = Token(
    secret_key="your-custom-secret",
    algorithm="HS256",
)

access_token = custom_token.generate_token(
    user_id="550e8400-e29b-41d4-a716-446655440000",
    token_type="access",
    token_lifetime=timedelta(hours=2),
)
```

## Custom Claims

BlockAuth's claims provider architecture lets you add custom data to JWT tokens without modifying the core package.

### Create a Claims Provider

```python
# myapp/jwt_claims.py
from blockauth.jwt.interfaces import CustomClaimsProvider

class MyClaimsProvider(CustomClaimsProvider):
    def get_custom_claims(self, user):
        return {
            "role": user.role,
            "org_id": str(user.organization_id),
            "permissions": list(user.get_permissions()),
        }

    def validate_custom_claims(self, claims):
        return "role" in claims
```

### Register the Provider

Register in your Django app's `ready()` method:

```python
# myapp/apps.py
from django.apps import AppConfig

class MyAppConfig(AppConfig):
    name = 'myapp'

    def ready(self):
        from blockauth.jwt.token_manager import jwt_manager
        from .jwt_claims import MyClaimsProvider

        jwt_manager.register_claims_provider(MyClaimsProvider())
```

### Multiple Providers

You can register multiple providers. Claims are merged into the final token:

```python
jwt_manager.register_claims_provider(AuthClaimsProvider())
jwt_manager.register_claims_provider(BillingClaimsProvider())
```

### Resulting Token

```json
{
  "user_id": "123",
  "exp": 1704067200,
  "iat": 1704063600,
  "type": "access",
  "role": "admin",
  "org_id": "org-456",
  "permissions": ["read", "write"]
}
```

!!! warning
    Custom claims cannot override base claims (`user_id`, `exp`, `iat`, `type`). Keep claims minimal -- large tokens impact performance and may exceed header size limits.

## Token Validation in External Services

### Python

```python
import jwt

def validate_blockauth_token(token_string, secret_key):
    try:
        payload = jwt.decode(
            token_string,
            secret_key,
            algorithms=["HS256"],
            options={"verify_signature": True, "verify_exp": True},
        )
        if "user_id" not in payload or "type" not in payload:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidSignatureError:
        return None
```

### JavaScript

```javascript
const jwt = require('jsonwebtoken');

function validateBlockAuthToken(token, secretKey) {
    try {
        const payload = jwt.verify(token, secretKey, {
            algorithms: ['HS256'],
        });
        if (!payload.user_id || !payload.type) return null;
        return payload;
    } catch (error) {
        return null;
    }
}
```

## Microservice Patterns

### Centralized Auth, Distributed Validation

Each service validates tokens independently using the shared secret or public key:

```python
# middleware.py
from blockauth.utils.token import AUTH_TOKEN_CLASS

class BlockAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.token_instance = AUTH_TOKEN_CLASS()

    def __call__(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                payload = self.token_instance.decode_token(token)
                request.user_id = payload['user_id']
            except Exception:
                pass
        return self.get_response(request)
```

## Token Refresh Rotation

When `ROTATE_REFRESH_TOKENS` is `True` (default), each refresh request:

1. Validates the refresh token
2. Blacklists the old refresh token
3. Issues a new access + refresh token pair

This limits the damage if a refresh token is compromised.

## Security Best Practices

- Store access tokens in memory only (never `localStorage`)
- Store refresh tokens in secure HTTP-only cookies
- Use short access token lifetimes (15-60 minutes)
- Always pin the algorithm on decode: `algorithms=["HS256"]`
- For asymmetric signing, keep private keys in a secrets manager
