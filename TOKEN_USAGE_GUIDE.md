# BlockAuth Token Usage Guide

This guide explains how to use BlockAuth's token generation and decoding functionality from external services or applications.

## Overview

BlockAuth uses JWT (JSON Web Tokens) for authentication. The token system provides:
- **Access Tokens**: Short-lived tokens for API authentication (default: 1 hour)
- **Refresh Tokens**: Long-lived tokens for obtaining new access tokens (default: 1 day)
- **Configurable**: Customizable lifetimes, algorithms, and secret keys

## Token Structure

### JWT Payload

**Access Token:**
```json
{
  "user_id": "user-uuid-hex",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "access",
  "is_verified": true
}
```

**Refresh Token:**
```json
{
  "user_id": "user-uuid-hex",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "refresh"
}
```

### Claims
- `user_id`: User's UUID in hexadecimal format
- `exp`: Expiration timestamp
- `iat`: Issued at timestamp
- `type`: Token type ("access" or "refresh")
- `is_verified`: User's email verification status (access tokens only)

## Using BlockAuth Tokens in External Services

### 1. Install BlockAuth Package

```bash
pip install blockauth
```

### 2. Basic Token Generation

```python
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

# Generate tokens for a user
user_id = "550e8400-e29b-41d4-a716-446655440000"  # User's UUID in hex
access_token, refresh_token = generate_auth_token(
    token_class=AUTH_TOKEN_CLASS(),
    user_id=user_id,
    user_data={"is_verified": True}  # Include user verification status
)

print(f"Access Token: {access_token}")
print(f"Refresh Token: {refresh_token}")
```

### 3. Token Decoding and Validation

```python
from blockauth.utils.token import AUTH_TOKEN_CLASS
from rest_framework.exceptions import AuthenticationFailed

# Create token instance
token_instance = AUTH_TOKEN_CLASS()

try:
    # Decode and validate token
    payload = token_instance.decode_token(access_token)
    
    # Extract user information
    user_id = payload['user_id']
    token_type = payload['type']
    issued_at = payload['iat']
    expires_at = payload['exp']
    
    print(f"User ID: {user_id}")
    print(f"Token Type: {token_type}")
    
except AuthenticationFailed as e:
    print(f"Token validation failed: {e}")
```

### 4. Custom Configuration

```python
from blockauth.utils.token import Token
from datetime import timedelta

# Create custom token instance with specific settings
custom_token = Token(
    secret_key="your-custom-secret-key",
    algorithm="HS256"
)

# Generate token with custom lifetime
access_token = custom_token.generate_token(
    user_id="user-uuid-hex",
    token_type="access",
    token_lifetime=timedelta(hours=2)
)
```

## Token Refresh Flow

```python
from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token

def refresh_token_view(request):
    refresh_token = request.data.get('refresh')
    
    try:
        # Validate refresh token
        token_instance = AUTH_TOKEN_CLASS()
        payload = token_instance.decode_token(refresh_token)
        
        # Check if it's a refresh token
        if payload['type'] != 'refresh':
            raise AuthenticationFailed("Invalid token type")
        
        # Get user to retrieve current verification status
        user_model = get_block_auth_user_model()
        user = user_model.objects.get(id=payload['user_id'])
        
        # Generate new tokens (user_data only goes to access token)
        access_token, new_refresh_token = generate_auth_token(
            token_class=AUTH_TOKEN_CLASS(),
            user_id=payload['user_id'],
            user_data={"is_verified": user.is_verified}
        )
        
        return {
            "access": access_token,
            "refresh": new_refresh_token
        }
        
    except AuthenticationFailed as e:
        return {"error": str(e)}, 401
```

## Django Settings Configuration

### Required Settings

Add these to your Django settings:

```python
# settings.py

# BlockAuth Configuration
BLOCK_AUTH_SETTINGS = {
    # Token settings
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ALGORITHM": "HS256",
    
    # Secret key (use Django's SECRET_KEY if not specified)
    "JWT_SECRET_KEY": "your-jwt-secret-key",  # Optional
    
    # User model
    "BLOCK_AUTH_USER_MODEL": "your_app.YourUserModel",
}
```

### Optional Settings

```python
BLOCK_AUTH_SETTINGS = {
    # ... required settings ...
    
    # Custom token lifetimes
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    
    # Custom algorithm
    "ALGORITHM": "HS512",
    
    # Custom secret key
    "JWT_SECRET_KEY": "your-super-secret-key",
}
```

## Microservice Integration

### Service A (Token Generator)

```python
# service_a/views.py
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

def login_view(request):
    # Authenticate user
    user = authenticate_user(request)
    
    # Generate tokens
    access_token, refresh_token = generate_auth_token(
        token_class=AUTH_TOKEN_CLASS(),
        user_id=user.id.hex,
        user_data={"is_verified": user.is_verified}
    )
    
    return {
        "access": access_token,
        "refresh": refresh_token,
        "user_id": user.id.hex
    }
```

### Service B (Token Validator)

```python
# service_b/middleware.py
from blockauth.utils.token import AUTH_TOKEN_CLASS
from rest_framework.exceptions import AuthenticationFailed

class BlockAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.token_instance = AUTH_TOKEN_CLASS()
    
    def __call__(self, request):
        # Extract token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token
                payload = self.token_instance.decode_token(token)
                
                # Add user info to request
                request.user_id = payload['user_id']
                request.token_type = payload['type']
                request.is_verified = payload.get('is_verified', False)
                
            except AuthenticationFailed:
                # Handle invalid token
                pass
        
        return self.get_response(request)
```

### Service C (API Endpoint)

```python
# service_c/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
def protected_endpoint(request):
    # User ID and verification status are available from middleware
    user_id = request.user_id
    is_verified = request.is_verified
    
    return {
        "message": f"Hello user {user_id}",
        "is_verified": is_verified,
        "data": "Protected data"
    }
```

## Testing Token Validation

```python
from blockauth.utils.token import generate_auth_token, Token

def test_token_validation():
    token_instance = Token(secret_key="test-secret")
    
    # Generate token
    access_token, refresh_token = generate_auth_token(
        token_class=token_instance,
        user_id="test-user",
        user_data={"is_verified": True}
    )
    
    # Validate tokens
    access_payload = token_instance.decode_token(access_token)
    refresh_payload = token_instance.decode_token(refresh_token)
    
    assert access_payload['type'] == "access"
    assert access_payload['is_verified'] == True
    assert refresh_payload['type'] == "refresh"
    assert 'is_verified' not in refresh_payload  # Refresh tokens don't contain user data
```