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
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "access"
}
```

**Refresh Token:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "type": "refresh"
}
```

### Claims
- `user_id`: User's UUID in standard format with hyphens
- `exp`: Expiration timestamp
- `iat`: Issued at timestamp
- `type`: Token type ("access" or "refresh")

## Using BlockAuth Tokens in External Services

### 1. Install BlockAuth Package

```bash
pip install blockauth
```

### 2. Basic Token Generation

```python
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

# Generate tokens for a user
user_id = "550e8400-e29b-41d4-a716-446655440000"  # User's UUID with hyphens
access_token, refresh_token = generate_auth_token(
    token_class=AUTH_TOKEN_CLASS(),
    user_id=user_id,
    user_data={}  # Include user verification status
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
    user_id="550e8400-e29b-41d4-a716-446655440000",
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
            user_id=payload['user_id']
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
        user_id=str(user.id),
        user_data={}
    )
    
    return {
        "access": access_token,
        "refresh": refresh_token,
        "user_id": str(user.id)
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
        user_id="test-user"
    )
    
    # Validate tokens
    access_payload = token_instance.decode_token(access_token)
    refresh_payload = token_instance.decode_token(refresh_token)
    
    assert access_payload['type'] == "access"
    assert access_payload['is_verified'] == True
    assert refresh_payload['type'] == "refresh"
    assert 'is_verified' not in refresh_payload  # Refresh tokens don't contain user data
```

## Authentication Flow Overview

BlockAuth implements a comprehensive JWT-based authentication system with access and refresh tokens. This section explains the complete authentication flow and how tokens are utilized across different services.

### Authentication Flow Diagram

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │  Auth       │    │  Token      │    │  Protected  │
│  (Frontend) │    │  Service    │    │  Validator  │    │  Service    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ 1. Login Request  │                   │                   │
       │ ──────────────────►│                   │                   │
       │                   │                   │                   │
       │                   │ 2. Authenticate   │                   │
       │                   │ User              │                   │
       │                   │ ┌─────────────┐   │                   │
       │                   │ │ Validate    │   │                   │
       │                   │ │ Credentials │   │                   │
       │                   │ └─────────────┘   │                   │
       │                   │                   │                   │
       │                   │ 3. Generate      │                   │
       │                   │ Tokens           │                   │
       │                   │ ┌─────────────┐   │                   │
       │                   │ │ Access Token│   │                   │
       │                   │ │ Refresh     │   │                   │
       │                   │ │ Token       │   │                   │
       │                   │ └─────────────┘   │                   │
       │                   │                   │                   │
       │ 4. Return Tokens  │                   │                   │
       │ ◄──────────────────│                   │                   │
       │                   │                   │                   │
       │ 5. API Request    │                   │                   │
       │ + Access Token    │                   │                   │
       │ ─────────────────────────────────────►│                   │
       │                   │                   │                   │
       │                   │ 6. Validate      │                   │
       │                   │ Token            │                   │
       │                   │ ┌─────────────┐   │                   │
       │                   │ │ Decode JWT  │   │                   │
       │                   │ │ Verify      │   │                   │
       │                   │ │ Signature   │   │                   │
       │                   │ │ Check Exp   │   │                   │
       │                   │ └─────────────┘   │                   │
       │                   │                   │                   │
       │                   │ 7. Forward       │                   │
       │                   │ Request + User   │                   │
       │                   │ ─────────────────►│                   │
       │                   │                   │                   │
       │                   │ 8. Process       │                   │
       │                   │ Request          │                   │
       │                   │ ┌─────────────┐   │                   │
       │                   │ │ Access      │   │                   │
       │                   │ │ User Data   │   │                   │
       │                   │ │ Return      │   │                   │
       │                   │ │ Response    │   │                   │
       │                   │ └─────────────┘   │                   │
       │                   │                   │                   │
       │ 9. Response       │                   │                   │
       │ ◄─────────────────────────────────────│                   │
       │                   │                   │                   │
       │ 10. Token Expired │                   │                   │
       │ + Refresh Token   │                   │                   │
       │ ──────────────────►│                   │                   │
       │                   │                   │                   │
       │                   │ 11. Validate     │                   │
       │                   │ Refresh Token    │                   │
       │                   │ ┌─────────────┐   │                   │
       │                   │ │ Decode      │   │                   │
       │                   │ │ Refresh JWT │   │                   │
       │                   │ │ Generate    │   │                   │
       │                   │ │ New Tokens  │   │                   │
       │                   │ └─────────────┘   │                   │
       │                   │                   │                   │
       │ 12. New Tokens    │                   │                   │
       │ ◄──────────────────│                   │                   │
       │                   │                   │                   │
```

### Detailed Flow Explanation

#### Phase 1: Initial Authentication
1. **Login Request**: Client sends credentials to authentication service
2. **User Validation**: Service validates credentials against user database
3. **Token Generation**: BlockAuth generates access and refresh tokens
4. **Token Response**: Tokens are returned to client for storage

#### Phase 2: API Access
5. **API Request**: Client includes access token in Authorization header
6. **Token Validation**: Middleware/validator decodes and validates token
7. **Request Forwarding**: Validated request with user context is forwarded
8. **Response Processing**: Protected service processes request and returns data

#### Phase 3: Token Refresh
9. **Token Expiration**: Access token expires (typically 1 hour)
10. **Refresh Request**: Client sends refresh token to auth service
11. **Token Renewal**: Service validates refresh token and issues new tokens
12. **New Tokens**: Client receives new access and refresh tokens

### Token Lifecycle Management

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOKEN LIFECYCLE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Login     │    │   Access    │    │   Refresh   │    │   Logout    │  │
│  │  Success    │───►│   Token     │───►│   Token     │───►│   Clear     │  │
│  │             │    │   Expires   │    │   Expires   │    │   Client    │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                   │                   │                   │      │
│         ▼                   ▼                   ▼                   ▼      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ Generate    │    │ Use Refresh │    │ Force       │    │ Clear       │  │
│  │ Both Tokens │    │ Token to    │    │ Re-login    │    │ Client      │  │
│  │             │    │ Get New     │    │ Required    │    │ Storage     │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Considerations

#### Token Storage
- **Access Tokens**: Store in memory (JavaScript variables) for web apps
- **Refresh Tokens**: Store in secure HTTP-only cookies or secure storage
- **Never**: Store tokens in localStorage (vulnerable to XSS)

#### Token Validation
- **Signature Verification**: Ensures token integrity
- **Expiration Check**: Prevents use of expired tokens
- **Algorithm Validation**: Prevents algorithm confusion attacks
- **Claim Validation**: Verifies required claims exist

#### Token Rotation
- **Access Tokens**: Short-lived (1 hour) to minimize exposure
- **Refresh Tokens**: Longer-lived (7 days) but can be revoked
- **Automatic Rotation**: New refresh token issued with each refresh

### Microservice Integration Patterns

#### Pattern 1: Centralized Authentication
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │  Auth       │    │  Service A  │
│             │    │  Service    │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │ 1. Login          │                   │
       │ ──────────────────►│                   │
       │                   │                   │
       │ 2. Tokens         │                   │
       │ ◄──────────────────│                   │
       │                   │                   │
       │ 3. API Call       │                   │
       │ + Token           │                   │
       │ ─────────────────────────────────────►│
       │                   │                   │
       │ 4. Validate       │                   │
       │ Token             │                   │
       │ ┌─────────────┐   │                   │
       │ │ Decode JWT  │   │                   │
       │ │ Check Claims│   │                   │
       │ └─────────────┘   │                   │
       │                   │                   │
       │ 5. Response       │                   │
       │ ◄─────────────────────────────────────│
```

#### Pattern 2: Distributed Validation
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │  Auth       │    │  Service A  │    │  Service B  │
│             │    │  Service    │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ 1. Login          │                   │                   │
       │ ──────────────────►│                   │                   │
       │                   │                   │                   │
       │ 2. Tokens         │                   │                   │
       │ ◄──────────────────│                   │                   │
       │                   │                   │
       │ 3. API Call A     │                   │                   │
       │ + Token           │                   │                   │
       │ ─────────────────────────────────────►│                   │
       │                   │                   │                   │
       │ 4. Validate A     │                   │                   │
       │ ┌─────────────┐   │                   │                   │
       │ │ Local JWT   │   │                   │                   │
       │ │ Validation  │   │                   │                   │
       │ └─────────────┘   │                   │                   │
       │                   │                   │                   │
       │ 5. API Call B     │                   │                   │
       │ + Same Token      │                   │                   │
       │ ─────────────────────────────────────────────────────────►│
       │                   │                   │                   │
       │ 6. Validate B     │                   │                   │
       │ ┌─────────────┐   │                   │                   │
       │ │ Local JWT   │   │                   │                   │
       │ │ Validation  │   │                   │                   │
       │ └─────────────┘   │                   │                   │
```

### Error Handling Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ERROR HANDLING FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Token     │    │   Token     │    │   Token     │    │   Token     │  │
│  │   Missing   │    │   Expired   │    │   Invalid   │    │   Malformed │  │
│  │             │    │             │    │   Signature │    │             │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                   │                   │                   │      │
│         ▼                   ▼                   ▼                   ▼      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ Return 401  │    │ Return 401  │    │ Return 401  │    │ Return 401  │  │
│  │ "Missing    │    │ "Token      │    │ "Invalid    │    │ "Malformed  │  │
│  │  Token"     │    │  Expired"   │    │  Token"     │    │  Token"     │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                   │                   │                   │      │
│         ▼                   ▼                   ▼                   ▼      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ Client      │    │ Client      │    │ Client      │    │ Client      │  │
│  │ Redirect    │    │ Use Refresh │    │ Clear       │    │ Clear       │  │
│  │ to Login    │    │ Token       │    │ Tokens      │    │ Tokens      │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Best Practices

#### For Token Generation
- Use strong, unique secret keys
- Set appropriate token lifetimes
- Include minimal necessary claims
- Use HTTPS for all token transmission

#### For Token Validation
- Always verify token signature
- Check token expiration
- Validate token type (access vs refresh)
- Handle all validation errors gracefully

#### For Token Storage
- Store access tokens in memory only
- Use secure storage for refresh tokens
- Implement automatic token refresh
- Clear tokens on logout

#### For Security
- Monitor for suspicious token usage
- Use rate limiting on auth endpoints
- Log authentication events

## Token Validation Examples

Simple examples showing how to validate BlockAuth tokens using the secret key in third-party applications.

### Python Example

```python
import jwt
from datetime import datetime

def validate_blockauth_token(token_string, secret_key):
    """
    Validate BlockAuth token using secret key.
    
    Args:
        token_string (str): The JWT token from BlockAuth
        secret_key (str): The secret key used to sign the token
    
    Returns:
        dict: Token payload if valid, None if invalid
    """
    try:
        # Decode and verify token
        payload = jwt.decode(
            token_string,
            secret_key,
            algorithms=["HS256"],
            options={"verify_signature": True, "verify_exp": True}
        )
        
        # Check required claims
        if 'user_id' not in payload or 'type' not in payload:
            return None
            
        return payload
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidSignatureError:
        print("Invalid token signature")
        return None
    except Exception as e:
        print(f"Token validation failed: {e}")
        return None

# Usage example
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Your BlockAuth token
secret_key = "your-secret-key-here"  # The secret key used by BlockAuth

result = validate_blockauth_token(token, secret_key)
if result:
    print(f"Valid token for user: {result['user_id']}")
    print(f"Token type: {result['type']}")
    print(f"Expires: {datetime.fromtimestamp(result['exp'])}")
else:
    print("Invalid token")
```

### JavaScript Example

```javascript
const jwt = require('jsonwebtoken');

function validateBlockAuthToken(tokenString, secretKey) {
    /**
     * Validate BlockAuth token using secret key.
     * 
     * @param {string} tokenString - The JWT token from BlockAuth
     * @param {string} secretKey - The secret key used to sign the token
     * @returns {object|null} Token payload if valid, null if invalid
     */
    try {
        // Decode and verify token
        const payload = jwt.verify(tokenString, secretKey, {
            algorithms: ['HS256'],
            ignoreExpiration: false
        });
        
        // Check required claims
        if (!payload.user_id || !payload.type) {
            return null;
        }
        
        return payload;
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            console.log('Token has expired');
        } else if (error.name === 'JsonWebTokenError') {
            console.log('Invalid token signature');
        } else {
            console.log(`Token validation failed: ${error.message}`);
        }
        return null;
    }
}

// Usage example
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // Your BlockAuth token
const secretKey = "your-secret-key-here"; // The secret key used by BlockAuth

const result = validateBlockAuthToken(token, secretKey);
if (result) {
    console.log(`Valid token for user: ${result.user_id}`);
    console.log(`Token type: ${result.type}`);
    console.log(`Expires: ${new Date(result.exp * 1000)}`);
} else {
    console.log('Invalid token');
}
```