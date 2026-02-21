# BlockAuth Package - AI Assistant Context

## ⚠️ CRITICAL SECURITY NOTICE

**MANDATORY: ALL code MUST comply with [SECURITY_STANDARDS.md](.claude/SECURITY_STANDARDS.md)**

Before writing ANY code, review the security standards. NO EXCEPTIONS.

## Package Overview

**BlockAuth** is a comprehensive Python authentication package that bridges Web2 and Web3, providing JWT authentication, OAuth integration, passwordless login, Web3 wallet authentication, and a revolutionary KDF system that enables blockchain access without crypto knowledge.

## 🎯 Critical Features

- **JWT Authentication**: Customizable claims providers, refresh tokens, revocation
- **OAuth Integration**: Google, Facebook, LinkedIn, GitHub providers
- **Web3 Authentication**: Ethereum wallet signature verification
- **KDF System**: Email/password → blockchain wallet generation
- **Custom Claims**: Pluggable JWT claims architecture
- **Passwordless**: OTP-based authentication
- **Rate Limiting**: DDoS protection, configurable throttling
- **MFA Support**: TOTP, SMS, email verification
- **Step-Up Authentication**: RFC 9470 receipt-based step-up auth (`blockauth.stepup`). Django-independent.

## Package Architecture

```
blockauth/
├── models/              # Django models
│   ├── user.py         # BlockUser base model
│   ├── session.py      # Session management
│   └── wallet.py       # Web3 wallet models
├── views/              # API views
│   ├── basic_auth.py   # Email/password authentication
│   ├── oauth_views.py  # OAuth provider views
│   ├── wallet_auth.py  # Web3 wallet authentication
│   └── passwordless.py # OTP-based authentication
├── serializers/        # DRF serializers
│   ├── auth.py        # Authentication serializers
│   ├── user.py        # User data serializers
│   └── token.py       # Token serializers
├── utils/              # Core utilities
│   ├── token.py       # JWT token generation
│   ├── kdf.py         # Key derivation functions
│   ├── crypto.py      # Cryptographic operations
│   └── validators.py  # Input validation
├── jwt/                # JWT management
│   ├── token_manager.py # JWT manager with claims
│   └── claims.py      # Claims provider base
├── middleware/         # Django middleware
├── permissions/        # Permission classes
├── stepup/            # Step-up authentication receipts (RFC 9470)
│   ├── __init__.py   # Exports: ReceiptIssuer, ReceiptValidator, ReceiptClaims, ReceiptValidationError
│   └── receipt.py    # Django-independent HS256 JWT receipt issue/validate
└── tests/             # Comprehensive test suite
```

## Installation & Setup

```bash
# Install package
pip install blockauth

# Django settings
INSTALLED_APPS = [
    'blockauth',
    # ...
]

# Configure BlockAuth
BLOCK_AUTH_SETTINGS = {
    'JWT_SECRET_KEY': 'your-secret-key',
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'KDF_ENABLED': True,
    'KDF_ITERATIONS': 100000,
    # ... more settings
}

# Add URLs
urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

## 🔐 Custom JWT Claims

### Creating a Claims Provider

```python
# myapp/jwt_claims.py
class MyAppClaimsProvider:
    def __init__(self):
        self.name = "myapp"

    def get_custom_claims(self, user):
        """Add custom claims to JWT."""
        return {
            "user_id": str(user.id),
            "role": user.role,
            "organization_id": str(user.organization_id),
            "is_verified": user.is_verified,
        }

# Register in Django app
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider(MyAppClaimsProvider())
```

### Token Structure

```json
{
  "user_id": "uuid",
  "role": "admin",
  "organization_id": "org-uuid",
  "is_verified": true,
  "exp": 1234567890,
  "iat": 1234567800,
  "type": "access"
}
```

## 🚀 KDF System (Key Derivation)

The KDF system enables Web2 users to have blockchain wallets without managing keys:

```python
# Enable KDF
BLOCK_AUTH_SETTINGS = {
    'KDF_ENABLED': True,
    'KDF_ITERATIONS': 100000,  # Security level
    'KDF_MASTER_SALT': 'master-salt',
    'MASTER_ENCRYPTION_KEY': '0x' + '64-hex-chars',
    'PLATFORM_MASTER_SALT': 'platform-salt',
}

# Usage
from blockauth.utils.kdf import derive_key

# Generate blockchain wallet from email/password
private_key = derive_key(email, password)
wallet_address = generate_wallet_address(private_key)
```

## 🔄 Authentication Flows

### Basic Authentication
```python
# Login endpoint
POST /auth/login/
{
    "email": "user@example.com",
    "password": "secure-password"
}

# Response
{
    "access": "jwt-access-token",
    "refresh": "jwt-refresh-token"
}
```

### OAuth Flow
```python
# Redirect to provider
GET /auth/google/login/

# Handle callback
GET /auth/google/callback/?code=...

# Automatic user creation and JWT generation
```

### Web3 Authentication
```python
# Wallet login
POST /auth/wallet/login/
{
    "wallet_address": "0x...",
    "message": "Sign this message",
    "signature": "0x..."
}
```

## 🛡️ MANDATORY SECURITY IMPLEMENTATION

### ⚠️ Security Standards Compliance
**EVERY line of code MUST comply with [SECURITY_STANDARDS.md](.claude/SECURITY_STANDARDS.md)**

### Critical Security Requirements

#### Password Security (MANDATORY)
```python
# MINIMUM Requirements - NO EXCEPTIONS
BCRYPT_ROUNDS = 14  # NEVER less than 14
PASSWORD_MIN_LENGTH = 12  # NEVER less than 12
PBKDF2_ITERATIONS = 600_000  # NIST 2024 minimum

# MANDATORY password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(14))
```

#### JWT Security (MANDATORY)
```python
JWT_SETTINGS = {
    'SECRET_KEY': secrets.token_hex(32),  # MINIMUM 256 bits
    'ALGORITHM': 'HS256',  # ONLY HS256 allowed
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),  # MAXIMUM 15 minutes
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,  # MANDATORY
    'BLACKLIST_AFTER_ROTATION': True,  # MANDATORY
}
```

#### Rate Limiting (MANDATORY)
```python
RATE_LIMITS = {
    'login': '5/minute',  # MAXIMUM
    'register': '3/hour',
    'password_reset': '3/hour',
    'wallet_creation': '3/hour',
    'kdf_derivation': '10/hour',
}
```

#### KDF Security (MANDATORY)
```python
KDF_SETTINGS = {
    'ITERATIONS': 600_000,  # NIST 2024 MINIMUM
    'KEY_LENGTH': 32,  # 256 bits MINIMUM
    'SALT_LENGTH': 32,  # MINIMUM
    'DUAL_ENCRYPTION': True,  # User + Platform keys
}
```

#### Web3 Security (MANDATORY)
- **Never store plain private keys**
- **Always validate signatures**
- **Prevent zero address**
- **Check signature malleability**
- **Validate message size (max 10KB)**

### Security Checklist (MUST PASS)
- [ ] No hardcoded secrets
- [ ] No sensitive data in logs
- [ ] Passwords hashed with bcrypt(14+)
- [ ] JWT tokens < 15 minutes
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] CSRF tokens
- [ ] Security headers configured

## 📊 Testing

```bash
# Run all tests
pytest

# Run specific test module
pytest blockauth/tests/test_jwt.py

# Coverage report
pytest --cov=blockauth --cov-report=html

# Security tests
pytest -m security
```

## 🔧 Development Commands

```bash
# Format code
black blockauth/
isort blockauth/

# Lint
flake8 blockauth/
pylint blockauth/

# Security scan
bandit -r blockauth/
safety check

# Type checking
mypy blockauth/
```

## 📚 Documentation

- **README.md**: Quick start and overview
- **docs/CUSTOM_JWT_CLAIMS.md**: JWT customization guide
- **docs/KDF_SYSTEM.md**: Key derivation documentation
- **docs/API_REFERENCE.md**: Complete API docs
- **docs/SECURITY.md**: Security best practices

## ⚠️ Common Issues

### fabric-auth Not Picking Up auth-pack Changes

**Symptom**: `ModuleNotFoundError` in fabric-auth CI for modules that exist in auth-pack.

**Cause**: `fabric-auth/poetry.lock` pins blockauth to a specific git commit. Pushing
to auth-pack does NOT auto-update the lock file.

**Fix**: After pushing auth-pack changes, update fabric-auth:
```bash
cd services/fabric-auth
poetry update blockauth
git add poetry.lock && git commit -m "chore: update blockauth to latest dev"
```

See `fabric-auth/CLAUDE.md` → "Updating blockauth" section for full details.

### JWT Claims Not Appearing
- Ensure claims provider is registered in Django app's `ready()` method
- Method must be named `get_custom_claims` (not `get_claims`)
- Check user object is being passed correctly

### OAuth Redirect Issues
- Verify redirect URIs match provider configuration
- Check ALLOWED_HOSTS includes callback domain
- Ensure HTTPS in production

### KDF Performance
- High iteration count impacts performance
- Consider async processing for wallet generation
- Cache derived keys securely

## 🎯 Best Practices

### Security
- **Never log sensitive data** (passwords, tokens, keys)
- **Always use HTTPS** in production
- **Implement rate limiting** on all auth endpoints
- **Rotate secrets** regularly
- **Audit dependencies** for vulnerabilities

### Performance
- **Cache JWT claims** for expensive calculations
- **Use database indexes** on frequently queried fields
- **Implement connection pooling**
- **Optimize token validation**

### Code Quality
- **Write tests** for all authentication flows
- **Document API changes**
- **Use type hints**
- **Follow PEP 8**
- **Security-focused code reviews**

## 🚀 Advanced Features

### Multi-Factor Authentication
```python
BLOCK_AUTH_SETTINGS = {
    'MFA_ENABLED': True,
    'MFA_METHODS': ['totp', 'sms', 'email'],
}
```

### Session Management
```python
# Concurrent session limiting
BLOCK_AUTH_SETTINGS = {
    'MAX_SESSIONS_PER_USER': 3,
    'SESSION_TIMEOUT': timedelta(hours=24),
}
```

### Webhook Events
```python
# Authentication events
BLOCK_AUTH_SETTINGS = {
    'WEBHOOKS': {
        'user.login': 'https://api.example.com/webhooks/login',
        'user.register': 'https://api.example.com/webhooks/register',
    }
}
```

## 🆘 Support Resources

- **Package Location**: `/services/auth-pack/`
- **Documentation**: `/services/auth-pack/docs/`
- **Examples**: `/services/auth-pack/blockauth-demo/`
- **Tests**: `/services/auth-pack/blockauth/tests/`
- **Claude Agents**: `/.claude/agents/`
- **Hooks**: `/.claude/hooks/`

## Platform Integration

BlockAuth is designed to work seamlessly with the FabricBloc platform:
- Used by `fabric-auth` service for authentication
- Provides JWT tokens for Kong Gateway
- Supports platform-wide custom claims
- Enables Web3 features for all services

---

**Note**: This is the authentication package used across the FabricBloc platform. For service-specific authentication implementation, see `/services/fabric-auth/`.