# BlockAuth Package - AI Assistant Context

## CRITICAL SECURITY NOTICE

**MANDATORY: ALL code MUST comply with [SECURITY_STANDARDS.md](.claude/SECURITY_STANDARDS.md)**

Before writing ANY code, review the security standards. NO EXCEPTIONS.

## Package Overview

**BlockAuth** is a comprehensive Python authentication package that bridges Web2 and Web3, providing JWT authentication, OAuth integration, passwordless login, Web3 wallet authentication, and a KDF system that enables blockchain access without crypto knowledge.

## Critical Features

- **JWT Authentication**: Customizable claims providers, refresh tokens, HS256/RS256/ES256
- **OAuth Integration**: Google, Facebook, LinkedIn providers
- **Web3 Authentication**: Ethereum wallet signature verification
- **KDF System**: Email/password to blockchain wallet generation (PBKDF2, Argon2)
- **Custom Claims**: Pluggable JWT claims architecture via `CustomClaimsProvider`
- **Passwordless**: OTP-based authentication
- **Rate Limiting**: DDoS protection, configurable throttling (per-request + OTP-specific)
- **TOTP/2FA**: Time-based one-time passwords with pluggable storage
- **Passkey/WebAuthn**: FIDO2 passwordless authentication (Face ID, Touch ID, Windows Hello)
- **Step-Up Authentication**: RFC 9470 receipt-based step-up auth (`blockauth.stepup`). Django-independent.

## Package Architecture

```
blockauth/
├── __init__.py              # Lazy imports, __all__ exports
├── apps.py                  # Django AppConfig
├── authentication.py        # DRF authentication backend
├── conf.py                  # Settings (BLOCK_AUTH_SETTINGS defaults)
├── enums.py                 # AuthenticationType enum
├── notification.py          # Notification system (NotificationEvent, send_otp)
├── triggers.py              # Event triggers (BaseTrigger, Dummy* triggers)
├── urls.py                  # Feature-flag-driven URL generation
├── settings.py              # Django settings module
├── constants/               # Constants sub-package
│   ├── core.py             # Features, URLNames, SocialProviders, ConfigKeys
│   └── sensitive_fields.py # Fields to exclude from logs
├── models/                  # Django models
│   ├── user.py             # BlockUser abstract base model
│   └── otp.py              # OTP model + OTPSubject enum
├── views/                   # API views (DRF APIView)
│   ├── basic_auth_views.py # Signup, login, password reset/change, email change, refresh
│   ├── wallet_auth_views.py # Web3 wallet login + email add
│   ├── google_auth_views.py # Google OAuth
│   ├── facebook_auth_views.py # Facebook OAuth
│   └── linkedin_auth_views.py # LinkedIn OAuth
├── serializers/             # DRF serializers
│   ├── otp_serializers.py  # OTP validation
│   ├── user_account_serializers.py # Auth flow serializers
│   └── wallet_serializers.py # Wallet auth serializers
├── jwt/                     # JWT management
│   ├── interfaces.py       # CustomClaimsProvider ABC
│   └── token_manager.py    # JWTTokenManager + jwt_manager singleton
├── utils/                   # Core utilities
│   ├── token.py            # Token class, generate_auth_token, _resolve_keys
│   ├── config.py           # get_config, get_block_auth_user_model
│   ├── validators.py       # BlockAuthPasswordValidator, phone validation
│   ├── permissions.py      # DRF permission classes
│   ├── rate_limiter.py     # RequestThrottle, OTPThrottle
│   ├── logger.py           # blockauth_logger
│   ├── generics.py         # model_to_json, sanitize_log_context
│   ├── audit.py            # Audit utilities
│   ├── custom_exception.py # ValidationErrorWithCode
│   ├── feature_flags.py    # is_feature_enabled
│   ├── social.py           # OAuth helpers
│   └── web3/
│       └── wallet.py       # Web3 wallet utilities
├── kdf/                     # Key Derivation sub-package
│   ├── __init__.py         # Exports (PBKDF2Service, Argon2Service, etc.)
│   ├── constants.py        # SecurityConstants, ErrorMessages, KDFAlgorithms
│   ├── services.py         # PBKDF2Service, Argon2Service, KeyDerivationService, KDFManager
│   └── tests.py            # KDF tests
├── totp/                    # TOTP/2FA sub-package
│   ├── config.py           # TOTP configuration
│   ├── constants.py        # TOTP constants
│   ├── exceptions.py       # TOTP exceptions
│   ├── models.py           # TOTP Django models
│   ├── serializers.py      # TOTP serializers
│   ├── urls.py             # TOTP URL patterns
│   ├── views.py            # TOTP API views
│   ├── services/
│   │   ├── totp_service.py # TOTPService (generate, verify, setup)
│   │   └── encryption.py   # Secret encryption service
│   ├── storage/
│   │   ├── base.py         # ITOTP2FAStore ABC, TOTP2FAData DTO
│   │   └── django_storage.py # Django model storage
│   └── tests/              # TOTP tests
├── passkey/                 # WebAuthn/Passkey sub-package
│   ├── config.py           # Passkey configuration
│   ├── constants.py        # Passkey constants
│   ├── exceptions.py       # Passkey exceptions
│   ├── models.py           # Credential Django model
│   ├── views.py            # Registration + Authentication views
│   ├── utils.py            # WebAuthn utilities
│   ├── services/
│   │   ├── passkey_service.py # PasskeyService (register, authenticate)
│   │   ├── challenge_service.py # Challenge generation
│   │   └── cleanup_service.py # Credential cleanup
│   ├── storage/
│   │   ├── base.py         # ICredentialStore ABC, CredentialData
│   │   ├── django_storage.py # Django model storage
│   │   └── memory_storage.py # In-memory storage (testing)
│   └── tests/              # Passkey tests
├── stepup/                  # Step-up authentication (RFC 9470)
│   ├── __init__.py         # Exports: ReceiptIssuer, ReceiptValidator, ReceiptClaims
│   └── receipt.py          # Django-independent HS256 JWT receipt issue/validate
├── schemas/                 # API documentation schemas
│   ├── factory.py          # Schema factory
│   └── examples/           # Request/response examples
├── docs/                    # Internal API documentation helpers
│   ├── auth_docs.py        # Auth endpoint docs
│   ├── social_auth_docs.py # OAuth endpoint docs
│   └── wallet_auth_docs.py # Wallet endpoint docs
└── migrations/              # Django migrations
```

## API Endpoints

All endpoints are feature-flag controlled via `BLOCK_AUTH_SETTINGS['FEATURES']`.

### Authentication
| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `signup/` | SIGNUP | Register with email/phone + password |
| POST | `signup/otp/resend/` | SIGNUP | Resend signup OTP |
| POST | `signup/confirm/` | SIGNUP | Confirm signup with OTP |
| POST | `login/basic/` | BASIC_LOGIN | Email/password login |
| POST | `login/passwordless/` | PASSWORDLESS_LOGIN | Request passwordless OTP |
| POST | `login/passwordless/confirm/` | PASSWORDLESS_LOGIN | Confirm passwordless login |
| POST | `login/wallet/` | WALLET_LOGIN | Web3 wallet signature auth |
| POST | `token/refresh/` | TOKEN_REFRESH | Refresh JWT tokens |

### Password Management
| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `password/reset/` | PASSWORD_RESET | Request password reset OTP |
| POST | `password/reset/confirm/` | PASSWORD_RESET | Confirm password reset |
| POST | `password/change/` | PASSWORD_CHANGE | Change password (authenticated) |

### Email & Wallet
| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `email/change/` | EMAIL_CHANGE | Request email change OTP |
| POST | `email/change/confirm/` | EMAIL_CHANGE | Confirm email change |
| POST | `wallet/email/add/` | WALLET_EMAIL_ADD | Add email to wallet account |

### OAuth (requires provider configuration)
| Method | Path | Provider | Description |
|--------|------|----------|-------------|
| GET | `google/` | Google | Initiate Google OAuth |
| GET | `google/callback/` | Google | Google OAuth callback |
| GET | `facebook/` | Facebook | Initiate Facebook OAuth |
| GET | `facebook/callback/` | Facebook | Facebook OAuth callback |
| GET | `linkedin/` | LinkedIn | Initiate LinkedIn OAuth |
| GET | `linkedin/callback/` | LinkedIn | LinkedIn OAuth callback |

### Passkey/WebAuthn
| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `passkey/register/options/` | PASSKEY_AUTH | Get registration options |
| POST | `passkey/register/verify/` | PASSKEY_AUTH | Verify registration |
| POST | `passkey/auth/options/` | PASSKEY_AUTH | Get authentication options |
| POST | `passkey/auth/verify/` | PASSKEY_AUTH | Verify authentication |
| GET | `passkey/credentials/` | PASSKEY_AUTH | List credentials |
| DELETE | `passkey/credentials/<uuid>/` | PASSKEY_AUTH | Delete credential |

## Installation & Setup

```bash
# Install from GitHub Releases
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.4.0/blockauth-0.4.0-py3-none-any.whl

# Or from git
pip install git+https://github.com/BloclabsHQ/auth-pack.git@dev
```

```python
# Django settings
INSTALLED_APPS = [
    'blockauth',
]

BLOCK_AUTH_SETTINGS = {
    'SECRET_KEY': 'your-jwt-secret',           # Falls back to Django SECRET_KEY
    'ALGORITHM': 'HS256',                       # HS256, RS256, or ES256
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'OTP_VALIDITY': timedelta(minutes=1),
    'OTP_LENGTH': 6,
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',      # Your user model
    'FEATURES': {
        'SIGNUP': True,
        'BASIC_LOGIN': True,
        'PASSWORDLESS_LOGIN': True,
        'WALLET_LOGIN': True,
        'TOKEN_REFRESH': True,
        'PASSWORD_RESET': True,
        'PASSWORD_CHANGE': True,
        'EMAIL_CHANGE': True,
        'WALLET_EMAIL_ADD': True,
        'SOCIAL_AUTH': True,
        'PASSKEY_AUTH': True,
    },
}

# URLs
urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

## Custom JWT Claims

```python
# myapp/jwt_claims.py
from blockauth.jwt.interfaces import CustomClaimsProvider

class MyAppClaimsProvider(CustomClaimsProvider):
    def get_custom_claims(self, user):
        return {
            "role": user.role,
            "org_id": str(user.organization_id),
        }

    def validate_custom_claims(self, claims):
        return "role" in claims

# Register in Django app's ready()
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider(MyAppClaimsProvider())
```

## KDF System

KDF services live in `blockauth.kdf.services`:

```python
from blockauth.kdf.services import PBKDF2Service, KeyDerivationService, KDFManager

# Direct PBKDF2 derivation
service = PBKDF2Service(iterations=100000)
private_key = service.derive_key(email, password, salt)

# Full key derivation with wallet generation
kds = KeyDerivationService()
private_key = kds.derive_private_key(email, password, salt)
address = kds.get_wallet_address(email, password, salt)

# KDFManager — dual encryption (user + platform keys)
manager = KDFManager(master_key, platform_salt)
```

## Trigger System

BlockAuth fires triggers at key authentication events. Configure trigger classes in settings:

```python
BLOCK_AUTH_SETTINGS = {
    'PRE_SIGNUP_TRIGGER': 'myapp.triggers.MyPreSignupTrigger',
    'POST_SIGNUP_TRIGGER': 'myapp.triggers.MyPostSignupTrigger',
    'POST_LOGIN_TRIGGER': 'myapp.triggers.MyPostLoginTrigger',
    'POST_PASSWORD_CHANGE_TRIGGER': 'myapp.triggers.MyPasswordChangeTrigger',
    'POST_PASSWORD_RESET_TRIGGER': 'myapp.triggers.MyPasswordResetTrigger',
}
```

Trigger context includes `user_id`, `username`, `email`, `trigger_type`, `timestamp`. **Plaintext passwords are never included.**

## Security Requirements

See [SECURITY_STANDARDS.md](.claude/SECURITY_STANDARDS.md) for full details.

Key rules:
- Passwords hashed with Django's `set_password()` (bcrypt recommended)
- JWT tokens use `algorithms=[...]` pinning on decode (no algorithm confusion)
- KDF comparisons use `hmac.compare_digest()` (timing-safe)
- OTP uses `secrets.choice()` (crypto-secure random)
- Rate limiting on all auth endpoints
- No sensitive data in logs (passwords, tokens, keys)
- No `traceback.print_exc()` in production code

## Releasing

Version is tracked in two places (keep in sync):
- `pyproject.toml` → `version = "X.Y.Z"`
- `blockauth/__init__.py` → `__version__ = "X.Y.Z"`

To release:
```bash
# 1. Bump version in both files
# 2. Commit and push to dev
# 3. Tag and push
git tag v0.4.0
git push origin v0.4.0
```

The `publish.yml` workflow validates the tag matches `pyproject.toml`, builds the package, and creates a GitHub Release with sdist + wheel artifacts.

## Testing

```bash
# Run all tests
uv run pytest

# Specific test modules
uv run pytest blockauth/kdf/tests.py
uv run pytest blockauth/totp/tests/
uv run pytest blockauth/passkey/tests/
uv run pytest blockauth/utils/tests/

# Format + lint
uv run black blockauth/
uv run isort blockauth/
uv run flake8 blockauth/
```

## Documentation

- **README.md**: Quick start and overview
- **docs/CUSTOM_JWT_CLAIMS.md**: JWT customization guide
- **docs/JWT_EXTENSION_GUIDE.md**: Extending JWT functionality
- **docs/TOKEN_USAGE_GUIDE.md**: Token class usage
- **docs/WEBAUTHN_PASSKEY_DPIA.md**: Data protection impact assessment

## Common Issues

### fabric-auth Not Picking Up auth-pack Changes

**Symptom**: `ModuleNotFoundError` in fabric-auth CI for modules that exist in auth-pack.

**Cause**: fabric-auth's lockfile pins blockauth to a specific git commit.

**Fix**: After pushing auth-pack changes:
```bash
cd services/fabric-auth
uv lock --upgrade-package blockauth
git add uv.lock && git commit -m "chore: update blockauth to latest dev"
```

### JWT Claims Not Appearing
- Register claims provider in Django app's `ready()` method
- Method must be named `get_custom_claims` (from `CustomClaimsProvider` interface in `jwt/interfaces.py`)
- User object is fetched by `user_id` from `get_block_auth_user_model()`

### OAuth Redirect Issues
- Verify redirect URIs match provider configuration
- Check ALLOWED_HOSTS includes callback domain
- Ensure HTTPS in production

## Platform Integration

BlockAuth is the authentication package for the FabricBloc platform:
- Used by `fabric-auth` service for authentication
- Provides JWT tokens consumed by Kong Gateway
- Supports platform-wide custom claims
- Enables Web3 features for all services

For service-specific authentication implementation, see `fabric-auth`.
