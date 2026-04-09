# BlockAuth

**The authentication package that bridges Web2 and Web3.**

BlockAuth gives your Django application a complete auth system out of the box — from traditional email/password login to MetaMask wallet signatures, passkeys, and TOTP 2FA. One package, one config, every auth method your users need.

---

<div class="grid cards" markdown>

-   :material-shield-lock:{ .lg .middle } **Security First**

    ---

    Timing-safe comparisons, progressive lockout, token rotation, replay protection, encrypted TOTP secrets. Audited and hardened.

-   :material-puzzle:{ .lg .middle } **Plug and Play**

    ---

    Install, inherit `BlockUser`, add your URLs. Feature flags let you enable only what you need — no dead code.

-   :material-web:{ .lg .middle } **Web2 + Web3**

    ---

    Email login, OAuth (Google/Facebook/LinkedIn), passwordless OTP, Ethereum wallet auth, and KDF wallet generation — all in one package.

-   :material-test-tube:{ .lg .middle } **Battle Tested**

    ---

    333 tests covering every endpoint. View-level tests, integration flows, and security-focused test suites.

</div>

---

## What's Included

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | HS256, RS256, ES256 with custom claims providers and token refresh/rotation |
| **OAuth Providers** | Google, Facebook, LinkedIn — configured in settings, no extra apps |
| **Passwordless Login** | OTP via email or SMS with configurable expiry and rate limiting |
| **Web3 Wallet Auth** | Ethereum signature verification with nonce + timestamp replay protection |
| **Passkeys / WebAuthn** | FIDO2 passwordless — Face ID, Touch ID, Windows Hello, hardware keys |
| **TOTP 2FA** | RFC 6238 with encrypted secrets, backup codes, and verification logging |
| **Step-Up Auth** | RFC 9470 receipt-based step-up authentication for sensitive operations |
| **KDF System** | Derive blockchain wallets from email/password — no crypto knowledge needed |
| **Rate Limiting** | Per-endpoint throttling with progressive lockout after failed attempts |
| **Feature Flags** | Enable/disable any auth method independently via `BLOCK_AUTH_SETTINGS` |
| **Cleanup Command** | `blockauth_cleanup` management command for expired OTPs, challenges, logs |

## Quick Install

```bash
pip install git+https://github.com/BloclabsHQ/auth-pack.git@v0.4.0
```

```python
# settings.py
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'blockauth',
]

BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
    'SECRET_KEY': 'your-jwt-secret',
    'FEATURES': {
        'SIGNUP': True,
        'BASIC_LOGIN': True,
        'WALLET_LOGIN': True,
        'PASSKEY_AUTH': True,
        # Enable only what you need
    },
}

# urls.py
urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

Then create your user model:

```python
# myapp/models.py
from blockauth.models.user import BlockUser

class User(BlockUser):
    class Meta:
        managed = True
        db_table = "users"
```

**[Get started in 5 minutes :material-arrow-right:](getting-started/quick-start.md)**

## API Endpoints

All endpoints are feature-flag controlled. Enable what you need, disable what you don't.

```
POST /auth/signup/                    # Register with email + password
POST /auth/signup/confirm/            # Verify OTP
POST /auth/login/basic/               # Email + password login
POST /auth/login/passwordless/        # Request passwordless OTP
POST /auth/login/wallet/              # Web3 wallet signature login
POST /auth/token/refresh/             # Refresh JWT tokens
POST /auth/password/reset/            # Request password reset
POST /auth/password/change/           # Change password (authenticated)
POST /auth/passkey/register/options/  # WebAuthn registration
POST /auth/passkey/auth/verify/       # WebAuthn authentication
GET  /auth/google/                    # Google OAuth redirect
GET  /auth/facebook/                  # Facebook OAuth redirect
GET  /auth/linkedin/                  # LinkedIn OAuth redirect
```

**[Full endpoint reference :material-arrow-right:](reference/api-endpoints.md)**

## Architecture

```
blockauth/
├── jwt/         # Token management, custom claims
├── views/       # DRF API views for all endpoints
├── serializers/  # Request/response validation
├── models/      # BlockUser (abstract), OTP
├── totp/        # TOTP 2FA with pluggable storage
├── passkey/     # WebAuthn/FIDO2 authentication
├── stepup/      # RFC 9470 step-up auth receipts
├── kdf/         # Key derivation (PBKDF2, Argon2)
└── utils/       # Rate limiting, validators, crypto
```

## License

MIT
