# BlockAuth

Comprehensive Python authentication package bridging Web2 and Web3 for Django REST Framework.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Django 5.x](https://img.shields.io/badge/django-5.x-green.svg)](https://djangoproject.com)

## Features

- **JWT Authentication** — HS256, RS256, ES256 with pluggable custom claims
- **OAuth Integration** — Google, Facebook, LinkedIn
- **Passwordless Login** — OTP-based authentication via email or SMS
- **Web3 Wallet Auth** — Ethereum signature verification (MetaMask, WalletConnect)
- **TOTP / 2FA** — Time-based one-time passwords with pluggable storage
- **WebAuthn / Passkeys** — Face ID, Touch ID, Windows Hello, hardware keys
- **KDF System** — Derive blockchain wallets from email + password (PBKDF2, Argon2)
- **Step-Up Auth** — RFC 9470 receipt-based step-up for sensitive operations
- **Rate Limiting** — Per-endpoint and OTP-specific throttling
- **Feature Flags** — Enable/disable endpoints via configuration

## Quick Start

### Install

```bash
uv add "blockauth @ https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl"
```

Or with pip:

```bash
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl
```

### Configure

```python
# settings.py
INSTALLED_APPS = [
    "blockauth",
    "rest_framework",
]

BLOCK_AUTH_SETTINGS = {
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "BLOCK_AUTH_USER_MODEL": "myapp.User",
}
```

### Add URLs

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path("auth/", include("blockauth.urls")),
]
```

All endpoints are feature-flag controlled. See the [Installation guide](https://github.com/BloclabsHQ/auth-pack/wiki/Installation) for the full settings reference.

## API Endpoints

| Method | Path | Description | Feature Flag |
|--------|------|-------------|-------------|
| POST | `signup/` | Register with email/phone + password | SIGNUP |
| POST | `signup/otp/resend/` | Resend signup / wallet email OTP | SIGNUP |
| POST | `signup/confirm/` | Confirm signup with OTP | SIGNUP |
| POST | `login/basic/` | Email/password login | BASIC_LOGIN |
| POST | `login/passwordless/` | Request passwordless OTP | PASSWORDLESS_LOGIN |
| POST | `login/passwordless/confirm/` | Confirm passwordless login | PASSWORDLESS_LOGIN |
| POST | `login/wallet/` | Web3 wallet signature auth | WALLET_LOGIN |
| POST | `token/refresh/` | Refresh JWT tokens | TOKEN_REFRESH |
| POST | `password/reset/` | Request password reset OTP | PASSWORD_RESET |
| POST | `password/reset/confirm/` | Confirm password reset | PASSWORD_RESET |
| POST | `password/change/` | Change password (authenticated) | PASSWORD_CHANGE |
| POST | `email/change/` | Request email change OTP | EMAIL_CHANGE |
| POST | `email/change/confirm/` | Confirm email change | EMAIL_CHANGE |
| POST | `wallet/email/add/` | Add email to wallet account | WALLET_EMAIL_ADD |
| POST | `passkey/register/options/` | Get WebAuthn registration options | PASSKEY_AUTH |
| POST | `passkey/register/verify/` | Verify WebAuthn registration | PASSKEY_AUTH |
| POST | `passkey/auth/options/` | Get WebAuthn authentication options | PASSKEY_AUTH |
| POST | `passkey/auth/verify/` | Verify WebAuthn authentication | PASSKEY_AUTH |
| GET | `passkey/credentials/` | List user's passkeys | PASSKEY_AUTH |
| DELETE | `passkey/credentials/<id>/` | Revoke a passkey | PASSKEY_AUTH |
| GET | `google/` | Google OAuth login | SOCIAL_AUTH |
| GET | `google/callback/` | Google OAuth callback | SOCIAL_AUTH |
| GET | `facebook/` | Facebook OAuth login | SOCIAL_AUTH |
| GET | `facebook/callback/` | Facebook OAuth callback | SOCIAL_AUTH |
| GET | `linkedin/` | LinkedIn OAuth login | SOCIAL_AUTH |
| GET | `linkedin/callback/` | LinkedIn OAuth callback | SOCIAL_AUTH |

Full endpoint documentation: [API Endpoints](https://github.com/BloclabsHQ/auth-pack/wiki/API-Endpoints)

## Custom JWT Claims

Add custom data to JWT tokens with pluggable claims providers:

```python
from blockauth.jwt.interfaces import CustomClaimsProvider

class MyClaimsProvider(CustomClaimsProvider):
    def get_custom_claims(self, user) -> dict:
        return {"role": user.role, "org_id": str(user.org_id)}

    def validate_custom_claims(self, claims: dict) -> bool:
        return "role" in claims
```

Register in your Django app's `ready()` method:

```python
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider(MyClaimsProvider())
```

Full guide: [Custom JWT Claims](https://github.com/BloclabsHQ/auth-pack/wiki/Custom-JWT-Claims)

## Documentation

Full documentation is available on the [Wiki](https://github.com/BloclabsHQ/auth-pack/wiki):

| Page | Description |
|------|-------------|
| [Installation](https://github.com/BloclabsHQ/auth-pack/wiki/Installation) | Setup, configuration, all settings |
| [API Endpoints](https://github.com/BloclabsHQ/auth-pack/wiki/API-Endpoints) | Complete endpoint reference |
| [Custom JWT Claims](https://github.com/BloclabsHQ/auth-pack/wiki/Custom-JWT-Claims) | Extending JWT tokens |
| [KDF System](https://github.com/BloclabsHQ/auth-pack/wiki/KDF-System) | Key derivation for wallets |
| [TOTP and Passkeys](https://github.com/BloclabsHQ/auth-pack/wiki/TOTP-and-Passkeys) | Multi-factor authentication |
| [Step-Up Authentication](https://github.com/BloclabsHQ/auth-pack/wiki/Step-Up-Authentication) | RFC 9470 receipts |
| [Triggers and Notifications](https://github.com/BloclabsHQ/auth-pack/wiki/Triggers-and-Notifications) | Event hooks |
| [Security](https://github.com/BloclabsHQ/auth-pack/wiki/Security) | Security standards |
| [Releasing](https://github.com/BloclabsHQ/auth-pack/wiki/Releasing) | Versioning and publishing |

## Requirements

- Python >= 3.12
- Django >= 5.0, < 6.0
- Django REST Framework >= 3.14

## Development

```bash
git clone https://github.com/BloclabsHQ/auth-pack.git
cd auth-pack
uv sync
uv run pytest
make check  # format + lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Security

If you discover a security vulnerability, please email **security@bloclabs.com** instead of opening a public issue. See [SECURITY.md](SECURITY.md) for details.

## License

MIT License. See [LICENSE](LICENSE) for details.
