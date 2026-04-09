# BlockAuth

Comprehensive Python authentication package bridging Web2 and Web3. Built on Django and Django REST Framework.

BlockAuth provides JWT authentication, OAuth integration, passwordless login, Web3 wallet authentication, TOTP/2FA, WebAuthn passkeys, step-up authentication, and a KDF system that enables blockchain access without crypto knowledge.

## Features

- **JWT Authentication** -- HS256, RS256, ES256 with customizable claims providers and refresh tokens
- **OAuth Integration** -- Google, Facebook, LinkedIn providers
- **Passwordless Login** -- OTP-based authentication via email
- **Web3 Wallet Auth** -- Ethereum wallet signature verification (MetaMask, etc.)
- **Passkey/WebAuthn** -- FIDO2 passwordless with Face ID, Touch ID, Windows Hello
- **TOTP/2FA** -- Time-based one-time passwords with pluggable storage
- **Step-Up Auth** -- RFC 9470 receipt-based step-up authentication
- **KDF System** -- Email/password to blockchain wallet generation (PBKDF2, Argon2)
- **Rate Limiting** -- Per-request and OTP-specific throttling
- **Feature Flags** -- Enable/disable any auth feature independently
- **Custom JWT Claims** -- Pluggable claims provider architecture
- **Trigger System** -- Hooks for signup, login, password change events

## Quick Install

```bash
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl
```

```python
# settings.py
INSTALLED_APPS = [
    'rest_framework',
    'blockauth',
]

BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
}

# urls.py
urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

See the [Quick Start](getting-started/quick-start.md) guide for a complete walkthrough.

## Architecture

BlockAuth is organized into focused sub-packages:

| Package | Purpose |
|---------|---------|
| `blockauth.jwt` | JWT token management and custom claims |
| `blockauth.kdf` | Key derivation for Web2-to-Web3 bridging |
| `blockauth.totp` | TOTP/2FA with pluggable storage |
| `blockauth.passkey` | WebAuthn/FIDO2 passkey authentication |
| `blockauth.stepup` | RFC 9470 step-up authentication receipts |
| `blockauth.views` | DRF API views for all auth endpoints |
| `blockauth.utils` | Rate limiting, validators, permissions |

## License

MIT
