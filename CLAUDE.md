# BlockAuth — AI Assistant Context

**MANDATORY: ALL code MUST comply with [SECURITY_STANDARDS.md](.claude/SECURITY_STANDARDS.md)**

## Overview

BlockAuth is a Django REST Framework authentication package bridging Web2 and Web3. Version 0.3.0, MIT licensed, uses uv for package management.

## Architecture

```
blockauth/
├── authentication.py        # DRF auth backend (JWTAuthentication)
├── conf.py                  # BLOCK_AUTH_SETTINGS defaults
├── urls.py                  # Feature-flag-driven URL generation
├── notification.py          # BaseNotification, NotificationEvent, send_otp
├── triggers.py              # BaseTrigger, Dummy* triggers
├── enums.py                 # AuthenticationType enum
├── jwt/
│   ├── interfaces.py       # CustomClaimsProvider ABC
│   └── token_manager.py    # JWTTokenManager, jwt_manager singleton
├── utils/
│   ├── token.py            # Token class, generate_auth_token, _resolve_keys
│   ├── config.py           # get_config, get_block_auth_user_model
│   ├── validators.py       # BlockAuthPasswordValidator
│   ├── rate_limiter.py     # RequestThrottle, OTPThrottle
│   └── web3/wallet.py      # WalletAuthenticator (signature verification)
├── kdf/
│   ├── services.py         # PBKDF2Service, Argon2Service, KeyDerivationService, KDFManager
│   └── constants.py        # SecurityConstants, ErrorMessages
├── totp/                    # TOTP 2FA (pluggable storage: ITOTP2FAStore)
├── passkey/                 # WebAuthn/FIDO2 (pluggable storage: ICredentialStore)
├── stepup/receipt.py        # RFC 9470 receipts (Django-independent)
├── views/                   # basic_auth_views, wallet_auth_views, google/facebook/linkedin
├── serializers/             # otp_serializers, user_account_serializers, wallet_serializers
└── models/                  # user.py (BlockUser), otp.py (OTP, OTPSubject)
```

## Key Endpoints (from urls.py)

| Path | View | Feature Flag |
|------|------|-------------|
| `login/basic/` | BasicAuthLoginView | BASIC_LOGIN |
| `login/passwordless/` | PasswordlessLoginView | PASSWORDLESS_LOGIN |
| `login/wallet/` | WalletAuthLoginView | WALLET_LOGIN |
| `token/refresh/` | AuthRefreshTokenView | TOKEN_REFRESH |
| `signup/` | SignUpView | SIGNUP |
| `password/reset/` | PasswordResetView | PASSWORD_RESET |
| `password/change/` | PasswordChangeView | PASSWORD_CHANGE |
| `passkey/register/options/` | PasskeyRegistrationOptionsView | PASSKEY_AUTH |

## Settings (conf.py DEFAULTS)

Key settings in `BLOCK_AUTH_SETTINGS`:
- `SECRET_KEY` — JWT signing key (falls back to Django SECRET_KEY)
- `ALGORITHM` — HS256 (default), RS256, ES256
- `ACCESS_TOKEN_LIFETIME` — timedelta (default: 1 hour)
- `REFRESH_TOKEN_LIFETIME` — timedelta (default: 1 day)
- `BLOCK_AUTH_USER_MODEL` — dotted path to user model
- `FEATURES` — dict of feature flags (all True by default)
- Triggers: `PRE_SIGNUP_TRIGGER`, `POST_SIGNUP_TRIGGER`, `POST_LOGIN_TRIGGER`, `POST_PASSWORD_CHANGE_TRIGGER`, `POST_PASSWORD_RESET_TRIGGER`
- `DEFAULT_NOTIFICATION_CLASS` — notification handler

## Security Rules

- Use `hmac.compare_digest()` for all cryptographic comparisons
- Pin JWT algorithms on decode: `algorithms=[self.algorithm]`
- Never log passwords, tokens, or private keys
- No `traceback.print_exc()` in production code
- No mock users with fabricated data
- OTP generation must use `secrets.choice()`
- Trigger contexts must never contain plaintext passwords

## Commands

```bash
uv sync            # install deps
uv run pytest      # run tests
make check         # format + lint
uv build           # build package
```

## Releasing

Bump version in `pyproject.toml` and `blockauth/__init__.py`, then:
```bash
git tag v0.3.0 && git push origin v0.3.0
```

## Documentation

Full docs: https://github.com/BloclabsHQ/auth-pack/wiki
