# Settings Reference

All settings are configured in `BLOCK_AUTH_SETTINGS` in your Django settings module. Every setting has a default value.

## JWT Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `SECRET_KEY` | Django `SECRET_KEY` | Secret key for HS256 JWT signing |
| `ALGORITHM` | `"HS256"` | JWT signing algorithm (HS256, RS256, ES256) |
| `ACCESS_TOKEN_LIFETIME` | `timedelta(seconds=3600)` | Access token expiration (1 hour) |
| `REFRESH_TOKEN_LIFETIME` | `timedelta(days=1)` | Refresh token expiration (1 day) |
| `AUTH_HEADER_NAME` | `"HTTP_AUTHORIZATION"` | HTTP header for JWT tokens |
| `USER_ID_FIELD` | `"id"` | User model field used as `user_id` in JWT |
| `JWT_PRIVATE_KEY` | `None` | PEM private key for RS256/ES256 signing |
| `JWT_PUBLIC_KEY` | `None` | PEM public key for RS256/ES256 verification |
| `ROTATE_REFRESH_TOKENS` | `True` | Blacklist old refresh token on rotation |

## OTP Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `OTP_VALIDITY` | `timedelta(minutes=1)` | OTP expiration time |
| `OTP_LENGTH` | `6` | Number of digits in OTP codes |

## Rate Limiting

| Setting | Default | Description |
|---------|---------|-------------|
| `REQUEST_LIMIT` | `(3, 30)` | `(max_requests, window_seconds)` per identifier+subject+IP |

## Email

| Setting | Default | Description |
|---------|---------|-------------|
| `EMAIL_VERIFICATION_REQUIRED` | `False` | Require email verification for non-auth endpoints |

## Wallet

| Setting | Default | Description |
|---------|---------|-------------|
| `WALLET_MESSAGE_TTL` | `300` | Signed wallet message expiry in seconds (5 minutes) |

## Feature Flags

| Setting | Default | Description |
|---------|---------|-------------|
| `FEATURES.SIGNUP` | `True` | Enable user registration |
| `FEATURES.BASIC_LOGIN` | `True` | Enable email/password login |
| `FEATURES.PASSWORDLESS_LOGIN` | `True` | Enable passwordless OTP login |
| `FEATURES.WALLET_LOGIN` | `True` | Enable wallet-based authentication |
| `FEATURES.TOKEN_REFRESH` | `True` | Enable JWT token refresh |
| `FEATURES.PASSWORD_RESET` | `True` | Enable password reset |
| `FEATURES.PASSWORD_CHANGE` | `True` | Enable password change |
| `FEATURES.EMAIL_CHANGE` | `True` | Enable email change |
| `FEATURES.EMAIL_VERIFICATION` | `True` | Enable email verification |
| `FEATURES.WALLET_EMAIL_ADD` | `True` | Enable adding email to wallet accounts |
| `FEATURES.SOCIAL_AUTH` | `True` | Master switch for social authentication |
| `FEATURES.PASSKEY_AUTH` | `True` | Enable WebAuthn passkey authentication |

## Triggers

| Setting | Default | Description |
|---------|---------|-------------|
| `PRE_SIGNUP_TRIGGER` | `"blockauth.triggers.DummyPreSignupTrigger"` | Class called before signup |
| `POST_SIGNUP_TRIGGER` | `"blockauth.triggers.DummyPostSignupTrigger"` | Class called after signup |
| `POST_LOGIN_TRIGGER` | `"blockauth.triggers.DummyPostLoginTrigger"` | Class called after login |
| `POST_PASSWORD_CHANGE_TRIGGER` | `"blockauth.triggers.DummyPostPasswordChangeTrigger"` | Class called after password change |
| `POST_PASSWORD_RESET_TRIGGER` | `"blockauth.triggers.DummyPostPasswordResetTrigger"` | Class called after password reset |

## Notification & Logging

| Setting | Default | Description |
|---------|---------|-------------|
| `DEFAULT_NOTIFICATION_CLASS` | `"blockauth.notification.DummyNotification"` | OTP delivery class |
| `BLOCK_AUTH_LOGGER_CLASS` | `"blockauth.utils.logger.DummyLogger"` | Logger implementation |

## OAuth Providers

Configure in `AUTH_PROVIDERS`. Only providers with configuration present have endpoints registered.

```python
'AUTH_PROVIDERS': {
    'GOOGLE': {
        'CLIENT_ID': '...',
        'CLIENT_SECRET': '...',
        'REDIRECT_URI': '...',
    },
    'LINKEDIN': { ... },
    'FACEBOOK': { ... },
}
```

## User Model

| Setting | Default | Description |
|---------|---------|-------------|
| `BLOCK_AUTH_USER_MODEL` | *(required)* | Dotted path to your user model (e.g., `"myapp.User"`) |

## Client App

| Setting | Default | Description |
|---------|---------|-------------|
| `CLIENT_APP_URL` | `None` | URL of the frontend application |
