# Configuration

All BlockAuth configuration lives in `BLOCK_AUTH_SETTINGS` in your Django settings module. Every key has a sensible default.

## Minimal Configuration

```python
BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
}
```

This enables all features with default token lifetimes and HS256 signing using Django's `SECRET_KEY`.

## Full Configuration Reference

```python
from datetime import timedelta

BLOCK_AUTH_SETTINGS = {
    # --- User Model ---
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',

    # --- JWT Settings ---
    'SECRET_KEY': 'your-jwt-secret',              # Falls back to Django SECRET_KEY
    'ALGORITHM': 'HS256',                          # HS256, RS256, or ES256
    'ACCESS_TOKEN_LIFETIME': timedelta(seconds=3600),  # Default: 1 hour
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),       # Default: 1 day
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',

    # Asymmetric signing (RS256/ES256) -- set these instead of SECRET_KEY
    'JWT_PRIVATE_KEY': None,   # PEM-encoded private key
    'JWT_PUBLIC_KEY': None,    # PEM-encoded public key

    # --- OTP Settings ---
    'OTP_VALIDITY': timedelta(minutes=1),   # Default: 1 minute
    'OTP_LENGTH': 6,                        # Default: 6 digits

    # --- Rate Limiting ---
    'REQUEST_LIMIT': (3, 30),  # (max_requests, window_seconds)

    # --- Email Verification ---
    'EMAIL_VERIFICATION_REQUIRED': False,

    # --- Refresh Token Rotation ---
    'ROTATE_REFRESH_TOKENS': True,  # Blacklist old refresh token on rotation

    # --- Wallet Settings ---
    'WALLET_MESSAGE_TTL': 300,  # Signed messages expire after 5 minutes

    # --- Feature Flags ---
    'FEATURES': {
        'SIGNUP': True,
        'BASIC_LOGIN': True,
        'PASSWORDLESS_LOGIN': True,
        'WALLET_LOGIN': True,
        'TOKEN_REFRESH': True,
        'PASSWORD_RESET': True,
        'PASSWORD_CHANGE': True,
        'EMAIL_CHANGE': True,
        'EMAIL_VERIFICATION': True,
        'WALLET_EMAIL_ADD': True,
        'SOCIAL_AUTH': True,
        'PASSKEY_AUTH': True,
    },

    # --- OAuth Providers ---
    'AUTH_PROVIDERS': {
        'GOOGLE': {
            'CLIENT_ID': os.getenv('GOOGLE_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('GOOGLE_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('GOOGLE_REDIRECT_URI'),
        },
        'LINKEDIN': {
            'CLIENT_ID': os.getenv('LINKEDIN_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('LINKEDIN_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('LINKEDIN_REDIRECT_URI'),
        },
        'FACEBOOK': {
            'CLIENT_ID': os.getenv('FACEBOOK_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('FACEBOOK_CLIENT_SECRET'),
            'REDIRECT_URI': os.getenv('FACEBOOK_REDIRECT_URI'),
        },
    },

    # --- Triggers ---
    'PRE_SIGNUP_TRIGGER': 'blockauth.triggers.DummyPreSignupTrigger',
    'POST_SIGNUP_TRIGGER': 'blockauth.triggers.DummyPostSignupTrigger',
    'POST_LOGIN_TRIGGER': 'blockauth.triggers.DummyPostLoginTrigger',
    'POST_PASSWORD_CHANGE_TRIGGER': 'blockauth.triggers.DummyPostPasswordChangeTrigger',
    'POST_PASSWORD_RESET_TRIGGER': 'blockauth.triggers.DummyPostPasswordResetTrigger',

    # --- Notification & Logging ---
    'DEFAULT_NOTIFICATION_CLASS': 'blockauth.notification.DummyNotification',
    'BLOCK_AUTH_LOGGER_CLASS': 'blockauth.utils.logger.DummyLogger',

    # --- Client App ---
    'CLIENT_APP_URL': 'http://localhost:3000',
}
```

## Feature Flags

Feature flags control which endpoints are registered. Disabling a feature removes its URL patterns entirely.

| Flag | Default | Controls |
|------|---------|----------|
| `SIGNUP` | `True` | `signup/`, `signup/otp/resend/`, `signup/confirm/` |
| `BASIC_LOGIN` | `True` | `login/basic/` |
| `PASSWORDLESS_LOGIN` | `True` | `login/passwordless/`, `login/passwordless/confirm/` |
| `WALLET_LOGIN` | `True` | `login/wallet/` |
| `TOKEN_REFRESH` | `True` | `token/refresh/` |
| `PASSWORD_RESET` | `True` | `password/reset/`, `password/reset/confirm/` |
| `PASSWORD_CHANGE` | `True` | `password/change/` |
| `EMAIL_CHANGE` | `True` | `email/change/`, `email/change/confirm/` |
| `EMAIL_VERIFICATION` | `True` | Email verification requirement |
| `WALLET_EMAIL_ADD` | `True` | `wallet/email/add/` |
| `SOCIAL_AUTH` | `True` | OAuth provider endpoints |
| `PASSKEY_AUTH` | `True` | `passkey/*` endpoints |

## JWT Algorithm Configuration

### HS256 (default, symmetric)

```python
BLOCK_AUTH_SETTINGS = {
    'ALGORITHM': 'HS256',
    'SECRET_KEY': 'your-secret-key',  # Or omit to use Django SECRET_KEY
}
```

### RS256 (asymmetric)

```python
BLOCK_AUTH_SETTINGS = {
    'ALGORITHM': 'RS256',
    'JWT_PRIVATE_KEY': open('/path/to/private.pem').read(),
    'JWT_PUBLIC_KEY': open('/path/to/public.pem').read(),
}
```

### ES256 (asymmetric, ECDSA)

```python
BLOCK_AUTH_SETTINGS = {
    'ALGORITHM': 'ES256',
    'JWT_PRIVATE_KEY': open('/path/to/ec-private.pem').read(),
    'JWT_PUBLIC_KEY': open('/path/to/ec-public.pem').read(),
}
```

!!! warning
    For asymmetric algorithms, never expose private keys in version control. Use environment variables or a secrets manager.

## Trigger System

Triggers fire at authentication events. Implement your own by subclassing `BaseTrigger`:

```python
from blockauth.triggers import BaseTrigger

class MyPostSignupTrigger(BaseTrigger):
    def execute(self, context: dict):
        # context contains: user_id, username, email, trigger_type, timestamp
        send_welcome_email(context['email'])
```

```python
BLOCK_AUTH_SETTINGS = {
    'POST_SIGNUP_TRIGGER': 'myapp.triggers.MyPostSignupTrigger',
}
```

## Notification Class

Override the notification class to send OTPs via your preferred channel (email, SMS, push):

```python
from blockauth.notification import BaseNotification

class MyNotification(BaseNotification):
    def send(self, event):
        # event.recipient, event.otp, event.subject
        send_email(to=event.recipient, body=f"Your code: {event.otp}")
```

```python
BLOCK_AUTH_SETTINGS = {
    'DEFAULT_NOTIFICATION_CLASS': 'myapp.notifications.MyNotification',
}
```

## OpenAPI / Swagger Documentation

BlockAuth works with `drf-spectacular` for auto-generated API docs:

```python
INSTALLED_APPS = [
    'drf_spectacular',
    'drf_spectacular_sidecar',
]

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'My API',
    'VERSION': '1.0.0',
}
```

## Next Steps

- [Quick Start](quick-start.md) -- First auth flow in 5 minutes
- [Settings Reference](../reference/settings.md) -- Every setting with its default
