# Quick Start

Get BlockAuth running in 5 minutes. This guide covers install, configuration, and your first login.

## 1. Install

```bash
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl
```

## 2. Create Your User Model

```python
# myapp/models.py
from blockauth.models import BlockUser

class User(BlockUser):
    pass
```

## 3. Configure Django Settings

```python
# settings.py
from datetime import timedelta

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'blockauth',
    'myapp',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'blockauth.authentication.JWTAuthentication',
    ),
}

BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'DEFAULT_NOTIFICATION_CLASS': 'myapp.notifications.ConsoleNotification',
}
```

## 4. Add URLs

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

## 5. Create a Notification Class

BlockAuth sends OTPs through a notification class. For development, print to console:

```python
# myapp/notifications.py
class ConsoleNotification:
    def send(self, event):
        print(f"OTP for {event.recipient}: {event.otp}")
```

## 6. Run Migrations

```bash
python manage.py migrate
```

## 7. Test the Flow

### Sign Up

```bash
curl -X POST http://localhost:8000/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

Check your console for the OTP, then confirm:

```bash
curl -X POST http://localhost:8000/auth/signup/confirm/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "otp": "123456"}'
```

### Login

```bash
curl -X POST http://localhost:8000/auth/login/basic/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

Response:

```json
{
  "access": "eyJhbGciOiJIUzI1NiIs...",
  "refresh": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Access a Protected Endpoint

```bash
curl http://localhost:8000/api/protected/ \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Refresh Token

```bash
curl -X POST http://localhost:8000/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "eyJhbGciOiJIUzI1NiIs..."}'
```

## What's Next?

- [Signup & Login](../guides/signup-login.md) -- All authentication flows in detail
- [JWT Tokens](../guides/jwt-tokens.md) -- Custom claims, token structure, microservice patterns
- [Configuration](configuration.md) -- Full settings reference
