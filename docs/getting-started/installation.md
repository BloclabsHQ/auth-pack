# Installation

## Requirements

- Python >= 3.12
- Django >= 5.1
- Django REST Framework >= 3.15

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `django` | 5.1.4 | Web framework |
| `djangorestframework` | 3.15.2 | API framework |
| `pyjwt` | 2.9.0 | JWT tokens |
| `requests` | 2.32.3 | HTTP client (OAuth) |
| `drf-spectacular` | 0.28.0 | OpenAPI schema |

### Optional Dependencies (KDF System)

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | >= 41.0.0 | AES-256-GCM encryption |
| `web3` | >= 6.0.0 | Ethereum integration |
| `eth-account` | >= 0.9.0 | Wallet management |
| `argon2-cffi` | >= 21.3.0 | Argon2 KDF algorithm |

## Install Methods

### From GitHub Releases (recommended)

```bash
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.4.0/blockauth-0.4.0-py3-none-any.whl
```

With uv:

```bash
uv add "blockauth @ https://github.com/BloclabsHQ/auth-pack/releases/download/v0.4.0/blockauth-0.4.0-py3-none-any.whl"
```

### From Git (development)

```bash
pip install git+https://github.com/BloclabsHQ/auth-pack.git@dev
```

With uv:

```bash
uv add "blockauth @ git+https://github.com/BloclabsHQ/auth-pack.git@dev"
```

### Editable Mode (local development)

```bash
git clone https://github.com/BloclabsHQ/auth-pack.git
pip install -e ./auth-pack
```

## Django Setup

### 1. Add to INSTALLED_APPS

```python
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'blockauth',
    # ...
]
```

### 2. Configure DRF Authentication

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'blockauth.authentication.JWTAuthentication',
    ),
}
```

### 3. Add URL Patterns

```python
from django.urls import path, include

urlpatterns = [
    path('auth/', include('blockauth.urls')),
]
```

### 4. Create Your User Model

Your user model must inherit from `BlockUser`:

```python
# myapp/models.py
from blockauth.models import BlockUser

class User(BlockUser):
    # Add any custom fields
    pass
```

Then set it in your settings:

```python
BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
}
```

### 5. Run Migrations

```bash
python manage.py migrate
```

## Verify Installation

```python
python -c "import blockauth; print(blockauth.__version__)"
```

## Next Steps

- [Configuration](configuration.md) -- Configure features, tokens, and providers
- [Quick Start](quick-start.md) -- Build your first auth flow in 5 minutes
