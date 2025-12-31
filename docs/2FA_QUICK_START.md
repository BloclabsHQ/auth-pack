# BlockAuth 2FA Quick Start Guide

## Overview

This guide helps you quickly implement Two-Factor Authentication (2FA) in BlockAuth as an optional, configurable feature that maintains complete independence from any proprietary systems.

## Installation

### 1. Install Dependencies

```bash
# Using pip
pip install pyotp qrcode[pil] cryptography

# Using poetry (recommended for BlockAuth)
poetry add pyotp qrcode[pil] cryptography
```

### 2. Update Settings

Add to your Django `settings.py`:

```python
# Enable 2FA in BlockAuth settings
BLOCK_AUTH_SETTINGS = {
    # ... existing settings ...
    
    # TOTP 2FA (Authenticator apps like Google Authenticator, Authy)
    "TOTP_ENABLED": True,
    "TOTP_ENCRYPTION_KEY": "your-fernet-key",  # Generate with: Fernet.generate_key()
    "TOTP_ISSUER_NAME": "YourAppName",
    
    "TWO_FACTOR": {
        # Basic Configuration
        "TOTP_ISSUER": "YourAppName",  # Shows in authenticator apps
        "TOTP_DIGITS": 6,              # 6 or 8 digit codes
        "TOTP_INTERVAL": 30,           # Seconds per code
        
        # Security Settings
        "MAX_ATTEMPTS": 3,             # Failed attempts before lockout
        "LOCKOUT_DURATION": 300,       # Lockout time in seconds
        "BACKUP_CODES_COUNT": 10,      # Number of backup codes
        "REMEMBER_DEVICE_DAYS": 30,    # Device trust duration
        
        # Optional Enforcement
        "ENFORCE_FOR_ADMIN": False,    # Require for admin users
        "ENFORCE_FOR_STAFF": False,    # Require for staff users
    }
}

# Add 2FA middleware (order matters!)
MIDDLEWARE = [
    # ... existing middleware ...
    'blockauth.twofa.middleware.TwoFactorAuthenticationMiddleware',
]
```

### 3. Run Migrations

```bash
# Create migration files
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### 4. Update URLs

In your main `urls.py`:

```python
from django.urls import path, include
from django.conf import settings

urlpatterns = [
    # ... existing patterns ...
    path('auth/', include('blockauth.urls')),
]

# 2FA URLs are automatically included when feature is enabled
```

## Basic Usage

### Enable 2FA for a User

```python
# Python/Django view example
from blockauth.twofa.providers import get_provider
from blockauth.twofa.models import TwoFactorSettings

def enable_2fa(request):
    """Enable 2FA for authenticated user"""
    user = request.user
    
    # Get TOTP provider
    provider = get_provider('TOTP')
    
    # Generate setup data
    setup_data = provider.get_setup_data(user)
    
    # Return QR code and secret to user
    return JsonResponse({
        'qr_code': setup_data['qr_code'],  # Base64 QR code image
        'secret': setup_data['manual_entry']['secret'],
        'instructions': setup_data['instructions']
    })
```

### Verify 2FA During Login

```python
from blockauth.twofa.providers import get_provider

def verify_2fa_code(request):
    """Verify 2FA code during login"""
    code = request.POST.get('code')
    user = request.user  # Or get from session
    
    # Get user's 2FA settings
    twofa = user.twofa_settings
    
    # Verify code
    provider = get_provider(twofa.primary_method)
    success, error = provider.verify_response(user, code)
    
    if success:
        # Mark session as 2FA verified
        request.session['2fa_verified'] = True
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': error}, status=400)
```

## API Endpoints

BlockAuth automatically provides these endpoints when 2FA is enabled:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/2fa/status/` | GET | Get user's 2FA status |
| `/auth/2fa/setup/` | POST | Initialize 2FA setup |
| `/auth/2fa/verify-setup/` | POST | Complete 2FA setup |
| `/auth/2fa/verify/` | POST | Verify 2FA during login |
| `/auth/2fa/disable/` | POST | Disable 2FA |
| `/auth/2fa/backup-codes/` | GET/POST | Manage backup codes |
| `/auth/2fa/trusted-devices/` | GET/DELETE | Manage trusted devices |

## Frontend Integration

### React Example

```typescript
// Setup 2FA
const setup2FA = async () => {
  const response = await fetch('/auth/2fa/setup/', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ method: 'TOTP' })
  });
  
  const data = await response.json();
  
  // Display QR code
  return data.setup_data.qr_code;
};

// Verify during login
const verify2FA = async (code: string) => {
  const response = await fetch('/auth/2fa/verify/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      session_token: sessionToken,
      code: code,
      trust_device: true
    })
  });
  
  const data = await response.json();
  
  if (data.success) {
    // Store tokens
    localStorage.setItem('access_token', data.tokens.access);
    localStorage.setItem('refresh_token', data.tokens.refresh);
  }
};
```

### HTML/JavaScript Example

```html
<!-- 2FA Setup -->
<div id="2fa-setup">
  <h3>Setup Two-Factor Authentication</h3>
  <div id="qr-code"></div>
  <input type="text" id="verify-code" placeholder="Enter 6-digit code">
  <button onclick="verifySetup()">Verify</button>
</div>

<script>
async function setup2FA() {
  const response = await fetch('/auth/2fa/setup/', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${getToken()}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ method: 'TOTP' })
  });
  
  const data = await response.json();
  
  // Display QR code
  document.getElementById('qr-code').innerHTML = 
    `<img src="${data.setup_data.qr_code}" alt="2FA QR Code">`;
}

async function verifySetup() {
  const code = document.getElementById('verify-code').value;
  
  const response = await fetch('/auth/2fa/verify-setup/', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${getToken()}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      session_id: sessionStorage.getItem('setup_session_id'),
      code: code
    })
  });
  
  const data = await response.json();
  
  if (data.success) {
    alert('2FA enabled! Save these backup codes: ' + 
          data.backup_codes.join(', '));
  }
}
</script>
```

## Configuration Examples

### Minimal Configuration

```python
# Bare minimum to enable 2FA
BLOCK_AUTH_SETTINGS = {
    "FEATURES": {
        "TWO_FACTOR_AUTH": True,
    },
    "TWO_FACTOR": {
        "TOTP_ISSUER": "MyApp",
    }
}
```

### Production Configuration

```python
# Recommended production settings
BLOCK_AUTH_SETTINGS = {
    # TOTP 2FA - Authenticator app support
    "TOTP_ENABLED": True,
    "TOTP_ENCRYPTION_KEY": "your-fernet-key",  # REQUIRED - Generate with Fernet.generate_key()
    "TOTP_ISSUER_NAME": "YourCompany",
    "TOTP_DIGITS": 6,
    "TOTP_TIME_STEP": 30,
    "TOTP_ALGORITHM": "sha1",  # sha1 for maximum compatibility
    "TOTP_SECRET_LENGTH": 32,  # 256 bits
    "TOTP_BACKUP_CODES_COUNT": 10,
    "TOTP_MAX_ATTEMPTS": 5,
    "TOTP_LOCKOUT_DURATION": 300,  # 5 minutes

    "TWO_FACTOR": {
        # Additional 2FA Settings (future expansion)
        
        # Security
        "MAX_ATTEMPTS": 3,
        "LOCKOUT_DURATION": 600,  # 10 minutes
        "BACKUP_CODES_COUNT": 12,
        "REMEMBER_DEVICE_DAYS": 14,  # Shorter for production
        
        # Enforcement
        "ENFORCE_FOR_ADMIN": True,  # Require for admins
        "ENFORCE_FOR_STAFF": True,  # Require for staff
        "GRACE_PERIOD_DAYS": 7,     # Grace period before enforcement
    },
    
    # SMS Provider (optional)
    "SMS_PROVIDER": {
        "BACKEND": "blockauth.providers.TwilioBackend",
        "TWILIO_ACCOUNT_SID": os.environ.get("TWILIO_SID"),
        "TWILIO_AUTH_TOKEN": os.environ.get("TWILIO_TOKEN"),
        "TWILIO_FROM_NUMBER": os.environ.get("TWILIO_PHONE"),
    }
}
```

### Development Configuration

```python
# Development-friendly settings
BLOCK_AUTH_SETTINGS = {
    # TOTP 2FA - Development settings
    "TOTP_ENABLED": True,
    "TOTP_ENCRYPTION_KEY": "dev-key-generate-real-one-for-prod",
    "TOTP_ISSUER_NAME": "DevApp",
    "TOTP_DIGITS": 6,
    "TOTP_TIME_STEP": 30,

    # Relaxed for development
    "TOTP_MAX_ATTEMPTS": 10,
    "TOTP_LOCKOUT_DURATION": 60,  # 1 minute

    "TWO_FACTOR": {
        # Additional settings (future expansion)
        
        # No enforcement in dev
        "ENFORCE_FOR_ADMIN": False,
        "ENFORCE_FOR_STAFF": False,
    }
}
```

## Testing 2FA

### Manual Testing with Google Authenticator

1. **Setup Phase:**
   ```python
   # In Django shell
   from blockauth.models import BlockUser
   from blockauth.twofa.providers import TOTPProvider
   
   user = BlockUser.objects.get(email='test@example.com')
   provider = TOTPProvider({'issuer': 'TestApp', 'digits': 6, 'interval': 30})
   setup_data = provider.get_setup_data(user)
   
   print(setup_data['manual_entry']['secret'])  # Enter this in Google Authenticator
   ```

2. **Verification:**
   ```python
   # Verify the code from Google Authenticator
   code = input("Enter code from app: ")
   success, error = provider.verify_response(user, code)
   print(f"Success: {success}, Error: {error}")
   ```

### Automated Testing

```python
# tests/test_2fa_quickstart.py
import pyotp
from django.test import TestCase
from blockauth.models import BlockUser
from blockauth.twofa.providers import TOTPProvider

class QuickStart2FATest(TestCase):
    def test_complete_flow(self):
        # Create user
        user = BlockUser.objects.create_user(
            email='test@example.com',
            password='testpass'
        )
        
        # Setup 2FA
        provider = TOTPProvider({
            'issuer': 'TestApp',
            'digits': 6,
            'interval': 30
        })
        
        setup_data = provider.get_setup_data(user)
        secret = setup_data['manual_entry']['secret']
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        # Verify code
        success, error = provider.verify_response(user, code)
        
        self.assertTrue(success)
        self.assertIsNone(error)
```

## Common Issues

### Issue: QR Code Not Displaying

```python
# Check if dependencies are installed
try:
    import qrcode
    import PIL
    print("Dependencies OK")
except ImportError as e:
    print(f"Missing dependency: {e}")
    # Install: pip install qrcode[pil]
```

### Issue: Time-based Codes Not Working

```python
# Check server time synchronization
import time
import pyotp

# Server time
server_time = time.time()
print(f"Server time: {server_time}")

# Generate code with server time
totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')
code = totp.at(server_time)
print(f"Current code: {code}")

# Verify time sync
# Codes should change every 30 seconds
```

### Issue: User Locked Out

```python
# Admin unlock script
from blockauth.models import BlockUser
from blockauth.twofa.models import TwoFactorSettings

def unlock_user(email):
    user = BlockUser.objects.get(email=email)
    settings = user.twofa_settings
    
    # Reset lockout
    settings.failed_attempts = 0
    settings.locked_until = None
    settings.save()
    
    print(f"User {email} unlocked")
```

## Security Best Practices

### 1. Always Use HTTPS
```python
# Enforce HTTPS in production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### 2. Encrypt Secrets
```python
# Secrets are automatically encrypted
# Never log or display raw TOTP secrets
import logging
logging.getLogger('blockauth.twofa').setLevel(logging.WARNING)
```

### 3. Rate Limiting
```python
# Built-in rate limiting
BLOCK_AUTH_SETTINGS['TWO_FACTOR']['MAX_ATTEMPTS'] = 3
BLOCK_AUTH_SETTINGS['TWO_FACTOR']['LOCKOUT_DURATION'] = 600
```

### 4. Audit Logging
```python
# Enable audit logging
LOGGING = {
    'handlers': {
        '2fa_audit': {
            'class': 'logging.FileHandler',
            'filename': '2fa_audit.log',
        },
    },
    'loggers': {
        'blockauth.twofa.audit': {
            'handlers': ['2fa_audit'],
            'level': 'INFO',
        },
    },
}
```

## Migration from Existing System

### From Django-OTP

```python
# Migration script example
from django_otp.models import TOTPDevice
from blockauth.twofa.models import TwoFactorSettings

def migrate_from_django_otp():
    for device in TOTPDevice.objects.filter(confirmed=True):
        settings, created = TwoFactorSettings.objects.get_or_create(
            user=device.user
        )
        settings.is_enabled = True
        settings.primary_method = 'TOTP'
        settings.totp_secret = device.key  # Encrypt if needed
        settings.totp_verified = True
        settings.save()
        
        print(f"Migrated user: {device.user.email}")
```

### From Custom Implementation

```python
# Custom migration example
def migrate_custom_2fa():
    for user in BlockUser.objects.all():
        if hasattr(user, 'old_2fa_field'):
            settings = TwoFactorSettings.objects.create(
                user=user,
                is_enabled=True,
                primary_method='TOTP',
                totp_secret=encrypt_secret(user.old_2fa_secret)
            )
            
            # Generate backup codes
            settings.generate_backup_codes()
            
            print(f"Migrated: {user.email}")
```

## Monitoring

### Check 2FA Adoption

```python
from django.core.management.base import BaseCommand
from blockauth.twofa.models import TwoFactorSettings
from blockauth.models import BlockUser

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        total = BlockUser.objects.count()
        enabled = TwoFactorSettings.objects.filter(
            is_enabled=True
        ).count()
        
        percentage = (enabled / total * 100) if total > 0 else 0
        
        self.stdout.write(
            f"2FA Adoption: {enabled}/{total} ({percentage:.1f}%)"
        )
```

## Support

### Getting Help

1. **Documentation**: See full [2FA Implementation Guide](./2FA_IMPLEMENTATION_GUIDE.md)
2. **Technical Specs**: See [2FA Technical Specification](./2FA_TECHNICAL_SPECIFICATION.md)
3. **Issues**: Report at `github.com/your-org/blockauth/issues`
4. **Community**: Join discussions at `github.com/your-org/blockauth/discussions`

### Contributing

BlockAuth is open source! To contribute:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### License

BlockAuth is released under the MIT License. The 2FA module maintains the same open-source license and can be used independently of any proprietary systems.

---

**Quick Links:**
- [Full Implementation Guide](./2FA_IMPLEMENTATION_GUIDE.md)
- [Technical Specification](./2FA_TECHNICAL_SPECIFICATION.md)
- [API Documentation](./2FA_API_REFERENCE.md)
- [Security Guidelines](./2FA_SECURITY.md)