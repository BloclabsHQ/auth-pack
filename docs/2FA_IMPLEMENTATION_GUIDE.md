# 2FA Implementation Guide for BlockAuth

## Executive Summary

This document outlines the implementation of Two-Factor Authentication (2FA) as an optional, modular feature for the BlockAuth open-source authentication package. The design maintains complete independence from fabric-auth while providing enterprise-grade security options.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Feature Design Principles](#feature-design-principles)
3. [Implementation Approach](#implementation-approach)
4. [Configuration](#configuration)
5. [API Specifications](#api-specifications)
6. [Database Schema](#database-schema)
7. [Security Considerations](#security-considerations)
8. [Integration Guide](#integration-guide)
9. [Testing Strategy](#testing-strategy)
10. [Migration Guide](#migration-guide)

## Architecture Overview

### Design Goals

- **Optional Feature**: 2FA is completely optional and configurable via settings
- **Provider Agnostic**: Support multiple 2FA methods (TOTP, SMS, Email, WebAuthn)
- **Backward Compatible**: Existing authentication flows remain unchanged
- **Open Source Ready**: No proprietary dependencies or tight coupling
- **Enterprise Ready**: Supports backup codes, device management, and recovery flows

### 2FA Methods Support

```
┌─────────────────────────────────────────────┐
│           BlockAuth 2FA System              │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐  ┌──────────────┐       │
│  │ TOTP/Auth    │  │   SMS OTP    │       │
│  │ Apps (RFC    │  │   (Existing) │       │
│  │ 6238)        │  │              │       │
│  └──────────────┘  └──────────────┘       │
│                                             │
│  ┌──────────────┐  ┌──────────────┐       │
│  │ Email OTP    │  │   WebAuthn   │       │
│  │ (Existing)   │  │   (Future)   │       │
│  └──────────────┘  └──────────────┘       │
│                                             │
│  ┌──────────────────────────────────┐      │
│  │     Backup Codes System          │      │
│  └──────────────────────────────────┘      │
└─────────────────────────────────────────────┘
```

## Feature Design Principles

### 1. Modular Architecture

```python
# Each 2FA method is a separate module
blockauth/
├── twofa/                      # New 2FA module
│   ├── __init__.py
│   ├── providers/              # 2FA providers
│   │   ├── base.py            # Abstract base provider
│   │   ├── totp.py            # TOTP authenticator apps
│   │   ├── sms.py             # SMS-based 2FA
│   │   ├── email.py           # Email-based 2FA
│   │   └── webauthn.py        # WebAuthn/FIDO2 (future)
│   ├── models.py              # 2FA-specific models
│   ├── serializers.py         # 2FA serializers
│   ├── views.py               # 2FA endpoints
│   ├── utils.py               # 2FA utilities
│   └── exceptions.py          # 2FA exceptions
```

### 2. Provider Pattern

```python
# Abstract base provider ensures consistency
from abc import ABC, abstractmethod

class TwoFactorProvider(ABC):
    """Base class for all 2FA providers"""
    
    @abstractmethod
    def generate_secret(self, user):
        """Generate provider-specific secret"""
        pass
    
    @abstractmethod
    def verify_code(self, user, code):
        """Verify the provided code"""
        pass
    
    @abstractmethod
    def get_setup_data(self, user):
        """Get data needed for client setup"""
        pass
    
    @abstractmethod
    def is_available(self):
        """Check if provider is available"""
        pass
```

### 3. Feature Flag Integration

```python
# Extends existing feature flag system
BLOCK_AUTH_SETTINGS = {
    "FEATURES": {
        # Existing features...
        "TWO_FACTOR_AUTH": True,  # Master switch for 2FA
        "TOTP_2FA": True,         # TOTP authenticator apps
        "SMS_2FA": True,          # SMS-based 2FA
        "EMAIL_2FA": True,        # Email-based 2FA
        "BACKUP_CODES": True,     # Backup recovery codes
        "TRUSTED_DEVICES": True,  # Remember device feature
    },
    
    "TWO_FACTOR": {
        "ENFORCE_FOR_ADMIN": False,  # Require 2FA for admin users
        "TOTP_ISSUER": "BlockAuth",  # App name in authenticator
        "TOTP_DIGITS": 6,            # Code length
        "TOTP_INTERVAL": 30,         # Seconds per code
        "BACKUP_CODES_COUNT": 10,    # Number of backup codes
        "REMEMBER_DEVICE_DAYS": 30,  # Trusted device duration
        "MAX_ATTEMPTS": 3,           # Max verification attempts
        "LOCKOUT_DURATION": 300,     # Lockout time in seconds
    }
}
```

## Implementation Approach

### Phase 1: Core Infrastructure

#### 1.1 Database Models

```python
# blockauth/twofa/models.py

from django.db import models
from django.contrib.postgres.fields import ArrayField
import pyotp
import secrets
from blockauth.models import BlockUser

class TwoFactorMethod(models.TextChoices):
    TOTP = 'TOTP', 'Time-based OTP'
    SMS = 'SMS', 'SMS'
    EMAIL = 'EMAIL', 'Email'
    WEBAUTHN = 'WEBAUTHN', 'WebAuthn'

class TwoFactorSettings(models.Model):
    """User's 2FA settings and secrets"""
    
    user = models.OneToOneField(
        BlockUser, 
        on_delete=models.CASCADE,
        related_name='twofa_settings'
    )
    
    # 2FA Status
    is_enabled = models.BooleanField(default=False)
    primary_method = models.CharField(
        max_length=20,
        choices=TwoFactorMethod.choices,
        null=True,
        blank=True
    )
    fallback_method = models.CharField(
        max_length=20,
        choices=TwoFactorMethod.choices,
        null=True,
        blank=True
    )
    
    # TOTP Settings
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    totp_verified = models.BooleanField(default=False)
    
    # Backup Codes
    backup_codes = ArrayField(
        models.CharField(max_length=16),
        size=10,
        default=list,
        blank=True
    )
    used_backup_codes = ArrayField(
        models.CharField(max_length=16),
        default=list,
        blank=True
    )
    
    # Security
    last_used_at = models.DateTimeField(null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'blockauth_twofa_settings'
        verbose_name = '2FA Settings'
        verbose_name_plural = '2FA Settings'
    
    def generate_backup_codes(self, count=10):
        """Generate new backup codes"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(8).upper()
            codes.append(code)
        self.backup_codes = codes
        self.used_backup_codes = []
        self.save()
        return codes
    
    def use_backup_code(self, code):
        """Mark a backup code as used"""
        if code in self.backup_codes and code not in self.used_backup_codes:
            self.used_backup_codes.append(code)
            self.save()
            return True
        return False


class TrustedDevice(models.Model):
    """Trusted devices for 2FA bypass"""
    
    user = models.ForeignKey(
        BlockUser,
        on_delete=models.CASCADE,
        related_name='trusted_devices'
    )
    
    device_id = models.CharField(max_length=64, unique=True)
    device_name = models.CharField(max_length=255)
    device_type = models.CharField(max_length=50)  # mobile, desktop, tablet
    
    # Browser/App Info
    user_agent = models.TextField()
    ip_address = models.GenericIPAddressField()
    
    # Trust Settings
    trusted_until = models.DateTimeField()
    last_used_at = models.DateTimeField(auto_now=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'blockauth_trusted_devices'
        indexes = [
            models.Index(fields=['user', 'device_id']),
            models.Index(fields=['trusted_until']),
        ]
```

#### 1.2 TOTP Provider Implementation

```python
# blockauth/twofa/providers/totp.py

import pyotp
import qrcode
import io
import base64
from typing import Dict, Any
from .base import TwoFactorProvider
from ..models import TwoFactorSettings

class TOTPProvider(TwoFactorProvider):
    """TOTP-based 2FA using authenticator apps"""
    
    def __init__(self, settings: Dict[str, Any]):
        self.issuer = settings.get('TOTP_ISSUER', 'BlockAuth')
        self.digits = settings.get('TOTP_DIGITS', 6)
        self.interval = settings.get('TOTP_INTERVAL', 30)
    
    def generate_secret(self, user) -> str:
        """Generate TOTP secret for user"""
        secret = pyotp.random_base32()
        
        # Get or create 2FA settings
        twofa, _ = TwoFactorSettings.objects.get_or_create(user=user)
        twofa.totp_secret = secret
        twofa.totp_verified = False
        twofa.save()
        
        return secret
    
    def verify_code(self, user, code: str) -> bool:
        """Verify TOTP code"""
        twofa = TwoFactorSettings.objects.filter(user=user).first()
        if not twofa or not twofa.totp_secret:
            return False
        
        totp = pyotp.TOTP(
            twofa.totp_secret,
            digits=self.digits,
            interval=self.interval
        )
        
        # Allow for time drift (±1 interval)
        valid = totp.verify(code, valid_window=1)
        
        if valid and not twofa.totp_verified:
            twofa.totp_verified = True
            twofa.save()
        
        return valid
    
    def get_setup_data(self, user) -> Dict[str, Any]:
        """Get QR code and setup data"""
        twofa = TwoFactorSettings.objects.filter(user=user).first()
        if not twofa or not twofa.totp_secret:
            secret = self.generate_secret(user)
        else:
            secret = twofa.totp_secret
        
        # Generate provisioning URI
        totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
        provisioning_uri = totp.provisioning_uri(
            name=user.email or user.id,
            issuer_name=self.issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': secret,
            'qr_code': f'data:image/png;base64,{qr_code_base64}',
            'provisioning_uri': provisioning_uri,
            'manual_entry': {
                'secret': secret,
                'issuer': self.issuer,
                'account': user.email or str(user.id),
                'digits': self.digits,
                'interval': self.interval
            }
        }
    
    def is_available(self) -> bool:
        """Check if TOTP is available"""
        try:
            import pyotp
            import qrcode
            return True
        except ImportError:
            return False
```

### Phase 2: API Endpoints

#### 2.1 2FA Management Views

```python
# blockauth/twofa/views.py

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.conf import settings
from .providers import get_provider
from .serializers import (
    Enable2FASerializer,
    Verify2FASerializer,
    Disable2FASerializer,
    BackupCodesSerializer
)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def twofa_status(request):
    """Get user's 2FA status"""
    user = request.user
    twofa = getattr(user, 'twofa_settings', None)
    
    return Response({
        'enabled': twofa.is_enabled if twofa else False,
        'primary_method': twofa.primary_method if twofa else None,
        'fallback_method': twofa.fallback_method if twofa else None,
        'backup_codes_remaining': len(twofa.backup_codes) - len(twofa.used_backup_codes) if twofa else 0,
        'available_methods': get_available_methods()
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enable_twofa(request):
    """Enable 2FA for user"""
    serializer = Enable2FASerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    method = serializer.validated_data['method']
    provider = get_provider(method)
    
    if not provider.is_available():
        return Response(
            {'error': f'{method} is not available'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    setup_data = provider.get_setup_data(request.user)
    
    return Response({
        'method': method,
        'setup_data': setup_data,
        'message': 'Please complete setup by verifying a code'
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_twofa_setup(request):
    """Verify 2FA setup with initial code"""
    serializer = Verify2FASerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    method = serializer.validated_data['method']
    code = serializer.validated_data['code']
    
    provider = get_provider(method)
    
    if provider.verify_code(request.user, code):
        # Enable 2FA
        twofa, _ = TwoFactorSettings.objects.get_or_create(user=request.user)
        twofa.is_enabled = True
        twofa.primary_method = method
        
        # Generate backup codes
        backup_codes = twofa.generate_backup_codes()
        
        twofa.save()
        
        return Response({
            'success': True,
            'message': '2FA has been enabled',
            'backup_codes': backup_codes
        })
    
    return Response(
        {'error': 'Invalid verification code'},
        status=status.HTTP_400_BAD_REQUEST
    )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_twofa(request):
    """Disable 2FA (requires current 2FA code)"""
    serializer = Disable2FASerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    code = serializer.validated_data['code']
    twofa = getattr(request.user, 'twofa_settings', None)
    
    if not twofa or not twofa.is_enabled:
        return Response(
            {'error': '2FA is not enabled'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    provider = get_provider(twofa.primary_method)
    
    # Verify code or backup code
    valid = provider.verify_code(request.user, code) or twofa.use_backup_code(code)
    
    if valid:
        twofa.is_enabled = False
        twofa.primary_method = None
        twofa.fallback_method = None
        twofa.totp_secret = None
        twofa.totp_verified = False
        twofa.backup_codes = []
        twofa.used_backup_codes = []
        twofa.save()
        
        # Remove all trusted devices
        request.user.trusted_devices.all().delete()
        
        return Response({'success': True, 'message': '2FA has been disabled'})
    
    return Response(
        {'error': 'Invalid verification code'},
        status=status.HTTP_400_BAD_REQUEST
    )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_backup_codes(request):
    """Regenerate backup codes (requires current 2FA code)"""
    serializer = Verify2FASerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    code = serializer.validated_data['code']
    twofa = getattr(request.user, 'twofa_settings', None)
    
    if not twofa or not twofa.is_enabled:
        return Response(
            {'error': '2FA is not enabled'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    provider = get_provider(twofa.primary_method)
    
    if provider.verify_code(request.user, code):
        backup_codes = twofa.generate_backup_codes()
        return Response({
            'success': True,
            'backup_codes': backup_codes,
            'message': 'New backup codes generated. Previous codes are now invalid.'
        })
    
    return Response(
        {'error': 'Invalid verification code'},
        status=status.HTTP_400_BAD_REQUEST
    )
```

#### 2.2 Authentication Flow Integration

```python
# blockauth/twofa/middleware.py

from django.contrib.auth import logout
from rest_framework.response import Response
from rest_framework import status
from .models import TwoFactorSettings, TrustedDevice
import hashlib
import secrets

class TwoFactorAuthenticationMiddleware:
    """Middleware to enforce 2FA verification"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = [
            '/auth/login/',
            '/auth/2fa/verify/',
            '/auth/logout/',
        ]
    
    def __call__(self, request):
        # Skip for exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return self.get_response(request)
        
        # Check if user is authenticated
        if request.user.is_authenticated:
            twofa = getattr(request.user, 'twofa_settings', None)
            
            # Check if 2FA is enabled
            if twofa and twofa.is_enabled:
                # Check if already verified in session
                if not request.session.get('2fa_verified', False):
                    # Check for trusted device
                    device_id = self.get_device_id(request)
                    if not self.is_trusted_device(request.user, device_id):
                        return Response(
                            {
                                'error': '2FA verification required',
                                'require_2fa': True,
                                'methods': [twofa.primary_method, twofa.fallback_method]
                            },
                            status=status.HTTP_403_FORBIDDEN
                        )
        
        return self.get_response(request)
    
    def get_device_id(self, request):
        """Generate unique device ID from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip_address = self.get_client_ip(request)
        
        # Create deterministic device ID
        device_string = f"{user_agent}:{ip_address}"
        return hashlib.sha256(device_string.encode()).hexdigest()
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_trusted_device(self, user, device_id):
        """Check if device is trusted"""
        from django.utils import timezone
        
        return TrustedDevice.objects.filter(
            user=user,
            device_id=device_id,
            trusted_until__gt=timezone.now()
        ).exists()
```

### Phase 3: Login Flow Enhancement

```python
# blockauth/views/enhanced_login.py

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from ..twofa.models import TwoFactorSettings, TrustedDevice
from ..twofa.providers import get_provider
from ..jwt.token_manager import BlockAuthTokenManager

@api_view(['POST'])
def verify_twofa_login(request):
    """Verify 2FA code during login"""
    code = request.data.get('code')
    method = request.data.get('method')
    remember_device = request.data.get('remember_device', False)
    
    # Get user from session or temporary token
    user_id = request.session.get('pending_2fa_user')
    if not user_id:
        return Response(
            {'error': 'No pending 2FA verification'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = BlockUser.objects.get(id=user_id)
    twofa = user.twofa_settings
    
    if not twofa or not twofa.is_enabled:
        return Response(
            {'error': '2FA not enabled for this user'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check lockout
    if twofa.is_locked():
        return Response(
            {'error': 'Too many failed attempts. Please try again later.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    # Verify code
    valid = False
    
    # Try primary method
    if method == twofa.primary_method:
        provider = get_provider(method)
        valid = provider.verify_code(user, code)
    
    # Try backup codes
    if not valid:
        valid = twofa.use_backup_code(code)
    
    if valid:
        # Reset failed attempts
        twofa.failed_attempts = 0
        twofa.locked_until = None
        twofa.last_used_at = timezone.now()
        twofa.save()
        
        # Mark as verified in session
        request.session['2fa_verified'] = True
        
        # Handle trusted device
        if remember_device:
            device_id = get_device_id(request)
            TrustedDevice.objects.update_or_create(
                user=user,
                device_id=device_id,
                defaults={
                    'device_name': request.data.get('device_name', 'Unknown Device'),
                    'device_type': request.data.get('device_type', 'unknown'),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'ip_address': get_client_ip(request),
                    'trusted_until': timezone.now() + timedelta(days=30)
                }
            )
        
        # Generate final JWT tokens
        token_manager = BlockAuthTokenManager()
        tokens = token_manager.generate_tokens(user, include_2fa_claim=True)
        
        # Clear pending user
        del request.session['pending_2fa_user']
        
        return Response({
            'success': True,
            'tokens': tokens,
            'backup_codes_remaining': len(twofa.backup_codes) - len(twofa.used_backup_codes)
        })
    
    else:
        # Increment failed attempts
        twofa.failed_attempts += 1
        
        # Lock after max attempts
        max_attempts = settings.BLOCK_AUTH_SETTINGS.get('TWO_FACTOR', {}).get('MAX_ATTEMPTS', 3)
        if twofa.failed_attempts >= max_attempts:
            lockout_duration = settings.BLOCK_AUTH_SETTINGS.get('TWO_FACTOR', {}).get('LOCKOUT_DURATION', 300)
            twofa.locked_until = timezone.now() + timedelta(seconds=lockout_duration)
        
        twofa.save()
        
        return Response(
            {
                'error': 'Invalid verification code',
                'attempts_remaining': max(0, max_attempts - twofa.failed_attempts)
            },
            status=status.HTTP_400_BAD_REQUEST
        )

# Enhanced login view modification
def enhanced_login_view(original_login_func):
    """Decorator to add 2FA check to login views"""
    def wrapper(request, *args, **kwargs):
        # Call original login
        response = original_login_func(request, *args, **kwargs)
        
        # Check if login was successful
        if response.status_code == 200 and 'tokens' in response.data:
            user = request.user
            twofa = getattr(user, 'twofa_settings', None)
            
            # Check if 2FA is enabled
            if twofa and twofa.is_enabled:
                # Check for trusted device
                device_id = get_device_id(request)
                if not is_trusted_device(user, device_id):
                    # Store user in session
                    request.session['pending_2fa_user'] = str(user.id)
                    
                    # Don't return tokens yet
                    return Response({
                        'require_2fa': True,
                        'methods': [twofa.primary_method],
                        'has_backup_codes': bool(twofa.backup_codes)
                    }, status=status.HTTP_200_OK)
        
        return response
    
    return wrapper
```

## Configuration

### settings.py Configuration

```python
# settings.py

BLOCK_AUTH_SETTINGS = {
    # Existing settings...
    
    "FEATURES": {
        # Existing features...
        "TWO_FACTOR_AUTH": True,      # Enable 2FA system
        "TOTP_2FA": True,             # Enable TOTP
        "SMS_2FA": False,             # Disable SMS (uses existing OTP)
        "EMAIL_2FA": False,           # Disable Email (uses existing OTP)
        "BACKUP_CODES": True,         # Enable backup codes
        "TRUSTED_DEVICES": True,      # Enable device trust
    },
    
    "TWO_FACTOR": {
        # TOTP Configuration
        "TOTP_ISSUER": "YourAppName",     # Shows in authenticator apps
        "TOTP_DIGITS": 6,                 # Code length (6 or 8)
        "TOTP_INTERVAL": 30,              # Seconds per code
        "TOTP_ALGORITHM": "SHA1",         # SHA1, SHA256, SHA512
        
        # Backup Codes
        "BACKUP_CODES_COUNT": 10,         # Number of codes to generate
        "BACKUP_CODE_LENGTH": 8,          # Length of each code
        
        # Security Settings
        "MAX_ATTEMPTS": 3,                # Max failed attempts
        "LOCKOUT_DURATION": 300,          # Lockout time in seconds
        "REMEMBER_DEVICE_DAYS": 30,       # Trusted device duration
        
        # Enforcement Rules
        "ENFORCE_FOR_ADMIN": False,       # Require for admin users
        "ENFORCE_FOR_STAFF": False,       # Require for staff users
        "GRACE_PERIOD_DAYS": 7,           # Days before enforcement
        
        # Provider Priorities (order matters)
        "PROVIDER_PRIORITY": [
            "TOTP",      # Try TOTP first
            "SMS",       # Then SMS
            "EMAIL",     # Then Email
        ],
    },
    
    # SMS Provider Configuration (if using SMS 2FA)
    "SMS_PROVIDER": {
        "BACKEND": "blockauth.sms.TwilioBackend",
        "TWILIO_ACCOUNT_SID": "your-account-sid",
        "TWILIO_AUTH_TOKEN": "your-auth-token",
        "TWILIO_FROM_NUMBER": "+1234567890",
    },
}

# Add middleware for 2FA enforcement
MIDDLEWARE = [
    # ... existing middleware ...
    'blockauth.twofa.middleware.TwoFactorAuthenticationMiddleware',
]

# URL Configuration
if BLOCK_AUTH_SETTINGS.get('FEATURES', {}).get('TWO_FACTOR_AUTH'):
    urlpatterns += [
        path('auth/2fa/', include('blockauth.twofa.urls')),
    ]
```

## API Specifications

### 2FA Endpoints

#### 1. Get 2FA Status
```
GET /auth/2fa/status/
Authorization: Bearer {token}

Response:
{
    "enabled": true,
    "primary_method": "TOTP",
    "fallback_method": "SMS",
    "backup_codes_remaining": 8,
    "available_methods": ["TOTP", "SMS", "EMAIL"]
}
```

#### 2. Enable 2FA
```
POST /auth/2fa/enable/
Authorization: Bearer {token}

Request:
{
    "method": "TOTP"
}

Response:
{
    "method": "TOTP",
    "setup_data": {
        "secret": "JBSWY3DPEHPK3PXP",
        "qr_code": "data:image/png;base64,...",
        "provisioning_uri": "otpauth://totp/...",
        "manual_entry": {
            "secret": "JBSWY3DPEHPK3PXP",
            "issuer": "YourApp",
            "account": "user@example.com",
            "digits": 6,
            "interval": 30
        }
    },
    "message": "Please complete setup by verifying a code"
}
```

#### 3. Verify 2FA Setup
```
POST /auth/2fa/verify-setup/
Authorization: Bearer {token}

Request:
{
    "method": "TOTP",
    "code": "123456"
}

Response:
{
    "success": true,
    "message": "2FA has been enabled",
    "backup_codes": [
        "A1B2C3D4E5F6G7H8",
        "I9J0K1L2M3N4O5P6",
        // ... 8 more codes
    ]
}
```

#### 4. Verify 2FA During Login
```
POST /auth/2fa/verify-login/

Request:
{
    "code": "123456",
    "method": "TOTP",
    "remember_device": true,
    "device_name": "Chrome on MacOS"
}

Response:
{
    "success": true,
    "tokens": {
        "access": "eyJ...",
        "refresh": "eyJ..."
    },
    "backup_codes_remaining": 8
}
```

#### 5. Disable 2FA
```
POST /auth/2fa/disable/
Authorization: Bearer {token}

Request:
{
    "code": "123456"  // Current 2FA code or backup code
}

Response:
{
    "success": true,
    "message": "2FA has been disabled"
}
```

#### 6. Regenerate Backup Codes
```
POST /auth/2fa/backup-codes/regenerate/
Authorization: Bearer {token}

Request:
{
    "code": "123456"  // Current 2FA code
}

Response:
{
    "success": true,
    "backup_codes": [
        "Q7R8S9T0U1V2W3X4",
        "Y5Z6A7B8C9D0E1F2",
        // ... 8 more codes
    ],
    "message": "New backup codes generated. Previous codes are now invalid."
}
```

#### 7. Manage Trusted Devices
```
GET /auth/2fa/trusted-devices/
Authorization: Bearer {token}

Response:
{
    "devices": [
        {
            "id": "uuid",
            "device_name": "Chrome on MacOS",
            "device_type": "desktop",
            "last_used_at": "2024-01-15T10:30:00Z",
            "trusted_until": "2024-02-14T10:30:00Z"
        }
    ]
}

DELETE /auth/2fa/trusted-devices/{device_id}/
Authorization: Bearer {token}

Response:
{
    "success": true,
    "message": "Device removed from trusted list"
}
```

## Database Schema

### Migrations

```python
# blockauth/twofa/migrations/0001_initial.py

from django.db import migrations, models
import django.contrib.postgres.fields

class Migration(migrations.Migration):
    dependencies = [
        ('blockauth', '0001_initial'),
    ]
    
    operations = [
        migrations.CreateModel(
            name='TwoFactorSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True)),
                ('user', models.OneToOneField(on_delete=models.CASCADE, related_name='twofa_settings', to='blockauth.blockuser')),
                ('is_enabled', models.BooleanField(default=False)),
                ('primary_method', models.CharField(blank=True, choices=[('TOTP', 'Time-based OTP'), ('SMS', 'SMS'), ('EMAIL', 'Email')], max_length=20, null=True)),
                ('fallback_method', models.CharField(blank=True, choices=[('TOTP', 'Time-based OTP'), ('SMS', 'SMS'), ('EMAIL', 'Email')], max_length=20, null=True)),
                ('totp_secret', models.CharField(blank=True, max_length=32, null=True)),
                ('totp_verified', models.BooleanField(default=False)),
                ('backup_codes', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=16), blank=True, default=list, size=10)),
                ('used_backup_codes', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=16), default=list, size=None)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('failed_attempts', models.IntegerField(default=0)),
                ('locked_until', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'blockauth_twofa_settings',
                'verbose_name': '2FA Settings',
                'verbose_name_plural': '2FA Settings',
            },
        ),
        
        migrations.CreateModel(
            name='TrustedDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True)),
                ('user', models.ForeignKey(on_delete=models.CASCADE, related_name='trusted_devices', to='blockauth.blockuser')),
                ('device_id', models.CharField(max_length=64, unique=True)),
                ('device_name', models.CharField(max_length=255)),
                ('device_type', models.CharField(max_length=50)),
                ('user_agent', models.TextField()),
                ('ip_address', models.GenericIPAddressField()),
                ('trusted_until', models.DateTimeField()),
                ('last_used_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'blockauth_trusted_devices',
            },
        ),
        
        migrations.AddIndex(
            model_name='trusteddevice',
            index=models.Index(fields=['user', 'device_id'], name='blockauth_t_user_id_device_idx'),
        ),
        
        migrations.AddIndex(
            model_name='trusteddevice',
            index=models.Index(fields=['trusted_until'], name='blockauth_t_trusted_until_idx'),
        ),
    ]
```

## Security Considerations

### 1. Secret Storage

```python
# Use Django's built-in encryption for TOTP secrets
from django.core import signing
from cryptography.fernet import Fernet

class EncryptedCharField(models.CharField):
    """Encrypted field for storing secrets"""
    
    def __init__(self, *args, **kwargs):
        self.cipher_suite = Fernet(settings.SECRET_KEY[:32].encode())
        super().__init__(*args, **kwargs)
    
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self.cipher_suite.decrypt(value.encode()).decode()
    
    def to_python(self, value):
        if isinstance(value, str) or value is None:
            return value
        return self.cipher_suite.decrypt(value).decode()
    
    def get_prep_value(self, value):
        if value is None:
            return value
        return self.cipher_suite.encrypt(value.encode()).decode()
```

### 2. Rate Limiting

```python
# blockauth/twofa/decorators.py

from django.core.cache import cache
from functools import wraps
from rest_framework.response import Response
from rest_framework import status

def rate_limit_2fa(max_attempts=3, window=300):
    """Rate limit 2FA verification attempts"""
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # Generate cache key
            user_id = request.user.id if request.user.is_authenticated else request.session.session_key
            cache_key = f'2fa_attempts:{user_id}'
            
            # Get current attempts
            attempts = cache.get(cache_key, 0)
            
            if attempts >= max_attempts:
                return Response(
                    {'error': 'Too many attempts. Please try again later.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Increment attempts
            cache.set(cache_key, attempts + 1, window)
            
            # Call original function
            response = func(request, *args, **kwargs)
            
            # Reset on success
            if response.status_code == 200:
                cache.delete(cache_key)
            
            return response
        return wrapper
    return decorator
```

### 3. Audit Logging

```python
# blockauth/twofa/audit.py

from django.db import models
from blockauth.models import BlockUser

class TwoFactorAuditLog(models.Model):
    """Audit log for 2FA events"""
    
    class EventType(models.TextChoices):
        ENABLED = 'ENABLED', '2FA Enabled'
        DISABLED = 'DISABLED', '2FA Disabled'
        VERIFIED = 'VERIFIED', '2FA Verified'
        FAILED = 'FAILED', '2FA Failed'
        BACKUP_USED = 'BACKUP_USED', 'Backup Code Used'
        BACKUP_GENERATED = 'BACKUP_GENERATED', 'Backup Codes Generated'
        DEVICE_TRUSTED = 'DEVICE_TRUSTED', 'Device Trusted'
        DEVICE_REMOVED = 'DEVICE_REMOVED', 'Device Removed'
    
    user = models.ForeignKey(BlockUser, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=20, choices=EventType.choices)
    method = models.CharField(max_length=20, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'blockauth_twofa_audit'
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
        ]

def log_2fa_event(user, event_type, request, **kwargs):
    """Helper to log 2FA events"""
    TwoFactorAuditLog.objects.create(
        user=user,
        event_type=event_type,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        **kwargs
    )
```

### 4. Security Best Practices

1. **TOTP Secret Generation**
   - Use cryptographically secure random generation
   - Store encrypted in database
   - Never expose in logs or API responses

2. **Backup Codes**
   - Generate using `secrets.token_hex()`
   - Store hashed versions (optional)
   - Single-use only
   - Warn when running low

3. **Device Trust**
   - Use combination of User-Agent + IP for device ID
   - Time-limited trust periods
   - Allow users to revoke trusted devices

4. **Rate Limiting**
   - Limit verification attempts
   - Progressive delays on failures
   - Account lockout after max attempts

5. **Audit Trail**
   - Log all 2FA events
   - Include IP, User-Agent, timestamp
   - Regular security reviews

## Integration Guide

### 1. Client-Side Integration (React Example)

```typescript
// 2fa-setup.tsx

import React, { useState } from 'react';
import QRCode from 'qrcode.react';
import { enable2FA, verifySetup } from './api';

const TwoFactorSetup: React.FC = () => {
    const [step, setStep] = useState<'choose' | 'setup' | 'verify' | 'complete'>('choose');
    const [method, setMethod] = useState<string>('TOTP');
    const [setupData, setSetupData] = useState<any>(null);
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    
    const handleEnable = async () => {
        const response = await enable2FA(method);
        setSetupData(response.setup_data);
        setStep('setup');
    };
    
    const handleVerify = async (code: string) => {
        const response = await verifySetup(method, code);
        if (response.success) {
            setBackupCodes(response.backup_codes);
            setStep('complete');
        }
    };
    
    return (
        <div className="twofa-setup">
            {step === 'choose' && (
                <div>
                    <h2>Choose 2FA Method</h2>
                    <button onClick={() => { setMethod('TOTP'); handleEnable(); }}>
                        Authenticator App
                    </button>
                    <button onClick={() => { setMethod('SMS'); handleEnable(); }}>
                        SMS
                    </button>
                </div>
            )}
            
            {step === 'setup' && method === 'TOTP' && setupData && (
                <div>
                    <h2>Setup Authenticator App</h2>
                    <p>Scan this QR code with your authenticator app:</p>
                    <img src={setupData.qr_code} alt="2FA QR Code" />
                    
                    <p>Or enter manually:</p>
                    <code>{setupData.manual_entry.secret}</code>
                    
                    <input
                        type="text"
                        placeholder="Enter verification code"
                        onKeyUp={(e) => {
                            if (e.key === 'Enter') {
                                handleVerify(e.currentTarget.value);
                            }
                        }}
                    />
                </div>
            )}
            
            {step === 'complete' && (
                <div>
                    <h2>2FA Enabled Successfully!</h2>
                    <p>Save these backup codes in a safe place:</p>
                    <ul>
                        {backupCodes.map((code, i) => (
                            <li key={i}><code>{code}</code></li>
                        ))}
                    </ul>
                    <button onClick={() => window.print()}>Print Codes</button>
                </div>
            )}
        </div>
    );
};
```

### 2. Login Flow Integration

```typescript
// login.tsx

import React, { useState } from 'react';
import { login, verify2FA } from './api';

const Login: React.FC = () => {
    const [step, setStep] = useState<'credentials' | 'twofa'>('credentials');
    const [require2FA, setRequire2FA] = useState(false);
    
    const handleLogin = async (email: string, password: string) => {
        const response = await login(email, password);
        
        if (response.require_2fa) {
            setRequire2FA(true);
            setStep('twofa');
        } else {
            // Login successful
            localStorage.setItem('access_token', response.tokens.access);
            window.location.href = '/dashboard';
        }
    };
    
    const handle2FA = async (code: string, rememberDevice: boolean) => {
        const response = await verify2FA(code, 'TOTP', rememberDevice);
        
        if (response.success) {
            localStorage.setItem('access_token', response.tokens.access);
            window.location.href = '/dashboard';
        }
    };
    
    return (
        <div>
            {step === 'credentials' && (
                <form onSubmit={handleLogin}>
                    {/* Email and password inputs */}
                </form>
            )}
            
            {step === 'twofa' && (
                <div>
                    <h2>Enter 2FA Code</h2>
                    <input
                        type="text"
                        placeholder="6-digit code"
                        maxLength={6}
                    />
                    <label>
                        <input type="checkbox" />
                        Remember this device for 30 days
                    </label>
                    <button onClick={handle2FA}>Verify</button>
                    
                    <p>Lost your device? <a href="/auth/recovery">Use backup code</a></p>
                </div>
            )}
        </div>
    );
};
```

## Testing Strategy

### 1. Unit Tests

```python
# tests/test_twofa.py

import pytest
from django.test import TestCase
from blockauth.models import BlockUser
from blockauth.twofa.models import TwoFactorSettings
from blockauth.twofa.providers.totp import TOTPProvider
import pyotp

class TestTOTPProvider(TestCase):
    def setUp(self):
        self.user = BlockUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.provider = TOTPProvider({
            'TOTP_ISSUER': 'TestApp',
            'TOTP_DIGITS': 6,
            'TOTP_INTERVAL': 30
        })
    
    def test_generate_secret(self):
        """Test TOTP secret generation"""
        secret = self.provider.generate_secret(self.user)
        
        # Check secret format
        self.assertEqual(len(secret), 32)
        self.assertTrue(all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret))
        
        # Check database storage
        twofa = TwoFactorSettings.objects.get(user=self.user)
        self.assertEqual(twofa.totp_secret, secret)
        self.assertFalse(twofa.totp_verified)
    
    def test_verify_code(self):
        """Test TOTP code verification"""
        secret = self.provider.generate_secret(self.user)
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Verify valid code
        self.assertTrue(self.provider.verify_code(self.user, valid_code))
        
        # Check verified flag
        twofa = TwoFactorSettings.objects.get(user=self.user)
        self.assertTrue(twofa.totp_verified)
        
        # Verify invalid code
        self.assertFalse(self.provider.verify_code(self.user, '000000'))
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        setup_data = self.provider.get_setup_data(self.user)
        
        self.assertIn('qr_code', setup_data)
        self.assertIn('provisioning_uri', setup_data)
        self.assertIn('manual_entry', setup_data)
        
        # Check QR code is base64 image
        self.assertTrue(setup_data['qr_code'].startswith('data:image/png;base64,'))

class TestBackupCodes(TestCase):
    def setUp(self):
        self.user = BlockUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.twofa = TwoFactorSettings.objects.create(
            user=self.user,
            is_enabled=True,
            primary_method='TOTP'
        )
    
    def test_generate_backup_codes(self):
        """Test backup code generation"""
        codes = self.twofa.generate_backup_codes(10)
        
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)  # All unique
        
        for code in codes:
            self.assertEqual(len(code), 16)
            self.assertTrue(all(c in '0123456789ABCDEF' for c in code))
    
    def test_use_backup_code(self):
        """Test backup code usage"""
        codes = self.twofa.generate_backup_codes(5)
        
        # Use valid code
        self.assertTrue(self.twofa.use_backup_code(codes[0]))
        
        # Can't reuse
        self.assertFalse(self.twofa.use_backup_code(codes[0]))
        
        # Invalid code
        self.assertFalse(self.twofa.use_backup_code('INVALID'))

class TestTrustedDevices(TestCase):
    # Add trusted device tests
    pass

class Test2FALoginFlow(TestCase):
    # Add integration tests for login flow
    pass
```

### 2. Integration Tests

```python
# tests/test_integration.py

from rest_framework.test import APITestCase
from django.urls import reverse

class Test2FAIntegration(APITestCase):
    def test_complete_2fa_flow(self):
        """Test complete 2FA setup and login flow"""
        
        # 1. Register user
        # 2. Login without 2FA
        # 3. Enable 2FA
        # 4. Logout
        # 5. Login with 2FA
        # 6. Verify trusted device
        # 7. Test backup codes
        pass
```

## Migration Guide

### For Existing BlockAuth Users

1. **Database Migration**
```bash
# Run migrations
python manage.py makemigrations blockauth.twofa
python manage.py migrate
```

2. **Settings Update**
```python
# Add to existing BLOCK_AUTH_SETTINGS
BLOCK_AUTH_SETTINGS['FEATURES']['TWO_FACTOR_AUTH'] = True
BLOCK_AUTH_SETTINGS['TWO_FACTOR'] = {
    # Configuration as shown above
}
```

3. **URL Configuration**
```python
# In urls.py
if settings.BLOCK_AUTH_SETTINGS.get('FEATURES', {}).get('TWO_FACTOR_AUTH'):
    urlpatterns += [
        path('auth/2fa/', include('blockauth.twofa.urls')),
    ]
```

4. **Middleware Addition**
```python
# Add to MIDDLEWARE
'blockauth.twofa.middleware.TwoFactorAuthenticationMiddleware'
```

### Progressive Rollout Strategy

1. **Phase 1: Optional for All Users**
   - Enable feature flag
   - Users can opt-in voluntarily
   - Monitor adoption and issues

2. **Phase 2: Encouraged for Sensitive Accounts**
   - Show prompts for admin/staff users
   - Provide incentives for enabling

3. **Phase 3: Mandatory for Admin/Staff**
   - Set `ENFORCE_FOR_ADMIN` = True
   - Provide grace period
   - Force enable after grace period

4. **Phase 4: Available for All (Optional)**
   - Full production deployment
   - User education and documentation

## Appendix

### A. Dependencies

```toml
# pyproject.toml additions
[tool.poetry.dependencies]
pyotp = "^2.9.0"          # TOTP implementation
qrcode = "^7.4.2"         # QR code generation
pillow = "^10.0.0"        # Image processing for QR codes
cryptography = "^41.0.0"   # For secret encryption

[tool.poetry.dev-dependencies]
pytest-django = "^4.5.2"   # Testing
freezegun = "^1.2.2"       # Time mocking for TOTP tests
```

### B. Security Checklist

- [ ] TOTP secrets encrypted at rest
- [ ] Rate limiting on verification endpoints
- [ ] Audit logging for all 2FA events
- [ ] Backup codes single-use only
- [ ] Device trust time-limited
- [ ] HTTPS-only for 2FA endpoints
- [ ] CSRF protection on state-changing operations
- [ ] Clear session on 2FA disable
- [ ] Notification on 2FA changes
- [ ] Account recovery process documented

### C. User Documentation Template

```markdown
# How to Set Up Two-Factor Authentication

## What is 2FA?
Two-factor authentication adds an extra layer of security...

## Setup Instructions
1. Go to Settings > Security
2. Click "Enable 2FA"
3. Choose your preferred method
4. Follow the setup wizard
5. Save your backup codes

## Supported Methods
- Authenticator Apps (Google Authenticator, Authy, 1Password)
- SMS Text Messages
- Email Codes

## Recovery Options
- Use backup codes
- Contact support with identity verification
```

### D. Monitoring and Analytics

```python
# Metrics to track
class TwoFactorMetrics:
    """Metrics for 2FA adoption and usage"""
    
    @staticmethod
    def adoption_rate():
        """Percentage of users with 2FA enabled"""
        total_users = BlockUser.objects.count()
        enabled_users = TwoFactorSettings.objects.filter(is_enabled=True).count()
        return (enabled_users / total_users) * 100 if total_users > 0 else 0
    
    @staticmethod
    def method_distribution():
        """Distribution of 2FA methods"""
        return TwoFactorSettings.objects.filter(is_enabled=True).values('primary_method').annotate(count=Count('id'))
    
    @staticmethod
    def failure_rate():
        """2FA verification failure rate"""
        # Implement based on audit logs
        pass
```

## Conclusion

This implementation provides a robust, modular, and open-source friendly 2FA system for BlockAuth that:

1. **Maintains Independence**: No coupling with fabric-auth or proprietary systems
2. **Follows Best Practices**: Industry-standard TOTP, secure storage, comprehensive audit logging
3. **Provides Flexibility**: Multiple methods, backup codes, trusted devices
4. **Ensures Security**: Rate limiting, encryption, lockout mechanisms
5. **Supports Easy Integration**: Clean APIs, client examples, migration guides

The system is designed to be production-ready while remaining simple to configure and extend for future authentication methods.