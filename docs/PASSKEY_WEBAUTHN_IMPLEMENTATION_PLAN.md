# Passkey/WebAuthn Implementation Plan for BlockAuth

**Document Version:** 1.0
**Created:** 2025-12-17
**Updated:** 2025-12-17
**Status:** Ready for Implementation
**Module:** `blockauth.passkey`

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Feature Overview](#feature-overview)
3. [WebAuthn Protocol Overview](#webauthn-protocol-overview)
4. [Module Architecture](#module-architecture)
5. [Configuration Design](#configuration-design)
6. [Database Schema](#database-schema)
7. [API Endpoints](#api-endpoints)
8. [Implementation Tasks](#implementation-tasks)
9. [Security Requirements](#security-requirements)
10. [Testing Strategy](#testing-strategy)
11. [Integration Guide](#integration-guide)
12. [Dependencies](#dependencies)
13. [File Structure Summary](#file-structure-summary)

---

## Executive Summary

### Purpose

Implement a standalone Passkey/WebAuthn authentication module for BlockAuth that enables passwordless authentication using FIDO2/WebAuthn standards. This module will be:

- **Standalone**: Works independently of other BlockAuth features
- **Optional**: Only loads when explicitly enabled via `PASSKEY_ENABLED=True`
- **Framework-Agnostic**: Can be used with any Django project
- **Configurable**: Supports multiple relying parties, attestation modes, and storage backends
- **Secure**: Follows WebAuthn Level 2 specification with security best practices

### Key Use Cases

1. **Primary Authentication**: Replace passwords entirely with passkeys
2. **MFA Enhancement**: Add passkeys as second factor alongside passwords
3. **Account Recovery**: Use passkeys as recovery mechanism
4. **B2B Integration**: Developers can enable passkeys for their applications
5. **MPC Key Protection**: Use passkey-derived keys to encrypt MPC wallet shards

### Benefits

- **No Passwords**: Eliminates password-related vulnerabilities
- **Phishing Resistant**: Bound to specific origins, immune to phishing
- **Cross-Device**: Synced across user's devices via platform authenticators
- **Biometric**: Uses device biometrics (Face ID, Touch ID, Windows Hello)
- **Standards-Based**: FIDO2/WebAuthn W3C standard

---

## Feature Overview

### What is WebAuthn/Passkey?

WebAuthn (Web Authentication) is a W3C standard that enables strong, passwordless authentication using public-key cryptography. "Passkeys" is the consumer-friendly name for WebAuthn credentials that sync across devices.

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        REGISTRATION FLOW                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. User initiates registration                                         │
│     └── Frontend: "Create Passkey" button clicked                       │
│                                                                         │
│  2. Server generates challenge                                          │
│     ├── POST /auth/passkey/register/options                             │
│     └── Returns: challenge, rp_id, user_id, pubKeyCredParams            │
│                                                                         │
│  3. Browser calls WebAuthn API                                          │
│     ├── navigator.credentials.create(options)                           │
│     └── User authenticates with biometrics                              │
│                                                                         │
│  4. Device generates key pair                                           │
│     ├── Private key: Stored securely on device (never leaves)          │
│     └── Public key: Sent to server for storage                          │
│                                                                         │
│  5. Server verifies and stores credential                               │
│     ├── POST /auth/passkey/register/verify                              │
│     ├── Verify attestation (optional)                                   │
│     └── Store: credential_id, public_key, counter, metadata             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                        AUTHENTICATION FLOW                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. User initiates login                                                │
│     └── Frontend: "Login with Passkey" button clicked                   │
│                                                                         │
│  2. Server generates challenge                                          │
│     ├── POST /auth/passkey/auth/options                                 │
│     └── Returns: challenge, rpId, allowCredentials, timeout             │
│                                                                         │
│  3. Browser calls WebAuthn API                                          │
│     ├── navigator.credentials.get(options)                              │
│     └── User authenticates with biometrics                              │
│                                                                         │
│  4. Device signs challenge                                              │
│     ├── Uses stored private key                                         │
│     └── Returns: signature, authenticatorData, clientDataJSON           │
│                                                                         │
│  5. Server verifies signature                                           │
│     ├── POST /auth/passkey/auth/verify                                  │
│     ├── Verify signature with stored public key                         │
│     ├── Check counter to detect cloned authenticators                   │
│     └── Return: JWT tokens (access + refresh)                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Credential Types

| Type | Description | Example |
|------|-------------|---------|
| **Platform Authenticator** | Built into device | Touch ID, Face ID, Windows Hello |
| **Roaming Authenticator** | External hardware | YubiKey, Titan Security Key |
| **Synced Passkeys** | Cloud-synced credentials | iCloud Keychain, Google Password Manager |

---

## WebAuthn Protocol Overview

### Key Concepts

1. **Relying Party (RP)**: Your application/website
2. **Authenticator**: Device that stores and uses credentials
3. **Credential**: Public-private key pair bound to RP
4. **Challenge**: Server-generated random bytes to prevent replay attacks
5. **Attestation**: Proof that credential was created on legitimate authenticator

### Data Structures

#### PublicKeyCredentialCreationOptions (Registration)

```json
{
  "challenge": "base64url-encoded-random-bytes",
  "rp": {
    "id": "example.com",
    "name": "Example App"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },   // ES256
    { "type": "public-key", "alg": -257 }  // RS256
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "userVerification": "required"
  },
  "timeout": 60000,
  "attestation": "none"
}
```

#### PublicKeyCredentialRequestOptions (Authentication)

```json
{
  "challenge": "base64url-encoded-random-bytes",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "hybrid"]
    }
  ],
  "timeout": 60000,
  "userVerification": "required"
}
```

---

## Module Architecture

### Design Principles

1. **Lazy Loading**: Module only loads when `PASSKEY_ENABLED=True`
2. **Pluggable Storage**: Abstract storage interface for flexibility
3. **Provider Abstraction**: Support different WebAuthn libraries
4. **Event Hooks**: Trigger callbacks on registration/authentication
5. **Configuration-Driven**: All behavior controlled via settings

### Module Structure

```
blockauth/passkey/
├── __init__.py              # Public API: is_enabled(), get_passkey_service()
├── apps.py                  # Django AppConfig
├── constants.py             # PasskeyFeatures, AttestationMode, config keys
├── exceptions.py            # Custom exceptions
├── models.py                # PasskeyCredential Django model
├── serializers.py           # DRF serializers for API
├── services/
│   ├── __init__.py
│   ├── interfaces.py        # Abstract interfaces (IPasskeyService, ICredentialStore)
│   ├── passkey_service.py   # Main service implementing WebAuthn logic
│   ├── challenge_service.py # Challenge generation and validation
│   └── credential_service.py # Credential CRUD operations
├── storage/
│   ├── __init__.py
│   ├── base.py              # Abstract storage interface
│   ├── django_storage.py    # Django ORM implementation
│   └── memory_storage.py    # In-memory for testing
├── views.py                 # DRF API views
├── urls.py                  # URL patterns
├── utils.py                 # Helper functions (base64url encoding, etc.)
├── migrations/
│   ├── __init__.py
│   └── 0001_initial.py
├── tests/
│   ├── __init__.py
│   ├── test_registration.py
│   ├── test_authentication.py
│   ├── test_challenge.py
│   └── test_storage.py
└── README.md                # Module documentation
```

### Class Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PUBLIC API                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  blockauth.passkey.is_enabled() → bool                                  │
│  blockauth.passkey.get_passkey_service() → PasskeyService               │
│  blockauth.passkey.get_credential_store() → ICredentialStore            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PasskeyService                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  + generate_registration_options(user_id, username, display_name)       │
│  + verify_registration(credential_id, client_data, attestation_object)  │
│  + generate_authentication_options(user_id=None)                        │
│  + verify_authentication(credential_id, client_data, auth_data, sig)    │
│                                                                         │
│  - _challenge_service: ChallengeService                                 │
│  - _credential_store: ICredentialStore                                  │
│  - _config: PasskeyConfig                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌──────────────────────┐ ┌──────────────────┐ ┌──────────────────────────┐
│  ChallengeService    │ │ ICredentialStore │ │ PasskeyConfig            │
├──────────────────────┤ ├──────────────────┤ ├──────────────────────────┤
│ + generate()         │ │ + save()         │ │ + rp_id: str             │
│ + validate()         │ │ + get()          │ │ + rp_name: str           │
│ + invalidate()       │ │ + list_for_user()│ │ + allowed_origins: list  │
│                      │ │ + delete()       │ │ + attestation: str       │
│ - _cache: Cache      │ │ + update_counter │ │ + timeout: int           │
│ - _expiry: int       │ └──────────────────┘ │ + user_verification: str │
└──────────────────────┘          │           └──────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
        ┌──────────────────────┐    ┌──────────────────────┐
        │  DjangoCredentialStore │    │ MemoryCredentialStore │
        ├──────────────────────┤    ├──────────────────────┤
        │ Uses Django ORM      │    │ For testing          │
        │ PasskeyCredential    │    │ Dict-based storage   │
        └──────────────────────┘    └──────────────────────┘
```

---

## Configuration Design

### Settings Structure

```python
# settings.py
BLOCK_AUTH_SETTINGS = {
    # ... existing settings ...

    # ═══════════════════════════════════════════════════════════════════
    # PASSKEY/WEBAUTHN CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════

    # Master switch - must be True to use Passkey functionality
    'PASSKEY_ENABLED': True,

    # Relying Party configuration
    'PASSKEY_RP_ID': 'example.com',           # Domain (no protocol, no port)
    'PASSKEY_RP_NAME': 'Example Application', # Human-readable name

    # Allowed origins (for cross-origin support)
    'PASSKEY_ALLOWED_ORIGINS': [
        'https://example.com',
        'https://app.example.com',
    ],

    # Attestation mode
    # Options: 'none', 'indirect', 'direct', 'enterprise'
    'PASSKEY_ATTESTATION': 'none',

    # Authenticator preferences
    # Options: 'platform', 'cross-platform', None (any)
    'PASSKEY_AUTHENTICATOR_ATTACHMENT': None,

    # Resident key (discoverable credential) preference
    # Options: 'required', 'preferred', 'discouraged'
    'PASSKEY_RESIDENT_KEY': 'preferred',

    # User verification requirement
    # Options: 'required', 'preferred', 'discouraged'
    'PASSKEY_USER_VERIFICATION': 'required',

    # Timeouts (milliseconds)
    'PASSKEY_REGISTRATION_TIMEOUT': 60000,  # 60 seconds
    'PASSKEY_AUTHENTICATION_TIMEOUT': 60000,

    # Challenge configuration
    'PASSKEY_CHALLENGE_LENGTH': 32,      # bytes
    'PASSKEY_CHALLENGE_EXPIRY': 300,     # seconds (5 minutes)

    # Supported algorithms (COSE algorithm identifiers)
    # -7: ES256 (ECDSA with P-256 and SHA-256)
    # -257: RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
    # -8: EdDSA (Ed25519)
    'PASSKEY_SUPPORTED_ALGORITHMS': [-7, -257],

    # Credential limits
    'PASSKEY_MAX_CREDENTIALS_PER_USER': 10,

    # Storage backend
    # Options: 'django', 'memory' (for testing)
    'PASSKEY_STORAGE_BACKEND': 'django',

    # Rate limiting
    'PASSKEY_RATE_LIMITS': {
        'registration_options': '10/hour',
        'registration_verify': '5/hour',
        'authentication_options': '20/minute',
        'authentication_verify': '10/minute',
    },

    # Hooks/Triggers
    'PASSKEY_POST_REGISTRATION_TRIGGER': 'blockauth.passkey.triggers.DummyPostRegistrationTrigger',
    'PASSKEY_POST_AUTHENTICATION_TRIGGER': 'blockauth.passkey.triggers.DummyPostAuthenticationTrigger',

    # Feature flags within passkey module
    'PASSKEY_FEATURES': {
        'DISCOVERABLE_CREDENTIALS': True,    # Allow passwordless with discoverable credentials
        'CROSS_ORIGIN': False,               # Allow cross-origin requests (iframe scenarios)
        'ATTESTATION_VERIFICATION': False,   # Verify attestation certificates
        'COUNTER_VALIDATION': True,          # Detect cloned authenticators via counter
    },
}
```

### Configuration Constants

```python
# blockauth/passkey/constants.py

from enum import Enum, IntEnum

class PasskeyConfigKeys:
    """Configuration key names"""
    ENABLED = 'PASSKEY_ENABLED'
    RP_ID = 'PASSKEY_RP_ID'
    RP_NAME = 'PASSKEY_RP_NAME'
    ALLOWED_ORIGINS = 'PASSKEY_ALLOWED_ORIGINS'
    ATTESTATION = 'PASSKEY_ATTESTATION'
    AUTHENTICATOR_ATTACHMENT = 'PASSKEY_AUTHENTICATOR_ATTACHMENT'
    RESIDENT_KEY = 'PASSKEY_RESIDENT_KEY'
    USER_VERIFICATION = 'PASSKEY_USER_VERIFICATION'
    REGISTRATION_TIMEOUT = 'PASSKEY_REGISTRATION_TIMEOUT'
    AUTHENTICATION_TIMEOUT = 'PASSKEY_AUTHENTICATION_TIMEOUT'
    CHALLENGE_LENGTH = 'PASSKEY_CHALLENGE_LENGTH'
    CHALLENGE_EXPIRY = 'PASSKEY_CHALLENGE_EXPIRY'
    SUPPORTED_ALGORITHMS = 'PASSKEY_SUPPORTED_ALGORITHMS'
    MAX_CREDENTIALS_PER_USER = 'PASSKEY_MAX_CREDENTIALS_PER_USER'
    STORAGE_BACKEND = 'PASSKEY_STORAGE_BACKEND'
    RATE_LIMITS = 'PASSKEY_RATE_LIMITS'
    FEATURES = 'PASSKEY_FEATURES'


class AttestationMode(str, Enum):
    """Attestation conveyance preference"""
    NONE = 'none'
    INDIRECT = 'indirect'
    DIRECT = 'direct'
    ENTERPRISE = 'enterprise'


class AuthenticatorAttachment(str, Enum):
    """Authenticator attachment modality"""
    PLATFORM = 'platform'
    CROSS_PLATFORM = 'cross-platform'


class ResidentKeyRequirement(str, Enum):
    """Resident key (discoverable credential) requirement"""
    REQUIRED = 'required'
    PREFERRED = 'preferred'
    DISCOURAGED = 'discouraged'


class UserVerificationRequirement(str, Enum):
    """User verification requirement"""
    REQUIRED = 'required'
    PREFERRED = 'preferred'
    DISCOURAGED = 'discouraged'


class COSEAlgorithm(IntEnum):
    """COSE algorithm identifiers"""
    ES256 = -7      # ECDSA with P-256 and SHA-256
    ES384 = -35     # ECDSA with P-384 and SHA-384
    ES512 = -36     # ECDSA with P-521 and SHA-512
    RS256 = -257    # RSASSA-PKCS1-v1_5 with SHA-256
    RS384 = -258    # RSASSA-PKCS1-v1_5 with SHA-384
    RS512 = -259    # RSASSA-PKCS1-v1_5 with SHA-512
    PS256 = -37     # RSASSA-PSS with SHA-256
    PS384 = -38     # RSASSA-PSS with SHA-384
    PS512 = -39     # RSASSA-PSS with SHA-512
    EDDSA = -8      # EdDSA (Ed25519/Ed448)


class PasskeyFeatureFlags:
    """Feature flag keys"""
    DISCOVERABLE_CREDENTIALS = 'DISCOVERABLE_CREDENTIALS'
    CROSS_ORIGIN = 'CROSS_ORIGIN'
    ATTESTATION_VERIFICATION = 'ATTESTATION_VERIFICATION'
    COUNTER_VALIDATION = 'COUNTER_VALIDATION'
```

---

## Database Schema

### PasskeyCredential Model

```python
# blockauth/passkey/models.py

import uuid
from django.db import models
from django.conf import settings


class PasskeyCredential(models.Model):
    """
    Stores WebAuthn credentials for users.

    Each credential represents a passkey registered on a user's device.
    Users can have multiple credentials across different devices.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    # Link to user (using AUTH_USER_MODEL for flexibility)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='passkey_credentials'
    )

    # Credential identifier (from authenticator)
    # Base64URL encoded, variable length (usually 16-64 bytes)
    credential_id = models.TextField(
        unique=True,
        db_index=True,
        help_text="Base64URL-encoded credential ID from authenticator"
    )

    # Public key (COSE-encoded)
    # Base64URL encoded
    public_key = models.TextField(
        help_text="Base64URL-encoded COSE public key"
    )

    # COSE algorithm identifier
    algorithm = models.IntegerField(
        default=-7,  # ES256
        help_text="COSE algorithm identifier (e.g., -7 for ES256)"
    )

    # Signature counter (for clone detection)
    sign_count = models.BigIntegerField(
        default=0,
        help_text="Signature counter to detect cloned authenticators"
    )

    # AAGUID (Authenticator Attestation GUID)
    # Identifies the authenticator model
    aaguid = models.CharField(
        max_length=36,
        blank=True,
        default='',
        help_text="Authenticator model identifier (AAGUID)"
    )

    # User-friendly name for the credential
    name = models.CharField(
        max_length=255,
        default='',
        blank=True,
        help_text="User-provided name for this credential (e.g., 'iPhone 15')"
    )

    # Device/transport information
    transports = models.JSONField(
        default=list,
        blank=True,
        help_text="Supported transports: internal, usb, nfc, ble, hybrid"
    )

    # Authenticator attachment type
    authenticator_attachment = models.CharField(
        max_length=20,
        blank=True,
        default='',
        help_text="platform or cross-platform"
    )

    # Backup eligibility and state (for synced passkeys)
    backup_eligible = models.BooleanField(
        default=False,
        help_text="Whether credential can be backed up"
    )
    backup_state = models.BooleanField(
        default=False,
        help_text="Whether credential is currently backed up"
    )

    # Discoverable credential (resident key)
    is_discoverable = models.BooleanField(
        default=False,
        help_text="Whether this is a discoverable credential (resident key)"
    )

    # Attestation data (optional, for enterprise use)
    attestation_object = models.TextField(
        blank=True,
        default='',
        help_text="Base64URL-encoded attestation object (if attestation was requested)"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    # Soft delete
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this credential is active"
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        db_table = 'blockauth_passkey_credential'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['credential_id']),
            models.Index(fields=['last_used_at']),
        ]
        verbose_name = 'Passkey Credential'
        verbose_name_plural = 'Passkey Credentials'

    def __str__(self):
        return f"{self.name or 'Unnamed'} ({self.user.email})"

    def update_counter(self, new_count: int) -> bool:
        """
        Update signature counter. Returns False if counter regression detected.

        Counter regression indicates a potentially cloned authenticator.
        """
        if new_count <= self.sign_count:
            return False
        self.sign_count = new_count
        self.save(update_fields=['sign_count'])
        return True


class PasskeyChallenge(models.Model):
    """
    Temporary storage for WebAuthn challenges.

    Challenges must be single-use and expire quickly to prevent replay attacks.
    This model can be replaced with Redis/cache storage for better performance.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    # Challenge value (base64url encoded)
    challenge = models.CharField(
        max_length=255,
        unique=True,
        db_index=True
    )

    # Associated user (optional for discoverable credentials)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    # Challenge type
    challenge_type = models.CharField(
        max_length=20,
        choices=[
            ('registration', 'Registration'),
            ('authentication', 'Authentication'),
        ]
    )

    # Expiration
    expires_at = models.DateTimeField()

    # Whether challenge has been used
    is_used = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'blockauth_passkey_challenge'
        indexes = [
            models.Index(fields=['challenge']),
            models.Index(fields=['expires_at']),
        ]
```

### Migration

```python
# blockauth/passkey/migrations/0001_initial.py

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PasskeyCredential',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('credential_id', models.TextField(db_index=True, help_text='Base64URL-encoded credential ID from authenticator', unique=True)),
                ('public_key', models.TextField(help_text='Base64URL-encoded COSE public key')),
                ('algorithm', models.IntegerField(default=-7, help_text='COSE algorithm identifier (e.g., -7 for ES256)')),
                ('sign_count', models.BigIntegerField(default=0, help_text='Signature counter to detect cloned authenticators')),
                ('aaguid', models.CharField(blank=True, default='', help_text='Authenticator model identifier (AAGUID)', max_length=36)),
                ('name', models.CharField(blank=True, default='', help_text="User-provided name for this credential (e.g., 'iPhone 15')", max_length=255)),
                ('transports', models.JSONField(blank=True, default=list, help_text='Supported transports: internal, usb, nfc, ble, hybrid')),
                ('authenticator_attachment', models.CharField(blank=True, default='', help_text='platform or cross-platform', max_length=20)),
                ('backup_eligible', models.BooleanField(default=False, help_text='Whether credential can be backed up')),
                ('backup_state', models.BooleanField(default=False, help_text='Whether credential is currently backed up')),
                ('is_discoverable', models.BooleanField(default=False, help_text='Whether this is a discoverable credential (resident key)')),
                ('attestation_object', models.TextField(blank=True, default='', help_text='Base64URL-encoded attestation object (if attestation was requested)')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True, help_text='Whether this credential is active')),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('revocation_reason', models.CharField(blank=True, default='', max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='passkey_credentials', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Passkey Credential',
                'verbose_name_plural': 'Passkey Credentials',
                'db_table': 'blockauth_passkey_credential',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='PasskeyChallenge',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('challenge', models.CharField(db_index=True, max_length=255, unique=True)),
                ('challenge_type', models.CharField(choices=[('registration', 'Registration'), ('authentication', 'Authentication')], max_length=20)),
                ('expires_at', models.DateTimeField()),
                ('is_used', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'blockauth_passkey_challenge',
            },
        ),
        migrations.AddIndex(
            model_name='passkeyCredential',
            index=models.Index(fields=['user', 'is_active'], name='blockauth_p_user_id_idx'),
        ),
        migrations.AddIndex(
            model_name='passkeyCredential',
            index=models.Index(fields=['credential_id'], name='blockauth_p_cred_id_idx'),
        ),
        migrations.AddIndex(
            model_name='passkeyCredential',
            index=models.Index(fields=['last_used_at'], name='blockauth_p_last_used_idx'),
        ),
        migrations.AddIndex(
            model_name='passkeychallenge',
            index=models.Index(fields=['challenge'], name='blockauth_c_challenge_idx'),
        ),
        migrations.AddIndex(
            model_name='passkeychallenge',
            index=models.Index(fields=['expires_at'], name='blockauth_c_expires_idx'),
        ),
    ]
```

---

## API Endpoints

### URL Configuration

```python
# blockauth/passkey/urls.py

from django.urls import path
from . import views

app_name = 'passkey'

urlpatterns = [
    # Registration
    path('register/options/', views.RegistrationOptionsView.as_view(), name='register-options'),
    path('register/verify/', views.RegistrationVerifyView.as_view(), name='register-verify'),

    # Authentication
    path('auth/options/', views.AuthenticationOptionsView.as_view(), name='auth-options'),
    path('auth/verify/', views.AuthenticationVerifyView.as_view(), name='auth-verify'),

    # Credential management
    path('credentials/', views.CredentialListView.as_view(), name='credential-list'),
    path('credentials/<uuid:credential_id>/', views.CredentialDetailView.as_view(), name='credential-detail'),
]
```

### Endpoint Specifications

#### 1. Registration Options

```
POST /auth/passkey/register/options/
Authorization: Bearer <access_token>  # Required - user must be authenticated

Request:
{
  "display_name": "John Doe"  # Optional, defaults to username
}

Response (200 OK):
{
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "id": "example.com",
    "name": "Example Application"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "john@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "userVerification": "required"
  },
  "timeout": 60000,
  "attestation": "none",
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "existing-credential-id",
      "transports": ["internal"]
    }
  ]
}

Errors:
- 401 Unauthorized: Not authenticated
- 429 Too Many Requests: Rate limit exceeded
- 400 Bad Request: Max credentials reached
```

#### 2. Registration Verify

```
POST /auth/passkey/register/verify/
Authorization: Bearer <access_token>

Request:
{
  "id": "base64url-credential-id",
  "rawId": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded",
    "attestationObject": "base64url-encoded",
    "transports": ["internal", "hybrid"]
  },
  "name": "My iPhone"  # Optional credential name
}

Response (201 Created):
{
  "id": "uuid",
  "credential_id": "base64url-credential-id",
  "name": "My iPhone",
  "created_at": "2025-12-17T12:00:00Z",
  "authenticator_attachment": "platform",
  "transports": ["internal", "hybrid"],
  "backup_eligible": true
}

Errors:
- 400 Bad Request: Invalid attestation, challenge expired, origin mismatch
- 401 Unauthorized: Not authenticated
- 409 Conflict: Credential already exists
```

#### 3. Authentication Options

```
POST /auth/passkey/auth/options/
Authorization: None (public endpoint)

Request:
{
  "username": "john@example.com"  # Optional for discoverable credentials
}

Response (200 OK):
{
  "challenge": "base64url-encoded-challenge",
  "rpId": "example.com",
  "timeout": 60000,
  "userVerification": "required",
  "allowCredentials": [  # Empty for discoverable credentials
    {
      "type": "public-key",
      "id": "base64url-credential-id",
      "transports": ["internal", "hybrid"]
    }
  ]
}

Errors:
- 404 Not Found: User has no credentials (if username provided)
- 429 Too Many Requests: Rate limit exceeded
```

#### 4. Authentication Verify

```
POST /auth/passkey/auth/verify/
Authorization: None (public endpoint)

Request:
{
  "id": "base64url-credential-id",
  "rawId": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded",
    "authenticatorData": "base64url-encoded",
    "signature": "base64url-encoded",
    "userHandle": "base64url-user-id"  # For discoverable credentials
  }
}

Response (200 OK):
{
  "access": "jwt-access-token",
  "refresh": "jwt-refresh-token",
  "user": {
    "id": "user-uuid",
    "email": "john@example.com"
  },
  "credential": {
    "id": "credential-uuid",
    "name": "My iPhone",
    "last_used_at": "2025-12-17T12:00:00Z"
  }
}

Errors:
- 400 Bad Request: Invalid signature, challenge expired, counter regression
- 404 Not Found: Credential not found
- 403 Forbidden: Credential revoked
```

#### 5. Credential List

```
GET /auth/passkey/credentials/
Authorization: Bearer <access_token>

Response (200 OK):
{
  "count": 2,
  "credentials": [
    {
      "id": "uuid-1",
      "credential_id": "base64url-credential-id-1",
      "name": "My iPhone",
      "created_at": "2025-12-17T12:00:00Z",
      "last_used_at": "2025-12-17T14:30:00Z",
      "authenticator_attachment": "platform",
      "transports": ["internal", "hybrid"],
      "backup_eligible": true,
      "backup_state": true,
      "is_active": true
    },
    {
      "id": "uuid-2",
      "credential_id": "base64url-credential-id-2",
      "name": "YubiKey",
      "created_at": "2025-12-10T10:00:00Z",
      "last_used_at": "2025-12-15T09:15:00Z",
      "authenticator_attachment": "cross-platform",
      "transports": ["usb"],
      "backup_eligible": false,
      "backup_state": false,
      "is_active": true
    }
  ]
}
```

#### 6. Credential Detail (Update/Delete)

```
PATCH /auth/passkey/credentials/<uuid>/
Authorization: Bearer <access_token>

Request:
{
  "name": "Work MacBook"
}

Response (200 OK):
{
  "id": "uuid",
  "name": "Work MacBook",
  ...
}

---

DELETE /auth/passkey/credentials/<uuid>/
Authorization: Bearer <access_token>

Response (204 No Content)

Errors:
- 404 Not Found: Credential not found or belongs to different user
- 400 Bad Request: Cannot delete last credential (optional policy)
```

---

## Implementation Tasks

### Phase 1: Foundation (Tasks 1-10)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-1 | Module Structure Setup | Create `passkey/` directory with `__init__.py`, `apps.py`, `constants.py`, `exceptions.py` | P0 | None | 2h |
| PK-2 | Configuration System | Implement config loading from `BLOCK_AUTH_SETTINGS`, defaults, validation | P0 | PK-1 | 4h |
| PK-3 | Database Models | Create `PasskeyCredential` and `PasskeyChallenge` models | P0 | PK-1 | 3h |
| PK-4 | Migrations | Generate and test initial migration | P0 | PK-3 | 1h |
| PK-5 | Storage Interface | Create abstract `ICredentialStore` interface | P0 | PK-1 | 2h |
| PK-6 | Django Storage Implementation | Implement `DjangoCredentialStore` using Django ORM | P0 | PK-3, PK-5 | 3h |
| PK-7 | Memory Storage Implementation | Implement `MemoryCredentialStore` for testing | P1 | PK-5 | 2h |
| PK-8 | Challenge Service | Implement challenge generation, validation, expiry | P0 | PK-2 | 3h |
| PK-9 | Base64URL Utilities | Implement base64url encoding/decoding helpers | P0 | None | 1h |
| PK-10 | Exception Classes | Define custom exceptions for all error cases | P0 | PK-1 | 1h |

### Phase 2: Core WebAuthn Logic (Tasks 11-18)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-11 | py-webauthn Integration | Add py-webauthn library, configure for Django | P0 | PK-1 | 2h |
| PK-12 | Registration Options Generator | Implement `generate_registration_options()` | P0 | PK-2, PK-8, PK-11 | 4h |
| PK-13 | Registration Verifier | Implement `verify_registration_response()` | P0 | PK-6, PK-8, PK-11 | 6h |
| PK-14 | Authentication Options Generator | Implement `generate_authentication_options()` | P0 | PK-2, PK-6, PK-8 | 3h |
| PK-15 | Authentication Verifier | Implement `verify_authentication_response()` | P0 | PK-6, PK-8, PK-11 | 6h |
| PK-16 | Counter Validation | Implement signature counter validation for clone detection | P0 | PK-15 | 2h |
| PK-17 | Origin Validation | Implement strict origin checking with subdomain support | P0 | PK-2 | 2h |
| PK-18 | PasskeyService Class | Combine all logic into main service class | P0 | PK-12 to PK-17 | 3h |

### Phase 3: API Layer (Tasks 19-26)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-19 | DRF Serializers | Create serializers for all request/response types | P0 | PK-3 | 4h |
| PK-20 | Registration Options View | `POST /passkey/register/options/` endpoint | P0 | PK-12, PK-19 | 2h |
| PK-21 | Registration Verify View | `POST /passkey/register/verify/` endpoint | P0 | PK-13, PK-19 | 3h |
| PK-22 | Authentication Options View | `POST /passkey/auth/options/` endpoint | P0 | PK-14, PK-19 | 2h |
| PK-23 | Authentication Verify View | `POST /passkey/auth/verify/` endpoint with JWT response | P0 | PK-15, PK-19 | 3h |
| PK-24 | Credential List View | `GET /passkey/credentials/` endpoint | P1 | PK-6, PK-19 | 2h |
| PK-25 | Credential Detail View | `PATCH/DELETE /passkey/credentials/<id>/` endpoint | P1 | PK-6, PK-19 | 2h |
| PK-26 | URL Configuration | Create `urls.py` with all routes | P0 | PK-20 to PK-25 | 1h |

### Phase 4: Security & Hardening (Tasks 27-32)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-27 | Rate Limiting | Implement rate limiting for all endpoints | P0 | PK-20 to PK-25 | 3h |
| PK-28 | Challenge Expiry Cleanup | Implement expired challenge cleanup (cron/celery) | P1 | PK-8 | 2h |
| PK-29 | Audit Logging | Log all passkey operations for security audit | P1 | PK-18 | 3h |
| PK-30 | Input Validation | Strict validation on all inputs, sanitize outputs | P0 | PK-19 | 3h |
| PK-31 | Error Handling | Consistent error responses, no sensitive data leakage | P0 | PK-10 | 2h |
| PK-32 | Security Headers | Ensure proper CORS, CSP headers for WebAuthn | P1 | PK-26 | 2h |

### Phase 5: Testing (Tasks 33-38)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-33 | Unit Tests - Services | Test PasskeyService, ChallengeService methods | P0 | PK-18 | 6h |
| PK-34 | Unit Tests - Storage | Test credential storage operations | P0 | PK-6, PK-7 | 3h |
| PK-35 | Integration Tests - Registration | End-to-end registration flow tests | P0 | PK-21 | 4h |
| PK-36 | Integration Tests - Authentication | End-to-end authentication flow tests | P0 | PK-23 | 4h |
| PK-37 | Security Tests | Replay attacks, origin bypass, counter regression | P1 | PK-35, PK-36 | 4h |
| PK-38 | Mock Authenticator | Create test utilities for simulating authenticators | P1 | PK-33 | 3h |

### Phase 6: Documentation & Polish (Tasks 39-44)

| ID | Task | Description | Priority | Dependencies | Effort |
|----|------|-------------|----------|--------------|--------|
| PK-39 | Module README | Comprehensive module documentation | P1 | All | 4h |
| PK-40 | API Documentation | OpenAPI/Swagger docs for all endpoints | P1 | PK-26 | 3h |
| PK-41 | Integration Guide | How to integrate in Django projects | P1 | All | 3h |
| PK-42 | Frontend Example | React/JS example for WebAuthn API calls | P2 | PK-26 | 4h |
| PK-43 | Triggers/Hooks | Implement post-registration/auth triggers | P2 | PK-18 | 2h |
| PK-44 | Public API Finalization | Finalize `__init__.py` exports | P0 | All | 1h |

### Task Summary

| Phase | Tasks | Total Effort |
|-------|-------|--------------|
| Phase 1: Foundation | 10 | 22h |
| Phase 2: Core WebAuthn | 8 | 28h |
| Phase 3: API Layer | 8 | 19h |
| Phase 4: Security | 6 | 15h |
| Phase 5: Testing | 6 | 24h |
| Phase 6: Documentation | 6 | 17h |
| **TOTAL** | **44** | **125h** |

---

## Security Requirements

### MANDATORY Security Measures

#### 1. Challenge Security

```python
# REQUIRED: Cryptographically secure random challenges
import secrets

def generate_challenge(length: int = 32) -> bytes:
    """Generate cryptographically secure challenge."""
    return secrets.token_bytes(length)

# REQUIRED: Challenge must be single-use
# REQUIRED: Challenge must expire within 5 minutes
# REQUIRED: Challenge must be bound to session/user
```

#### 2. Origin Validation

```python
# REQUIRED: Strict origin checking
ALLOWED_ORIGINS = ['https://example.com', 'https://app.example.com']

def validate_origin(client_data: dict, allowed_origins: list) -> bool:
    """
    Validate origin matches expected values.

    SECURITY: Origin validation prevents phishing attacks.
    Attacker sites cannot use credentials registered on legitimate sites.
    """
    origin = client_data.get('origin')
    return origin in allowed_origins
```

#### 3. Counter Validation

```python
# REQUIRED: Detect cloned authenticators via counter
def validate_counter(stored_count: int, new_count: int) -> bool:
    """
    Validate signature counter has increased.

    SECURITY: Counter regression indicates potentially cloned authenticator.
    If counter goes backward, credential may be compromised.
    """
    if new_count <= stored_count:
        # SECURITY ALERT: Possible cloned authenticator
        log_security_event('counter_regression', {
            'stored': stored_count,
            'received': new_count
        })
        return False
    return True
```

#### 4. Replay Attack Prevention

```python
# REQUIRED: Challenges must be single-use
def use_challenge(challenge: str) -> bool:
    """
    Mark challenge as used. Returns False if already used.

    SECURITY: Prevents replay attacks where attacker captures
    and reuses valid authentication response.
    """
    challenge_obj = PasskeyChallenge.objects.filter(
        challenge=challenge,
        is_used=False,
        expires_at__gt=timezone.now()
    ).first()

    if not challenge_obj:
        return False

    challenge_obj.is_used = True
    challenge_obj.save()
    return True
```

#### 5. Rate Limiting

```python
# REQUIRED: Rate limit all endpoints
RATE_LIMITS = {
    'registration_options': '10/hour',     # Prevent enumeration
    'registration_verify': '5/hour',       # Prevent abuse
    'authentication_options': '20/minute', # Allow legitimate retries
    'authentication_verify': '10/minute',  # Prevent brute force
}
```

### Security Checklist

- [ ] Challenges are cryptographically random (32+ bytes)
- [ ] Challenges expire within 5 minutes
- [ ] Challenges are single-use
- [ ] Origin validation is strict
- [ ] RP ID matches expected domain
- [ ] Counter validation detects clones
- [ ] Rate limiting on all endpoints
- [ ] No sensitive data in error messages
- [ ] Audit logging for all operations
- [ ] HTTPS required in production
- [ ] Proper CORS configuration
- [ ] User verification enforced

---

## Testing Strategy

### Test Categories

#### 1. Unit Tests

```python
# test_services.py

class TestPasskeyService:
    """Unit tests for PasskeyService"""

    def test_generate_registration_options(self):
        """Test registration options generation"""
        pass

    def test_verify_registration_valid(self):
        """Test valid registration verification"""
        pass

    def test_verify_registration_invalid_challenge(self):
        """Test registration with expired/invalid challenge"""
        pass

    def test_verify_registration_invalid_origin(self):
        """Test registration with wrong origin"""
        pass

class TestChallengeService:
    """Unit tests for ChallengeService"""

    def test_generate_challenge_length(self):
        """Test challenge has correct length"""
        pass

    def test_challenge_expiry(self):
        """Test challenge expires after configured time"""
        pass

    def test_challenge_single_use(self):
        """Test challenge cannot be reused"""
        pass
```

#### 2. Integration Tests

```python
# test_integration.py

class TestRegistrationFlow:
    """End-to-end registration tests"""

    def test_full_registration_flow(self):
        """Test complete registration with mock authenticator"""
        # 1. Get options
        response = client.post('/auth/passkey/register/options/')
        assert response.status_code == 200

        # 2. Simulate authenticator response
        credential = mock_authenticator.create(response.json())

        # 3. Verify registration
        response = client.post('/auth/passkey/register/verify/', credential)
        assert response.status_code == 201

class TestAuthenticationFlow:
    """End-to-end authentication tests"""

    def test_full_authentication_flow(self):
        """Test complete authentication with mock authenticator"""
        pass
```

#### 3. Security Tests

```python
# test_security.py

class TestSecurityMeasures:
    """Security-focused tests"""

    def test_replay_attack_prevention(self):
        """Verify same challenge cannot be used twice"""
        pass

    def test_challenge_expiry(self):
        """Verify expired challenges are rejected"""
        pass

    def test_origin_validation(self):
        """Verify wrong origin is rejected"""
        pass

    def test_counter_regression_detection(self):
        """Verify counter regression triggers alert"""
        pass

    def test_rate_limiting(self):
        """Verify rate limits are enforced"""
        pass
```

### Mock Authenticator

```python
# test_utils.py

class MockAuthenticator:
    """
    Simulates WebAuthn authenticator for testing.

    Usage:
        authenticator = MockAuthenticator()
        credential = authenticator.create(registration_options)
        assertion = authenticator.get(authentication_options)
    """

    def __init__(self):
        self.credentials = {}
        self.counter = 0

    def create(self, options: dict) -> dict:
        """Simulate credential creation"""
        # Generate key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Create credential ID
        credential_id = secrets.token_bytes(32)

        # Store for later authentication
        self.credentials[credential_id] = {
            'private_key': private_key,
            'public_key': public_key,
            'rp_id': options['rp']['id'],
        }

        # Return attestation response
        return {
            'id': base64url_encode(credential_id),
            'rawId': base64url_encode(credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': self._create_client_data(options['challenge'], 'webauthn.create'),
                'attestationObject': self._create_attestation(public_key),
                'transports': ['internal'],
            }
        }

    def get(self, options: dict, credential_id: bytes) -> dict:
        """Simulate authentication"""
        self.counter += 1
        credential = self.credentials[credential_id]

        # Sign the challenge
        client_data = self._create_client_data(options['challenge'], 'webauthn.get')
        auth_data = self._create_auth_data(options['rpId'], self.counter)
        signature = self._sign(credential['private_key'], auth_data, client_data)

        return {
            'id': base64url_encode(credential_id),
            'rawId': base64url_encode(credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': client_data,
                'authenticatorData': auth_data,
                'signature': signature,
            }
        }
```

---

## Integration Guide

### Adding to Django Project

```python
# 1. Install blockauth (if not already)
# pip install blockauth

# 2. Add to INSTALLED_APPS
INSTALLED_APPS = [
    ...
    'blockauth',
    'blockauth.passkey',  # Add passkey app
]

# 3. Configure in settings.py
BLOCK_AUTH_SETTINGS = {
    # Enable passkey
    'PASSKEY_ENABLED': True,
    'PASSKEY_RP_ID': 'yourdomain.com',
    'PASSKEY_RP_NAME': 'Your Application',
    'PASSKEY_ALLOWED_ORIGINS': ['https://yourdomain.com'],

    # Other settings...
}

# 4. Add URLs
urlpatterns = [
    path('auth/', include('blockauth.urls')),
    path('auth/passkey/', include('blockauth.passkey.urls')),
]

# 5. Run migrations
# python manage.py migrate blockauth_passkey
```

### Frontend Integration (JavaScript)

```javascript
// Registration
async function registerPasskey() {
    // 1. Get options from server
    const optionsResponse = await fetch('/auth/passkey/register/options/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ display_name: 'My Device' })
    });
    const options = await optionsResponse.json();

    // 2. Decode challenge and user.id
    options.challenge = base64urlDecode(options.challenge);
    options.user.id = base64urlDecode(options.user.id);
    options.excludeCredentials?.forEach(cred => {
        cred.id = base64urlDecode(cred.id);
    });

    // 3. Create credential
    const credential = await navigator.credentials.create({
        publicKey: options
    });

    // 4. Send to server for verification
    const verifyResponse = await fetch('/auth/passkey/register/verify/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: base64urlEncode(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
                attestationObject: base64urlEncode(credential.response.attestationObject),
                transports: credential.response.getTransports?.() || []
            },
            name: 'My iPhone'
        })
    });

    return verifyResponse.json();
}

// Authentication
async function authenticateWithPasskey(username = null) {
    // 1. Get options from server
    const optionsResponse = await fetch('/auth/passkey/auth/options/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    const options = await optionsResponse.json();

    // 2. Decode challenge and credential IDs
    options.challenge = base64urlDecode(options.challenge);
    options.allowCredentials?.forEach(cred => {
        cred.id = base64urlDecode(cred.id);
    });

    // 3. Get assertion
    const assertion = await navigator.credentials.get({
        publicKey: options
    });

    // 4. Send to server for verification
    const verifyResponse = await fetch('/auth/passkey/auth/verify/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: assertion.id,
            rawId: base64urlEncode(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
                authenticatorData: base64urlEncode(assertion.response.authenticatorData),
                signature: base64urlEncode(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? base64urlEncode(assertion.response.userHandle)
                    : null
            }
        })
    });

    return verifyResponse.json();  // { access, refresh, user }
}

// Helper functions
function base64urlEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(base64 + padding);
    return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
}
```

---

## Dependencies

### Required Python Packages

```toml
# pyproject.toml additions

[tool.poetry.dependencies]
# WebAuthn library (REQUIRED)
py-webauthn = "^2.0.0"

# Already in blockauth (verify versions)
django = "^4.2"
djangorestframework = "^3.14"
PyJWT = "^2.8"
```

### Package Details

| Package | Version | Purpose |
|---------|---------|---------|
| `py-webauthn` | ^2.0.0 | WebAuthn protocol implementation |
| `cbor2` | ^5.5.0 | CBOR encoding (dependency of py-webauthn) |
| `cryptography` | ^41.0.0 | Cryptographic operations |

### Optional Dependencies

| Package | Purpose |
|---------|---------|
| `django-redis` | Cache challenges in Redis instead of database |
| `celery` | Background task for challenge cleanup |

---

## File Structure Summary

```
services/auth-pack/
├── blockauth/
│   ├── passkey/                          # NEW MODULE
│   │   ├── __init__.py                   # PK-1, PK-44
│   │   ├── apps.py                       # PK-1
│   │   ├── constants.py                  # PK-1
│   │   ├── exceptions.py                 # PK-10
│   │   ├── models.py                     # PK-3
│   │   ├── serializers.py                # PK-19
│   │   ├── views.py                      # PK-20 to PK-25
│   │   ├── urls.py                       # PK-26
│   │   ├── utils.py                      # PK-9
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── interfaces.py             # PK-5
│   │   │   ├── passkey_service.py        # PK-18
│   │   │   ├── challenge_service.py      # PK-8
│   │   │   └── credential_service.py     # PK-6
│   │   ├── storage/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                   # PK-5
│   │   │   ├── django_storage.py         # PK-6
│   │   │   └── memory_storage.py         # PK-7
│   │   ├── migrations/
│   │   │   ├── __init__.py
│   │   │   └── 0001_initial.py           # PK-4
│   │   ├── tests/
│   │   │   ├── __init__.py
│   │   │   ├── test_services.py          # PK-33
│   │   │   ├── test_storage.py           # PK-34
│   │   │   ├── test_registration.py      # PK-35
│   │   │   ├── test_authentication.py    # PK-36
│   │   │   ├── test_security.py          # PK-37
│   │   │   └── mock_authenticator.py     # PK-38
│   │   └── README.md                     # PK-39
│   └── ... (existing modules)
├── docs/
│   ├── PASSKEY_WEBAUTHN_IMPLEMENTATION_PLAN.md  # THIS DOCUMENT
│   └── ... (existing docs)
└── ... (other files)
```

---

## Appendix A: Error Codes

| Code | Message | Description |
|------|---------|-------------|
| `PASSKEY_001` | Passkey module not enabled | Set `PASSKEY_ENABLED=True` |
| `PASSKEY_002` | Challenge expired | Generate new challenge |
| `PASSKEY_003` | Challenge already used | Generate new challenge |
| `PASSKEY_004` | Invalid origin | Origin doesn't match allowed origins |
| `PASSKEY_005` | Invalid RP ID | RP ID doesn't match configuration |
| `PASSKEY_006` | Credential not found | No credential with given ID |
| `PASSKEY_007` | Credential revoked | Credential has been deactivated |
| `PASSKEY_008` | Counter regression | Possible cloned authenticator |
| `PASSKEY_009` | Signature verification failed | Invalid signature |
| `PASSKEY_010` | Max credentials reached | User has maximum allowed credentials |
| `PASSKEY_011` | Attestation verification failed | Invalid attestation |
| `PASSKEY_012` | Rate limit exceeded | Too many requests |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **AAGUID** | Authenticator Attestation GUID - identifies authenticator model |
| **Attestation** | Cryptographic proof that credential was created on legitimate authenticator |
| **Authenticator** | Hardware or software that creates and uses credentials |
| **CBOR** | Concise Binary Object Representation - binary encoding format |
| **COSE** | CBOR Object Signing and Encryption - key format used in WebAuthn |
| **Credential** | Public-private key pair bound to a relying party |
| **Discoverable Credential** | Credential that can be used without providing credential ID (resident key) |
| **FIDO2** | Authentication standards framework (includes WebAuthn and CTAP) |
| **Passkey** | Consumer-friendly term for synced WebAuthn credentials |
| **Relying Party (RP)** | Website/application that uses WebAuthn for authentication |
| **Resident Key** | Same as discoverable credential - stored on authenticator |
| **User Handle** | Opaque identifier for user, revealed during discoverable credential auth |
| **User Verification** | Authenticator confirms user identity (biometric, PIN) |
| **WebAuthn** | W3C Web Authentication API standard |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-17 | AI Assistant | Initial document creation |

---

**Next Steps:**
1. Review and approve this implementation plan
2. Begin Phase 1 (Foundation) tasks
3. Set up py-webauthn in development environment
4. Create feature branch for implementation
