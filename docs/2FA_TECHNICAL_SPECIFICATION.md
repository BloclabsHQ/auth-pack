# Two-Factor Authentication Technical Specification

## Document Information
- **Version**: 1.0.0
- **Status**: Draft
- **Package**: BlockAuth (Open Source)
- **Independence**: Fully decoupled from fabric-auth

## Executive Summary

This technical specification defines the implementation of an optional, modular Two-Factor Authentication (2FA) system for the BlockAuth open-source authentication package. The system provides multiple 2FA methods while maintaining complete independence from proprietary implementations.

## System Architecture

### Core Design Principles

1. **Modularity**: Each 2FA method is a self-contained provider
2. **Configurability**: All features controlled via settings.py
3. **Extensibility**: Easy to add new 2FA methods
4. **Independence**: No external service dependencies (optional)
5. **Security-First**: Encrypted storage, rate limiting, audit logging

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     BlockAuth Core                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                   2FA Module                        │  │
│  ├─────────────────────────────────────────────────────┤  │
│  │                                                     │  │
│  │  ┌──────────────┐  ┌────────────────────────────┐ │  │
│  │  │   Provider   │  │     Provider Manager       │ │  │
│  │  │   Interface  │──│  - Provider Registration   │ │  │
│  │  └──────────────┘  │  - Method Selection        │ │  │
│  │                     │  - Fallback Handling      │ │  │
│  │                     └────────────────────────────┘ │  │
│  │                                                     │  │
│  │  ┌──────────────────────────────────────────────┐ │  │
│  │  │              Provider Implementations        │ │  │
│  │  ├──────────────────────────────────────────────┤ │  │
│  │  │  TOTP  │  SMS  │  Email  │  WebAuthn       │ │  │
│  │  └──────────────────────────────────────────────┘ │  │
│  │                                                     │  │
│  │  ┌──────────────────────────────────────────────┐ │  │
│  │  │           Security Components                │ │  │
│  │  ├──────────────────────────────────────────────┤ │  │
│  │  │  Encryption  │  Rate Limiting  │  Audit Log │ │  │
│  │  └──────────────────────────────────────────────┘ │  │
│  │                                                     │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Data Models

### TwoFactorSettings Model

```python
class TwoFactorSettings:
    """
    Primary model for user's 2FA configuration
    
    Relationships:
    - One-to-one with BlockUser
    - One-to-many with TrustedDevice
    - One-to-many with TwoFactorAuditLog
    """
    
    # Identity
    user: OneToOneField[BlockUser]
    
    # Configuration
    is_enabled: bool
    primary_method: str  # TOTP|SMS|EMAIL|WEBAUTHN
    fallback_method: str  # Optional secondary method
    
    # TOTP Specific
    totp_secret: str  # Encrypted base32 secret
    totp_verified: bool  # Initial setup completion
    totp_algorithm: str  # SHA1|SHA256|SHA512
    
    # SMS/Email Specific
    phone_verified: bool
    email_verified: bool
    preferred_channel: str  # SMS|EMAIL
    
    # WebAuthn Specific (Future)
    webauthn_credentials: JSONField  # Registered credentials
    
    # Backup & Recovery
    backup_codes: list[str]  # Encrypted backup codes
    used_backup_codes: list[str]  # Track used codes
    recovery_email: str  # Alternative recovery email
    recovery_phone: str  # Alternative recovery phone
    
    # Security
    last_used_at: datetime
    last_method_used: str
    failed_attempts: int
    locked_until: datetime
    require_2fa_for_sensitive: bool  # Force 2FA for sensitive ops
    
    # Metadata
    created_at: datetime
    updated_at: datetime
    setup_completed_at: datetime
    last_modified_by: str  # admin|user|system
```

### TrustedDevice Model

```python
class TrustedDevice:
    """
    Devices that can bypass 2FA temporarily
    
    Security: Device trust is time-limited and revocable
    """
    
    # Identity
    id: UUID
    user: ForeignKey[BlockUser]
    
    # Device Identification
    device_id: str  # SHA256(user_agent + ip + salt)
    device_fingerprint: str  # Optional browser fingerprint
    device_name: str  # User-provided name
    device_type: str  # mobile|desktop|tablet|unknown
    
    # Context
    user_agent: str
    ip_address: IPAddressField
    location: JSONField  # Optional geolocation
    platform: str  # ios|android|windows|macos|linux
    browser: str  # chrome|firefox|safari|edge
    
    # Trust Settings
    trusted_at: datetime
    trusted_until: datetime
    trust_level: str  # full|limited|read_only
    max_idle_time: int  # Minutes before re-verification
    
    # Usage Tracking
    last_used_at: datetime
    usage_count: int
    last_ip_address: IPAddressField
    ip_address_history: JSONField  # Track IP changes
    
    # Security
    is_active: bool
    revoked_at: datetime
    revoked_reason: str
    risk_score: float  # 0.0-1.0 based on behavior
```

### TwoFactorAuditLog Model

```python
class TwoFactorAuditLog:
    """
    Comprehensive audit trail for all 2FA events
    
    Compliance: Supports regulatory requirements
    """
    
    # Identity
    id: UUID
    user: ForeignKey[BlockUser]
    
    # Event Details
    event_type: str  # See EventType enum below
    event_subtype: str  # Additional categorization
    method: str  # TOTP|SMS|EMAIL|BACKUP|WEBAUTHN
    success: bool
    
    # Context
    ip_address: IPAddressField
    user_agent: str
    device_id: str  # From TrustedDevice if applicable
    session_id: str
    request_id: str  # For correlation
    
    # Security Details
    risk_score: float  # 0.0-1.0
    risk_factors: JSONField  # List of risk indicators
    is_suspicious: bool
    blocked_by_rules: JSONField  # Which rules triggered
    
    # Additional Data
    metadata: JSONField  # Event-specific data
    error_code: str  # If failed
    error_message: str
    
    # Timestamps
    created_at: datetime
    
    class EventType:
        # Setup Events
        SETUP_INITIATED = 'setup_initiated'
        SETUP_COMPLETED = 'setup_completed'
        SETUP_FAILED = 'setup_failed'
        
        # Verification Events
        VERIFICATION_SUCCESS = 'verification_success'
        VERIFICATION_FAILED = 'verification_failed'
        VERIFICATION_LOCKED = 'verification_locked'
        
        # Management Events
        METHOD_CHANGED = 'method_changed'
        BACKUP_CODES_GENERATED = 'backup_codes_generated'
        BACKUP_CODE_USED = 'backup_code_used'
        SETTINGS_UPDATED = 'settings_updated'
        
        # Device Events
        DEVICE_TRUSTED = 'device_trusted'
        DEVICE_REVOKED = 'device_revoked'
        DEVICE_EXPIRED = 'device_expired'
        
        # Security Events
        SUSPICIOUS_ACTIVITY = 'suspicious_activity'
        ACCOUNT_LOCKED = 'account_locked'
        RECOVERY_INITIATED = 'recovery_initiated'
```

## Provider System

### Base Provider Interface

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple

class TwoFactorProvider(ABC):
    """
    Abstract base class for all 2FA providers
    
    Design: Strategy pattern for provider implementations
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize provider with configuration"""
        self.config = config
        self.validate_config()
    
    @abstractmethod
    def validate_config(self) -> None:
        """Validate provider configuration"""
        pass
    
    @abstractmethod
    def generate_secret(self, user: BlockUser) -> str:
        """
        Generate provider-specific secret
        
        Returns: Secret string (encrypted before storage)
        """
        pass
    
    @abstractmethod
    def generate_challenge(self, user: BlockUser) -> Dict[str, Any]:
        """
        Generate challenge for user
        
        Returns: Challenge data for client
        """
        pass
    
    @abstractmethod
    def verify_response(
        self, 
        user: BlockUser, 
        response: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify user's response to challenge
        
        Returns: (success, error_message)
        """
        pass
    
    @abstractmethod
    def get_setup_instructions(self, user: BlockUser) -> Dict[str, Any]:
        """
        Get setup instructions for client
        
        Returns: Setup data including QR codes, instructions, etc.
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider dependencies are available"""
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get provider metadata
        
        Returns: Name, description, requirements, etc.
        """
        pass
    
    def handle_failure(self, user: BlockUser, reason: str) -> None:
        """Handle verification failure (rate limiting, logging)"""
        settings = user.twofa_settings
        settings.failed_attempts += 1
        
        max_attempts = self.config.get('max_attempts', 3)
        if settings.failed_attempts >= max_attempts:
            lockout_duration = self.config.get('lockout_duration', 300)
            settings.locked_until = timezone.now() + timedelta(seconds=lockout_duration)
        
        settings.save()
        
        # Audit log
        self.audit_log(user, 'verification_failed', {'reason': reason})
    
    def handle_success(self, user: BlockUser) -> None:
        """Handle verification success"""
        settings = user.twofa_settings
        settings.failed_attempts = 0
        settings.locked_until = None
        settings.last_used_at = timezone.now()
        settings.save()
        
        # Audit log
        self.audit_log(user, 'verification_success', {})
    
    def audit_log(
        self, 
        user: BlockUser, 
        event_type: str, 
        metadata: Dict[str, Any]
    ) -> None:
        """Create audit log entry"""
        # Implementation in audit module
        pass
```

### TOTP Provider Implementation

```python
import pyotp
import qrcode
from typing import Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet

class TOTPProvider(TwoFactorProvider):
    """
    Time-based One-Time Password provider
    
    Standards: RFC 6238 compliant
    """
    
    def validate_config(self) -> None:
        """Validate TOTP configuration"""
        required = ['issuer', 'digits', 'interval']
        for field in required:
            if field not in self.config:
                raise ValueError(f"Missing required config: {field}")
        
        if self.config['digits'] not in [6, 8]:
            raise ValueError("Digits must be 6 or 8")
        
        if self.config['interval'] not in [30, 60]:
            raise ValueError("Interval must be 30 or 60 seconds")
    
    def generate_secret(self, user: BlockUser) -> str:
        """Generate TOTP secret"""
        # Generate random base32 secret
        secret = pyotp.random_base32()
        
        # Encrypt for storage
        cipher = Fernet(settings.SECRET_KEY[:32].encode())
        encrypted = cipher.encrypt(secret.encode()).decode()
        
        # Store encrypted
        settings, _ = TwoFactorSettings.objects.get_or_create(user=user)
        settings.totp_secret = encrypted
        settings.totp_verified = False
        settings.save()
        
        return secret  # Return unencrypted for setup
    
    def generate_challenge(self, user: BlockUser) -> Dict[str, Any]:
        """No challenge needed for TOTP"""
        return {
            'type': 'totp',
            'message': 'Enter your 6-digit code'
        }
    
    def verify_response(
        self, 
        user: BlockUser, 
        response: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Verify TOTP code"""
        settings = user.twofa_settings
        
        if not settings or not settings.totp_secret:
            return False, "2FA not configured"
        
        # Check lockout
        if settings.locked_until and settings.locked_until > timezone.now():
            return False, "Account temporarily locked"
        
        # Decrypt secret
        cipher = Fernet(settings.SECRET_KEY[:32].encode())
        secret = cipher.decrypt(settings.totp_secret.encode()).decode()
        
        # Verify code
        totp = pyotp.TOTP(
            secret,
            digits=self.config['digits'],
            interval=self.config['interval']
        )
        
        # Allow time drift
        valid = totp.verify(response, valid_window=1)
        
        if valid:
            self.handle_success(user)
            if not settings.totp_verified:
                settings.totp_verified = True
                settings.save()
            return True, None
        else:
            self.handle_failure(user, "Invalid code")
            return False, "Invalid code"
    
    def get_setup_instructions(self, user: BlockUser) -> Dict[str, Any]:
        """Generate QR code and manual entry data"""
        settings = user.twofa_settings
        
        # Get or generate secret
        if not settings.totp_secret:
            secret = self.generate_secret(user)
        else:
            # Decrypt existing
            cipher = Fernet(settings.SECRET_KEY[:32].encode())
            secret = cipher.decrypt(settings.totp_secret.encode()).decode()
        
        # Generate provisioning URI
        totp = pyotp.TOTP(
            secret,
            digits=self.config['digits'],
            interval=self.config['interval']
        )
        
        provisioning_uri = totp.provisioning_uri(
            name=user.email or str(user.id),
            issuer_name=self.config['issuer']
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
            'method': 'totp',
            'qr_code': f'data:image/png;base64,{qr_code_base64}',
            'provisioning_uri': provisioning_uri,
            'manual_entry': {
                'secret': secret,
                'issuer': self.config['issuer'],
                'account': user.email or str(user.id),
                'algorithm': self.config.get('algorithm', 'SHA1'),
                'digits': self.config['digits'],
                'period': self.config['interval']
            },
            'instructions': [
                "Install an authenticator app (Google Authenticator, Authy, etc.)",
                "Scan the QR code or enter the secret manually",
                "Enter the 6-digit code to complete setup"
            ]
        }
    
    def is_available(self) -> bool:
        """Check if TOTP dependencies are available"""
        try:
            import pyotp
            import qrcode
            return True
        except ImportError:
            return False
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get TOTP provider metadata"""
        return {
            'name': 'Authenticator App',
            'description': 'Use an authenticator app for secure 2FA',
            'icon': 'mobile-alt',
            'requirements': ['Smartphone with authenticator app'],
            'security_level': 'high',
            'recovery_options': ['backup_codes'],
            'supports_backup': True
        }
```

## API Specifications

### RESTful Endpoints

```yaml
openapi: 3.0.0
info:
  title: BlockAuth 2FA API
  version: 1.0.0
  description: Two-Factor Authentication endpoints

paths:
  /auth/2fa/status:
    get:
      summary: Get 2FA status for authenticated user
      security:
        - bearerAuth: []
      responses:
        200:
          description: 2FA status
          content:
            application/json:
              schema:
                type: object
                properties:
                  enabled: 
                    type: boolean
                  primary_method: 
                    type: string
                    enum: [TOTP, SMS, EMAIL, WEBAUTHN]
                  fallback_method: 
                    type: string
                  backup_codes_remaining: 
                    type: integer
                  trusted_devices_count: 
                    type: integer
                  last_verified_at: 
                    type: string
                    format: date-time
                  available_methods:
                    type: array
                    items:
                      type: object
                      properties:
                        method: 
                          type: string
                        name: 
                          type: string
                        available: 
                          type: boolean
  
  /auth/2fa/methods:
    get:
      summary: Get available 2FA methods
      responses:
        200:
          description: Available methods
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    method: 
                      type: string
                    name: 
                      type: string
                    description: 
                      type: string
                    security_level: 
                      type: string
                      enum: [low, medium, high, very_high]
                    requirements:
                      type: array
                      items:
                        type: string
  
  /auth/2fa/setup:
    post:
      summary: Initialize 2FA setup
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [method]
              properties:
                method:
                  type: string
                  enum: [TOTP, SMS, EMAIL]
                phone_number:
                  type: string
                  description: Required for SMS method
      responses:
        200:
          description: Setup instructions
          content:
            application/json:
              schema:
                type: object
                properties:
                  session_id:
                    type: string
                    description: Setup session identifier
                  method:
                    type: string
                  setup_data:
                    type: object
                    description: Method-specific setup data
                  expires_at:
                    type: string
                    format: date-time
  
  /auth/2fa/verify-setup:
    post:
      summary: Complete 2FA setup verification
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [session_id, code]
              properties:
                session_id:
                  type: string
                code:
                  type: string
                set_as_primary:
                  type: boolean
                  default: true
      responses:
        200:
          description: Setup completed
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                  backup_codes:
                    type: array
                    items:
                      type: string
                  recovery_instructions:
                    type: string
  
  /auth/2fa/verify:
    post:
      summary: Verify 2FA during login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [session_token, code]
              properties:
                session_token:
                  type: string
                  description: Temporary token from login
                code:
                  type: string
                method:
                  type: string
                  description: Override method (backup codes)
                trust_device:
                  type: boolean
                  default: false
                device_name:
                  type: string
      responses:
        200:
          description: Verification successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  tokens:
                    type: object
                    properties:
                      access:
                        type: string
                      refresh:
                        type: string
                  device_token:
                    type: string
                    description: If device was trusted
  
  /auth/2fa/disable:
    post:
      summary: Disable 2FA
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [code]
              properties:
                code:
                  type: string
                  description: Current 2FA code or backup code
                password:
                  type: string
                  description: Optional additional verification
      responses:
        200:
          description: 2FA disabled
  
  /auth/2fa/backup-codes:
    get:
      summary: Get backup codes status
      security:
        - bearerAuth: []
      responses:
        200:
          description: Backup codes status
          content:
            application/json:
              schema:
                type: object
                properties:
                  total:
                    type: integer
                  remaining:
                    type: integer
                  last_generated_at:
                    type: string
                    format: date-time
    
    post:
      summary: Generate new backup codes
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [code]
              properties:
                code:
                  type: string
                  description: Current 2FA code
                count:
                  type: integer
                  default: 10
                  minimum: 5
                  maximum: 20
      responses:
        200:
          description: New backup codes
          content:
            application/json:
              schema:
                type: object
                properties:
                  codes:
                    type: array
                    items:
                      type: string
                  generated_at:
                    type: string
                    format: date-time
  
  /auth/2fa/trusted-devices:
    get:
      summary: List trusted devices
      security:
        - bearerAuth: []
      responses:
        200:
          description: Trusted devices list
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: string
                    device_name:
                      type: string
                    device_type:
                      type: string
                    platform:
                      type: string
                    browser:
                      type: string
                    last_used_at:
                      type: string
                      format: date-time
                    trusted_until:
                      type: string
                      format: date-time
                    current_device:
                      type: boolean
    
    delete:
      summary: Revoke trusted device
      security:
        - bearerAuth: []
      parameters:
        - name: device_id
          in: query
          required: true
          schema:
            type: string
      responses:
        204:
          description: Device revoked
  
  /auth/2fa/recovery:
    post:
      summary: Initiate account recovery
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email:
                  type: string
                  format: email
                recovery_method:
                  type: string
                  enum: [email, sms, support]
      responses:
        200:
          description: Recovery initiated
          content:
            application/json:
              schema:
                type: object
                properties:
                  recovery_token:
                    type: string
                  method:
                    type: string
                  instructions:
                    type: string
```

## Security Implementation

### Encryption Strategy

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64

class SecureStorage:
    """
    Secure storage for 2FA secrets and backup codes
    
    Security: AES-256 encryption with key derivation
    """
    
    @staticmethod
    def derive_key(master_key: str, salt: bytes) -> bytes:
        """Derive encryption key from master key"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(master_key.encode())
        )
        return key
    
    @staticmethod
    def encrypt_secret(secret: str, user_id: str) -> str:
        """Encrypt secret for storage"""
        # User-specific salt
        salt = hashlib.sha256(f"{user_id}:2fa".encode()).digest()[:16]
        
        # Derive key
        key = SecureStorage.derive_key(
            settings.SECRET_KEY,
            salt
        )
        
        # Encrypt
        cipher = Fernet(key)
        encrypted = cipher.encrypt(secret.encode())
        
        # Return base64 encoded
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_secret(encrypted: str, user_id: str) -> str:
        """Decrypt secret from storage"""
        # User-specific salt
        salt = hashlib.sha256(f"{user_id}:2fa".encode()).digest()[:16]
        
        # Derive key
        key = SecureStorage.derive_key(
            settings.SECRET_KEY,
            salt
        )
        
        # Decrypt
        cipher = Fernet(key)
        decrypted = cipher.decrypt(
            base64.b64decode(encrypted)
        )
        
        return decrypted.decode()
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """Hash backup code for storage"""
        return hashlib.sha256(
            f"{code}:{settings.SECRET_KEY[:16]}".encode()
        ).hexdigest()
    
    @staticmethod
    def verify_backup_code(code: str, hashed: str) -> bool:
        """Verify backup code against hash"""
        return SecureStorage.hash_backup_code(code) == hashed
```

### Rate Limiting Implementation

```python
from django.core.cache import cache
from functools import wraps
import hashlib

class RateLimiter:
    """
    Rate limiting for 2FA operations
    
    Protection: Against brute force and DoS attacks
    """
    
    @staticmethod
    def get_identifier(request, user=None):
        """Get unique identifier for rate limiting"""
        if user:
            return f"user:{user.id}"
        
        # Use IP + User-Agent for anonymous
        ip = request.META.get('REMOTE_ADDR')
        ua = request.META.get('HTTP_USER_AGENT', '')
        return hashlib.sha256(f"{ip}:{ua}".encode()).hexdigest()
    
    @staticmethod
    def check_rate_limit(
        identifier: str,
        action: str,
        max_attempts: int,
        window: int
    ) -> tuple[bool, int]:
        """
        Check if rate limit exceeded
        
        Returns: (allowed, remaining_attempts)
        """
        cache_key = f"ratelimit:{action}:{identifier}"
        
        # Get current count
        current = cache.get(cache_key, 0)
        
        if current >= max_attempts:
            ttl = cache.ttl(cache_key)
            return False, 0, ttl
        
        # Increment
        cache.set(cache_key, current + 1, window)
        
        return True, max_attempts - current - 1, 0
    
    @staticmethod
    def rate_limit_decorator(
        action: str,
        max_attempts: int = 5,
        window: int = 300
    ):
        """Decorator for rate-limited views"""
        def decorator(func):
            @wraps(func)
            def wrapper(request, *args, **kwargs):
                identifier = RateLimiter.get_identifier(
                    request,
                    getattr(request, 'user', None)
                )
                
                allowed, remaining, ttl = RateLimiter.check_rate_limit(
                    identifier,
                    action,
                    max_attempts,
                    window
                )
                
                if not allowed:
                    return Response(
                        {
                            'error': 'Rate limit exceeded',
                            'retry_after': ttl
                        },
                        status=429,
                        headers={'Retry-After': str(ttl)}
                    )
                
                response = func(request, *args, **kwargs)
                
                # Add rate limit headers
                response['X-RateLimit-Limit'] = str(max_attempts)
                response['X-RateLimit-Remaining'] = str(remaining)
                response['X-RateLimit-Reset'] = str(window)
                
                return response
            return wrapper
        return decorator

# Usage
@rate_limit_decorator('2fa_verify', max_attempts=3, window=300)
def verify_2fa(request):
    # Verification logic
    pass
```

### Risk Assessment

```python
from typing import Dict, List, Tuple
import geoip2.database

class RiskAssessment:
    """
    Risk assessment for 2FA operations
    
    Purpose: Identify suspicious activities
    """
    
    def __init__(self):
        self.geoip_reader = geoip2.database.Reader(
            'path/to/GeoLite2-City.mmdb'
        )
    
    def assess_login_risk(
        self, 
        user: BlockUser, 
        request
    ) -> Tuple[float, List[str]]:
        """
        Assess risk level for login attempt
        
        Returns: (risk_score, risk_factors)
        """
        risk_score = 0.0
        risk_factors = []
        
        # Check location change
        location_risk = self._check_location_anomaly(user, request)
        if location_risk > 0:
            risk_score += location_risk
            risk_factors.append('location_anomaly')
        
        # Check device change
        if self._is_new_device(user, request):
            risk_score += 0.3
            risk_factors.append('new_device')
        
        # Check time anomaly
        if self._check_time_anomaly(user):
            risk_score += 0.2
            risk_factors.append('unusual_time')
        
        # Check velocity (impossible travel)
        velocity_risk = self._check_velocity(user, request)
        if velocity_risk > 0:
            risk_score += velocity_risk
            risk_factors.append('impossible_travel')
        
        # Check failed attempts
        if user.twofa_settings.failed_attempts > 0:
            risk_score += 0.1 * user.twofa_settings.failed_attempts
            risk_factors.append('recent_failures')
        
        # Normalize score
        risk_score = min(1.0, risk_score)
        
        return risk_score, risk_factors
    
    def _check_location_anomaly(
        self, 
        user: BlockUser, 
        request
    ) -> float:
        """Check for location anomalies"""
        try:
            current_ip = request.META.get('REMOTE_ADDR')
            current_location = self.geoip_reader.city(current_ip)
            
            # Get last known location
            last_login = TwoFactorAuditLog.objects.filter(
                user=user,
                event_type='verification_success'
            ).order_by('-created_at').first()
            
            if last_login and last_login.ip_address:
                last_location = self.geoip_reader.city(
                    last_login.ip_address
                )
                
                # Calculate distance
                distance = self._calculate_distance(
                    (current_location.location.latitude,
                     current_location.location.longitude),
                    (last_location.location.latitude,
                     last_location.location.longitude)
                )
                
                # Different country = high risk
                if current_location.country.iso_code != \
                   last_location.country.iso_code:
                    return 0.5
                
                # Large distance = medium risk
                if distance > 1000:  # km
                    return 0.3
                
        except Exception:
            pass
        
        return 0.0
    
    def _check_velocity(
        self, 
        user: BlockUser, 
        request
    ) -> float:
        """Check for impossible travel"""
        # Implementation details...
        return 0.0
    
    def _is_new_device(
        self, 
        user: BlockUser, 
        request
    ) -> bool:
        """Check if device is new"""
        device_id = self._generate_device_id(request)
        return not TrustedDevice.objects.filter(
            user=user,
            device_id=device_id
        ).exists()
    
    def _check_time_anomaly(self, user: BlockUser) -> bool:
        """Check for unusual login times"""
        # Implementation details...
        return False
    
    def should_require_additional_verification(
        self,
        risk_score: float,
        risk_factors: List[str]
    ) -> bool:
        """Determine if additional verification needed"""
        # High risk score
        if risk_score > 0.7:
            return True
        
        # Critical risk factors
        critical_factors = [
            'impossible_travel',
            'location_anomaly'
        ]
        
        if any(factor in critical_factors for factor in risk_factors):
            return True
        
        return False
```

## Testing Specifications

### Unit Test Suite

```python
# tests/test_2fa_core.py

import pytest
from django.test import TestCase
from unittest.mock import Mock, patch
from blockauth.twofa.providers import TOTPProvider
from blockauth.twofa.models import TwoFactorSettings

class TestTOTPProvider(TestCase):
    """Test TOTP provider implementation"""
    
    def setUp(self):
        self.user = create_test_user()
        self.provider = TOTPProvider({
            'issuer': 'TestApp',
            'digits': 6,
            'interval': 30
        })
    
    def test_secret_generation(self):
        """Test secret generation and encryption"""
        secret = self.provider.generate_secret(self.user)
        
        # Verify format
        assert len(secret) == 32
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' 
                  for c in secret)
        
        # Verify storage
        settings = TwoFactorSettings.objects.get(user=self.user)
        assert settings.totp_secret != secret  # Should be encrypted
        
        # Verify decryption
        decrypted = SecureStorage.decrypt_secret(
            settings.totp_secret,
            str(self.user.id)
        )
        assert decrypted == secret
    
    def test_code_verification(self):
        """Test TOTP code verification"""
        secret = self.provider.generate_secret(self.user)
        
        # Generate valid code
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Test valid code
        success, error = self.provider.verify_response(
            self.user,
            valid_code
        )
        assert success is True
        assert error is None
        
        # Test invalid code
        success, error = self.provider.verify_response(
            self.user,
            '000000'
        )
        assert success is False
        assert error == 'Invalid code'
    
    def test_time_window_tolerance(self):
        """Test TOTP time window tolerance"""
        secret = self.provider.generate_secret(self.user)
        
        import pyotp
        import time
        totp = pyotp.TOTP(secret, interval=30)
        
        # Get code for previous interval
        with patch('time.time', return_value=time.time() - 30):
            old_code = totp.now()
        
        # Should still be valid (1 interval tolerance)
        success, _ = self.provider.verify_response(
            self.user,
            old_code
        )
        assert success is True
    
    @patch('blockauth.twofa.providers.totp.qrcode')
    def test_qr_code_generation(self, mock_qrcode):
        """Test QR code generation"""
        setup_data = self.provider.get_setup_instructions(self.user)
        
        assert 'qr_code' in setup_data
        assert 'provisioning_uri' in setup_data
        assert 'manual_entry' in setup_data
        
        # Verify provisioning URI format
        uri = setup_data['provisioning_uri']
        assert uri.startswith('otpauth://totp/')
        assert 'TestApp' in uri
        assert self.user.email in uri

class TestBackupCodes(TestCase):
    """Test backup code functionality"""
    
    def setUp(self):
        self.user = create_test_user()
        self.settings = TwoFactorSettings.objects.create(
            user=self.user,
            is_enabled=True
        )
    
    def test_backup_code_generation(self):
        """Test generating backup codes"""
        codes = self.settings.generate_backup_codes(10)
        
        assert len(codes) == 10
        assert len(set(codes)) == 10  # All unique
        
        # Verify format
        for code in codes:
            assert len(code) == 16
            assert all(c in '0123456789ABCDEF' for c in code)
    
    def test_backup_code_usage(self):
        """Test using backup codes"""
        codes = self.settings.generate_backup_codes(5)
        
        # Use first code
        assert self.settings.use_backup_code(codes[0]) is True
        assert len(self.settings.used_backup_codes) == 1
        
        # Can't reuse
        assert self.settings.use_backup_code(codes[0]) is False
        
        # Other codes still work
        assert self.settings.use_backup_code(codes[1]) is True
        assert len(self.settings.used_backup_codes) == 2
    
    def test_backup_code_regeneration(self):
        """Test regenerating backup codes"""
        old_codes = self.settings.generate_backup_codes(10)
        
        # Use some codes
        self.settings.use_backup_code(old_codes[0])
        self.settings.use_backup_code(old_codes[1])
        
        # Regenerate
        new_codes = self.settings.generate_backup_codes(10)
        
        # Old codes should not work
        assert self.settings.use_backup_code(old_codes[2]) is False
        
        # New codes should work
        assert self.settings.use_backup_code(new_codes[0]) is True
        
        # Used codes list should be reset
        assert len(self.settings.used_backup_codes) == 1

class TestRateLimiting(TestCase):
    """Test rate limiting functionality"""
    
    def test_rate_limit_enforcement(self):
        """Test rate limit is enforced"""
        identifier = 'test_user'
        action = 'test_action'
        
        # First 3 attempts should succeed
        for i in range(3):
            allowed, remaining, ttl = RateLimiter.check_rate_limit(
                identifier, action, 3, 300
            )
            assert allowed is True
            assert remaining == 2 - i
        
        # 4th attempt should fail
        allowed, remaining, ttl = RateLimiter.check_rate_limit(
            identifier, action, 3, 300
        )
        assert allowed is False
        assert remaining == 0
        assert ttl > 0
    
    def test_rate_limit_window_expiry(self):
        """Test rate limit window expiry"""
        identifier = 'test_user'
        action = 'test_action'
        
        # Use up attempts
        for _ in range(3):
            RateLimiter.check_rate_limit(
                identifier, action, 3, 1  # 1 second window
            )
        
        # Wait for window to expire
        import time
        time.sleep(1.1)
        
        # Should be allowed again
        allowed, _, _ = RateLimiter.check_rate_limit(
            identifier, action, 3, 1
        )
        assert allowed is True

class TestTrustedDevices(TestCase):
    """Test trusted device functionality"""
    
    def setUp(self):
        self.user = create_test_user()
        self.request = Mock()
        self.request.META = {
            'HTTP_USER_AGENT': 'TestBrowser/1.0',
            'REMOTE_ADDR': '192.168.1.1'
        }
    
    def test_device_trust(self):
        """Test trusting a device"""
        device_id = generate_device_id(self.request)
        
        device = TrustedDevice.objects.create(
            user=self.user,
            device_id=device_id,
            device_name='Test Device',
            device_type='desktop',
            user_agent=self.request.META['HTTP_USER_AGENT'],
            ip_address=self.request.META['REMOTE_ADDR'],
            trusted_until=timezone.now() + timedelta(days=30)
        )
        
        # Device should be trusted
        assert is_device_trusted(self.user, device_id) is True
        
        # Expire trust
        device.trusted_until = timezone.now() - timedelta(days=1)
        device.save()
        
        # Device should not be trusted
        assert is_device_trusted(self.user, device_id) is False
    
    def test_device_revocation(self):
        """Test revoking device trust"""
        device_id = generate_device_id(self.request)
        
        device = TrustedDevice.objects.create(
            user=self.user,
            device_id=device_id,
            device_name='Test Device',
            device_type='desktop',
            user_agent=self.request.META['HTTP_USER_AGENT'],
            ip_address=self.request.META['REMOTE_ADDR'],
            trusted_until=timezone.now() + timedelta(days=30)
        )
        
        # Revoke device
        device.is_active = False
        device.revoked_at = timezone.now()
        device.revoked_reason = 'User requested'
        device.save()
        
        # Device should not be trusted
        assert is_device_trusted(self.user, device_id) is False
```

### Integration Test Suite

```python
# tests/test_2fa_integration.py

from rest_framework.test import APITestCase
from django.urls import reverse

class Test2FACompleteFlow(APITestCase):
    """Test complete 2FA flow"""
    
    def test_setup_and_login_flow(self):
        """Test setting up 2FA and logging in"""
        
        # 1. Register user
        response = self.client.post(
            reverse('auth:signup'),
            {
                'email': 'test@example.com',
                'password': 'TestPass123!'
            }
        )
        assert response.status_code == 201
        tokens = response.json()['tokens']
        
        # 2. Setup 2FA
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}'
        )
        
        response = self.client.post(
            reverse('auth:2fa-setup'),
            {'method': 'TOTP'}
        )
        assert response.status_code == 200
        setup_data = response.json()
        
        # 3. Verify setup with valid code
        secret = setup_data['setup_data']['manual_entry']['secret']
        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        response = self.client.post(
            reverse('auth:2fa-verify-setup'),
            {
                'session_id': setup_data['session_id'],
                'code': code
            }
        )
        assert response.status_code == 200
        backup_codes = response.json()['backup_codes']
        assert len(backup_codes) == 10
        
        # 4. Logout
        self.client.credentials()
        
        # 5. Login with 2FA
        response = self.client.post(
            reverse('auth:login'),
            {
                'email': 'test@example.com',
                'password': 'TestPass123!'
            }
        )
        assert response.status_code == 200
        assert 'require_2fa' in response.json()
        session_token = response.json()['session_token']
        
        # 6. Verify 2FA
        code = totp.now()
        response = self.client.post(
            reverse('auth:2fa-verify'),
            {
                'session_token': session_token,
                'code': code,
                'trust_device': True,
                'device_name': 'Test Browser'
            }
        )
        assert response.status_code == 200
        assert 'tokens' in response.json()
        assert 'device_token' in response.json()
    
    def test_backup_code_flow(self):
        """Test using backup codes"""
        # Setup user with 2FA
        user, backup_codes = self.setup_user_with_2fa()
        
        # Login with backup code
        response = self.client.post(
            reverse('auth:login'),
            {
                'email': user.email,
                'password': 'TestPass123!'
            }
        )
        session_token = response.json()['session_token']
        
        # Use backup code
        response = self.client.post(
            reverse('auth:2fa-verify'),
            {
                'session_token': session_token,
                'code': backup_codes[0],
                'method': 'backup'
            }
        )
        assert response.status_code == 200
        
        # Same backup code should not work again
        response = self.client.post(
            reverse('auth:login'),
            {
                'email': user.email,
                'password': 'TestPass123!'
            }
        )
        session_token = response.json()['session_token']
        
        response = self.client.post(
            reverse('auth:2fa-verify'),
            {
                'session_token': session_token,
                'code': backup_codes[0],
                'method': 'backup'
            }
        )
        assert response.status_code == 400
```

## Performance Considerations

### Caching Strategy

```python
from django.core.cache import cache
from typing import Optional

class TwoFactorCache:
    """
    Caching layer for 2FA operations
    
    Purpose: Reduce database queries and improve performance
    """
    
    @staticmethod
    def get_user_settings(user_id: str) -> Optional[Dict]:
        """Get cached user 2FA settings"""
        cache_key = f"2fa:settings:{user_id}"
        return cache.get(cache_key)
    
    @staticmethod
    def set_user_settings(
        user_id: str, 
        settings: Dict, 
        ttl: int = 300
    ):
        """Cache user 2FA settings"""
        cache_key = f"2fa:settings:{user_id}"
        cache.set(cache_key, settings, ttl)
    
    @staticmethod
    def invalidate_user_settings(user_id: str):
        """Invalidate cached settings"""
        cache_key = f"2fa:settings:{user_id}"
        cache.delete(cache_key)
    
    @staticmethod
    def get_setup_session(session_id: str) -> Optional[Dict]:
        """Get cached setup session"""
        cache_key = f"2fa:setup:{session_id}"
        return cache.get(cache_key)
    
    @staticmethod
    def set_setup_session(
        session_id: str,
        data: Dict,
        ttl: int = 600  # 10 minutes
    ):
        """Cache setup session"""
        cache_key = f"2fa:setup:{session_id}"
        cache.set(cache_key, data, ttl)
```

### Database Optimization

```sql
-- Indexes for optimal query performance

-- TwoFactorSettings indexes
CREATE INDEX idx_twofa_user_enabled 
ON blockauth_twofa_settings(user_id, is_enabled);

CREATE INDEX idx_twofa_locked 
ON blockauth_twofa_settings(locked_until) 
WHERE locked_until IS NOT NULL;

-- TrustedDevice indexes
CREATE INDEX idx_trusted_user_device 
ON blockauth_trusted_devices(user_id, device_id);

CREATE INDEX idx_trusted_expiry 
ON blockauth_trusted_devices(trusted_until);

CREATE INDEX idx_trusted_active 
ON blockauth_trusted_devices(is_active, trusted_until);

-- Audit log indexes
CREATE INDEX idx_audit_user_time 
ON blockauth_twofa_audit(user_id, created_at DESC);

CREATE INDEX idx_audit_event_time 
ON blockauth_twofa_audit(event_type, created_at DESC);

CREATE INDEX idx_audit_suspicious 
ON blockauth_twofa_audit(is_suspicious, created_at DESC) 
WHERE is_suspicious = true;
```

## Monitoring and Metrics

### Key Performance Indicators

```python
from django.db.models import Count, Avg, Q
from datetime import timedelta

class TwoFactorMetrics:
    """
    Metrics and monitoring for 2FA system
    
    Purpose: Track adoption, performance, and security
    """
    
    @staticmethod
    def get_adoption_metrics() -> Dict:
        """Get 2FA adoption metrics"""
        total_users = BlockUser.objects.count()
        enabled_users = TwoFactorSettings.objects.filter(
            is_enabled=True
        ).count()
        
        by_method = TwoFactorSettings.objects.filter(
            is_enabled=True
        ).values('primary_method').annotate(
            count=Count('id')
        )
        
        return {
            'total_users': total_users,
            'enabled_users': enabled_users,
            'adoption_rate': (enabled_users / total_users * 100) 
                           if total_users > 0 else 0,
            'by_method': dict(
                (item['primary_method'], item['count']) 
                for item in by_method
            )
        }
    
    @staticmethod
    def get_security_metrics(days: int = 7) -> Dict:
        """Get security metrics"""
        since = timezone.now() - timedelta(days=days)
        
        audit_logs = TwoFactorAuditLog.objects.filter(
            created_at__gte=since
        )
        
        return {
            'total_verifications': audit_logs.filter(
                event_type='verification_success'
            ).count(),
            'failed_verifications': audit_logs.filter(
                event_type='verification_failed'
            ).count(),
            'suspicious_activities': audit_logs.filter(
                is_suspicious=True
            ).count(),
            'backup_codes_used': audit_logs.filter(
                event_type='backup_code_used'
            ).count(),
            'average_risk_score': audit_logs.aggregate(
                Avg('risk_score')
            )['risk_score__avg'] or 0
        }
    
    @staticmethod
    def get_performance_metrics() -> Dict:
        """Get performance metrics"""
        # Implementation for response times, cache hit rates, etc.
        return {
            'average_verification_time': 0.15,  # seconds
            'cache_hit_rate': 0.85,  # 85%
            'database_queries_per_verification': 2.3
        }
```

## Deployment Checklist

```markdown
## Pre-Deployment

- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] Security audit completed
- [ ] Performance testing completed
- [ ] Documentation updated
- [ ] Migration scripts tested

## Configuration

- [ ] SECRET_KEY configured securely
- [ ] 2FA settings configured in settings.py
- [ ] Redis cache configured
- [ ] Rate limiting configured
- [ ] Audit logging configured
- [ ] Backup strategy in place

## Security

- [ ] HTTPS enforced for all 2FA endpoints
- [ ] CSRF protection enabled
- [ ] Session security configured
- [ ] Encryption keys rotated
- [ ] Rate limits appropriate for production
- [ ] Monitoring alerts configured

## Database

- [ ] Migrations run successfully
- [ ] Indexes created
- [ ] Backup procedures tested
- [ ] Recovery procedures documented

## Monitoring

- [ ] Metrics collection enabled
- [ ] Alert thresholds configured
- [ ] Dashboard created
- [ ] Log aggregation configured
- [ ] Error tracking enabled

## User Communication

- [ ] User documentation published
- [ ] Support team trained
- [ ] FAQ updated
- [ ] Recovery procedures documented
- [ ] Communication plan for rollout
```

## Support and Maintenance

### Common Issues and Solutions

```python
# Common troubleshooting scenarios

class TwoFactorTroubleshooting:
    """Common 2FA issues and solutions"""
    
    @staticmethod
    def reset_failed_attempts(user: BlockUser):
        """Reset failed attempts for locked account"""
        settings = user.twofa_settings
        settings.failed_attempts = 0
        settings.locked_until = None
        settings.save()
        
        # Audit log
        TwoFactorAuditLog.objects.create(
            user=user,
            event_type='admin_unlock',
            metadata={'reason': 'Manual unlock by admin'}
        )
    
    @staticmethod
    def force_disable_2fa(user: BlockUser, admin_user: BlockUser):
        """Force disable 2FA (admin action)"""
        settings = user.twofa_settings
        settings.is_enabled = False
        settings.save()
        
        # Clear all trusted devices
        user.trusted_devices.all().delete()
        
        # Audit log
        TwoFactorAuditLog.objects.create(
            user=user,
            event_type='admin_disable',
            metadata={
                'admin_id': str(admin_user.id),
                'reason': 'Administrative action'
            }
        )
    
    @staticmethod
    def regenerate_recovery_codes(
        user: BlockUser, 
        admin_user: BlockUser
    ):
        """Admin regenerate recovery codes"""
        settings = user.twofa_settings
        codes = settings.generate_backup_codes()
        
        # Audit log
        TwoFactorAuditLog.objects.create(
            user=user,
            event_type='admin_recovery_codes',
            metadata={
                'admin_id': str(admin_user.id),
                'codes_generated': len(codes)
            }
        )
        
        return codes
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-20 | Initial specification |
| 1.1.0 | TBD | WebAuthn support |
| 1.2.0 | TBD | Biometric support |

## References

- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)