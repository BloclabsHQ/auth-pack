# 🔐 MANDATORY SECURITY STANDARDS - FabricBloc Authentication

## ⚠️ CRITICAL: These Standards Are NON-NEGOTIABLE

**EVERY line of code MUST comply with these security standards. NO EXCEPTIONS.**

---

## 🚨 IMMEDIATE SECURITY RULES (ALWAYS APPLY)

### NEVER DO THIS (Instant Security Failures)
```python
# ❌ NEVER log sensitive data
logger.info(f"Password: {password}")  # NEVER
logger.debug(f"Token: {token}")  # NEVER
print(f"Private key: {private_key}")  # NEVER

# ❌ NEVER use weak crypto
random.random()  # NEVER for tokens
uuid.uuid4()  # NEVER for security tokens
md5()  # NEVER for hashing
sha1()  # NEVER for security

# ❌ NEVER store secrets in code
SECRET_KEY = "hardcoded-secret"  # NEVER
API_KEY = "sk-1234567890"  # NEVER

# ❌ NEVER trust user input
query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL INJECTION
html = f"<div>{user_input}</div>"  # XSS VULNERABILITY
```

### ALWAYS DO THIS (Security Requirements)
```python
# ✅ ALWAYS use secure random
import secrets
token = secrets.token_urlsafe(32)  # 256 bits

# ✅ ALWAYS hash passwords properly
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(14))

# ✅ ALWAYS validate input
from django.core.validators import validate_email
validate_email(email)

# ✅ ALWAYS use parameterized queries
User.objects.filter(id=user_id)  # ORM
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
```

---

## 1️⃣ PASSWORD SECURITY STANDARDS

### Hashing Requirements
```python
# MANDATORY: bcrypt with 14+ rounds
BCRYPT_ROUNDS = 14  # MINIMUM - Never less

# Implementation
import bcrypt

def hash_password(password: str) -> str:
    """SECURE password hashing."""
    salt = bcrypt.gensalt(rounds=14)  # NEVER less than 14
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, hashed: str) -> bool:
    """SECURE password verification with timing attack protection."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
```

### Password Validation Rules
```python
# MANDATORY validators
PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},  # MINIMUM 12 characters
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    {'NAME': 'blockauth.utils.validators.BlockAuthPasswordValidator'},
]

# MANDATORY complexity requirements
PASSWORD_RULES = {
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_special': True,
    'max_consecutive': 3,
    'history_count': 5,  # Prevent reuse of last 5 passwords
}
```

---

## 2️⃣ JWT TOKEN SECURITY STANDARDS

### Token Configuration
```python
# MANDATORY JWT settings
JWT_SETTINGS = {
    'SECRET_KEY': secrets.token_hex(32),  # MINIMUM 256 bits
    'ALGORITHM': 'HS256',  # ONLY HS256 allowed
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),  # MAXIMUM 15 minutes
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),  # With rotation
    'ROTATE_REFRESH_TOKENS': True,  # MANDATORY
    'BLACKLIST_AFTER_ROTATION': True,  # MANDATORY
}

# SECURE token generation
def generate_secure_token() -> str:
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(32)  # 256 bits MINIMUM
```

### JWT Validation Rules
```python
def validate_jwt_token(token: str) -> dict:
    """SECURE JWT validation."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=['HS256'],  # ONLY HS256
            options={
                'verify_signature': True,  # MANDATORY
                'verify_exp': True,  # MANDATORY
                'verify_iat': True,  # MANDATORY
                'require': ['exp', 'iat', 'user_id', 'type']  # REQUIRED claims
            }
        )

        # Additional validation
        if payload.get('type') not in ['access', 'refresh']:
            raise jwt.InvalidTokenError("Invalid token type")

        return payload

    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Token expired")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid token")
```

---

## 3️⃣ WEB3 SECURITY STANDARDS

### Private Key Management
```python
# MANDATORY: Never store plain private keys
from cryptography.fernet import Fernet

class SecureKeyManager:
    """MANDATORY encryption for private keys."""

    def encrypt_private_key(self, private_key: str, password: str) -> str:
        """Encrypt private key with user password + platform key."""
        # Derive encryption key
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.get_salt(),
            iterations=100_000,  # MINIMUM iterations
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Encrypt with Fernet (AES-128)
        f = Fernet(key)
        encrypted = f.encrypt(private_key.encode())

        # Double encryption with platform key
        platform_f = Fernet(self.get_platform_key())
        double_encrypted = platform_f.encrypt(encrypted)

        return double_encrypted.decode()
```

### Signature Validation
```python
def validate_web3_signature(address: str, message: str, signature: str) -> bool:
    """SECURE Web3 signature validation."""

    # Format validation
    if not re.match(r'^0x[a-fA-F0-9]{130}$', signature):
        return False

    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        return False

    # Prevent zero address
    if address == '0x0000000000000000000000000000000000000000':
        return False

    # Message size limit (prevent DoS)
    if len(message) > 10_000:
        return False

    # Verify signature (with malleability check)
    try:
        # Extract r, s, v
        r = int(signature[2:66], 16)
        s = int(signature[66:130], 16)
        v = int(signature[130:132], 16)

        # Check s value (prevent malleability)
        if s > SECP256K1_N // 2:
            return False

        # Recover and verify address
        recovered = recover_address(message, signature)
        return recovered.lower() == address.lower()

    except Exception:
        return False
```

---

## 4️⃣ KEY DERIVATION (KDF) STANDARDS

### KDF Configuration
```python
# MANDATORY KDF settings
KDF_SETTINGS = {
    'ALGORITHM': 'pbkdf2',  # or 'argon2id'
    'ITERATIONS': 600_000,  # NIST 2024 MINIMUM
    'KEY_LENGTH': 32,  # 256 bits
    'SALT_LENGTH': 32,  # MINIMUM
    'MASTER_KEY_LENGTH': 64,  # 512 bits for master key
}

def derive_secure_key(email: str, password: str) -> bytes:
    """SECURE key derivation for Web2→Web3."""

    # Generate or retrieve salt
    salt = get_user_salt(email)  # UNIQUE per user

    # PBKDF2 with high iterations
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # NIST 2024 minimum
    )

    # Combine inputs securely
    input_data = f"{email}:{password}".encode('utf-8')

    # Derive key
    derived_key = kdf.derive(input_data)

    # Additional platform salt mixing
    platform_salt = settings.PLATFORM_MASTER_SALT.encode()
    final_key = hashlib.pbkdf2_hmac(
        'sha256',
        derived_key,
        platform_salt,
        100_000
    )

    return final_key
```

---

## 5️⃣ RATE LIMITING STANDARDS

### MANDATORY Rate Limits
```python
RATE_LIMITS = {
    # Authentication endpoints
    'login': '5/minute',  # MAXIMUM
    'register': '3/hour',
    'password_reset': '3/hour',
    'token_refresh': '10/minute',

    # Sensitive operations
    'wallet_creation': '3/hour',
    'kdf_derivation': '10/hour',
    'mfa_setup': '5/hour',

    # API endpoints
    'api_read': '100/hour',
    'api_write': '50/hour',
    'api_sensitive': '30/hour',
}

# Implementation
from django_ratelimit.decorators import ratelimit

@ratelimit(key='user', rate='5/m', method='POST')
def login_view(request):
    """Rate-limited login endpoint."""
    pass
```

---

## 6️⃣ INPUT VALIDATION STANDARDS

### Email Validation
```python
from django.core.validators import validate_email
from email_validator import validate_email as deep_validate

def validate_secure_email(email: str) -> str:
    """SECURE email validation."""
    # Django validation
    validate_email(email)

    # Deep validation (DNS, deliverability)
    validated = deep_validate(email, check_deliverability=True)

    # Normalize
    return validated.email.lower()
```

### Web3 Address Validation
```python
def validate_ethereum_address(address: str) -> str:
    """SECURE Ethereum address validation."""
    # Format check
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        raise ValueError("Invalid address format")

    # Checksum validation
    if not Web3.isChecksumAddress(address):
        raise ValueError("Invalid address checksum")

    # Prevent zero address
    if address == '0x0000000000000000000000000000000000000000':
        raise ValueError("Zero address not allowed")

    return Web3.toChecksumAddress(address)
```

---

## 7️⃣ SESSION SECURITY STANDARDS

### Cookie Configuration
```python
# MANDATORY cookie settings
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
SESSION_COOKIE_AGE = 86400  # 24 hours maximum
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
```

### Session Management
```python
# MANDATORY session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'  # Redis backend

# Session security
SESSION_SAVE_EVERY_REQUEST = True  # Update activity
SESSION_COOKIE_NAME = '__Host-sessionid'  # Chrome protection
```

---

## 8️⃣ SECURITY HEADERS STANDARDS

### MANDATORY Headers
```python
# Security middleware
class SecurityHeadersMiddleware:
    def __call__(self, request):
        response = self.get_response(request)

        # MANDATORY security headers
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        # Content Security Policy
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'strict-dynamic'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        return response
```

---

## 9️⃣ AUDIT LOGGING STANDARDS

### Security Event Logging
```python
# MANDATORY logging for security events
import structlog

security_logger = structlog.get_logger('security')

def log_security_event(event_type: str, **kwargs):
    """Log security-relevant events."""
    security_logger.info(
        event_type,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs
    )

# MUST log these events
MANDATORY_LOG_EVENTS = [
    'login_attempt',
    'login_success',
    'login_failure',
    'logout',
    'password_change',
    'password_reset',
    'mfa_enabled',
    'mfa_disabled',
    'token_generated',
    'token_revoked',
    'permission_denied',
    'rate_limit_exceeded',
    'suspicious_activity',
]
```

---

## 🔟 DEPLOYMENT SECURITY CHECKLIST

### Pre-Deployment MANDATORY Checks
```python
# This MUST pass before ANY deployment
def security_deployment_check():
    """MANDATORY security checks before deployment."""

    checks = {
        'DEBUG_FALSE': settings.DEBUG is False,
        'SECRET_KEY_UNIQUE': len(settings.SECRET_KEY) >= 50,
        'JWT_SECRET_UNIQUE': len(settings.JWT_SECRET_KEY) >= 32,
        'DATABASE_PASSWORD': len(settings.DATABASES['default']['PASSWORD']) >= 20,
        'REDIS_PASSWORD': 'PASSWORD' in settings.CACHES['default']['OPTIONS'],
        'HTTPS_ENFORCED': settings.SECURE_SSL_REDIRECT is True,
        'ALLOWED_HOSTS': '*' not in settings.ALLOWED_HOSTS,
        'RATE_LIMITING': 'ratelimit' in settings.INSTALLED_APPS,
        'SECURITY_HEADERS': 'SecurityHeadersMiddleware' in settings.MIDDLEWARE,
        'AUDIT_LOGGING': settings.LOGGING['loggers']['security'] is not None,
    }

    for check, passed in checks.items():
        if not passed:
            raise SecurityError(f"FAILED: {check}")

    return True
```

---

## ⛔ FORBIDDEN PRACTICES

### NEVER Use These Patterns
```python
# ❌ FORBIDDEN: Eval or exec
eval(user_input)  # NEVER
exec(user_code)  # NEVER

# ❌ FORBIDDEN: Pickle with user data
pickle.loads(user_data)  # NEVER

# ❌ FORBIDDEN: Direct OS commands
os.system(f"command {user_input}")  # NEVER

# ❌ FORBIDDEN: Weak random
random.randint()  # NEVER for security
uuid.uuid1()  # NEVER (MAC address leak)

# ❌ FORBIDDEN: Unvalidated redirects
return redirect(request.GET['next'])  # NEVER

# ❌ FORBIDDEN: Debug info in production
DEBUG = True  # NEVER in production
TEMPLATE_DEBUG = True  # NEVER in production
```

---

## 🚨 SECURITY INCIDENT RESPONSE

### Immediate Actions for Breach
```python
def security_breach_response():
    """IMMEDIATE response to security breach."""

    # 1. Isolate affected systems
    disable_all_external_access()

    # 2. Revoke all tokens
    TokenBlacklist.revoke_all_tokens()

    # 3. Force password resets
    User.objects.update(password_reset_required=True)

    # 4. Enable emergency MFA
    settings.REQUIRE_MFA = True

    # 5. Alert security team
    send_security_alert("CRITICAL: Security breach detected")

    # 6. Preserve forensic evidence
    create_forensic_snapshot()
```

---

## 📝 SECURITY CODE REVIEW CHECKLIST

Before ANY code merge:
- [ ] No hardcoded secrets
- [ ] No sensitive data in logs
- [ ] All inputs validated
- [ ] SQL injection prevention verified
- [ ] XSS prevention implemented
- [ ] CSRF tokens present
- [ ] Rate limiting configured
- [ ] Authentication required
- [ ] Permissions checked
- [ ] Crypto functions use established libraries
- [ ] Error messages don't leak information
- [ ] Security tests passing
- [ ] Dependencies scanned for vulnerabilities

---

## 1️⃣1️⃣ SOC2 COMPLIANCE REQUIREMENTS

### MANDATORY SOC2 Controls
```python
# ALL authentication systems MUST implement
SOC2_REQUIREMENTS = {
    'AUDIT_TRAIL': True,  # Complete audit logging
    'ACCESS_CONTROL': True,  # Role-based access
    'ENCRYPTION': True,  # Data at rest and in transit
    'MONITORING': True,  # Continuous security monitoring
    'INCIDENT_RESPONSE': True,  # Documented procedures
    'CHANGE_MANAGEMENT': True,  # Controlled changes
    'RISK_ASSESSMENT': True,  # Regular assessments
    'VENDOR_MANAGEMENT': True,  # Third-party security
}

# MANDATORY audit events (see AUDIT_TRAIL_IMPLEMENTATION.md)
AUDIT_ALL_EVENTS = True
AUDIT_RETENTION_YEARS = 7
AUDIT_IMMUTABLE = True
AUDIT_TAMPER_PROOF = True
```

### Enterprise Security Standards
```python
# MANDATORY compliance frameworks
COMPLIANCE_FRAMEWORKS = [
    'SOC2_TYPE_II',
    'ISO_27001',
    'NIST_CSF',
    'CIS_CONTROLS_V8',
    'GDPR',
    'CCPA',
]

# MANDATORY certifications
SECURITY_CERTIFICATIONS = {
    'PENETRATION_TESTING': 'quarterly',
    'VULNERABILITY_SCANNING': 'weekly',
    'SECURITY_AUDIT': 'annual',
    'COMPLIANCE_AUDIT': 'annual',
}
```

## 1️⃣2️⃣ AUDIT-READY IMPLEMENTATION

### Audit Trail Requirements
```python
# EVERY action MUST be audited
@audit_trail  # MANDATORY decorator
def any_sensitive_function():
    """All functions handling auth/data MUST use audit_trail."""
    pass

# MANDATORY audit fields
AUDIT_FIELDS = {
    'timestamp': datetime,  # When
    'user_id': UUID,  # Who
    'action': str,  # What
    'resource': str,  # On what
    'ip_address': str,  # From where
    'result': str,  # Outcome
    'risk_score': int,  # Risk level
    'compliance_framework': list,  # SOC2, ISO, etc.
}
```

### Evidence Collection
```python
# MANDATORY evidence for audits
class ComplianceEvidence:
    """Collect evidence for compliance audits."""

    RETENTION_PERIOD = timedelta(days=2555)  # 7 years
    EVIDENCE_TYPES = [
        'authentication_logs',
        'access_control_logs',
        'change_management_logs',
        'security_incident_logs',
        'system_monitoring_logs',
    ]

    @audit_trail
    def collect_evidence(self, event):
        """MUST collect evidence for ALL security events."""
        pass
```

## 1️⃣3️⃣ CONTINUOUS MONITORING

### Real-time Security Monitoring
```python
# MANDATORY monitoring
MONITORING_REQUIREMENTS = {
    'REAL_TIME_ALERTS': True,
    'ANOMALY_DETECTION': True,
    'THREAT_INTELLIGENCE': True,
    'BEHAVIORAL_ANALYSIS': True,
    'AUTOMATED_RESPONSE': True,
}

# Alert thresholds
ALERT_THRESHOLDS = {
    'failed_login_attempts': 5,  # per minute
    'high_risk_score': 70,
    'unusual_activity': True,
    'compliance_violation': 0,  # Zero tolerance
}
```

## 🎯 REMEMBER

**Security, Compliance, and Audit-Readiness are NOT optional. These standards are MANDATORY.**

Every line of code you write MUST:
1. **Comply with security standards**
2. **Meet SOC2 requirements**
3. **Be audit-ready**
4. **Include complete logging**
5. **Follow enterprise standards**

No exceptions, no shortcuts, no "temporary" insecure code.

When in doubt, choose the MORE SECURE option. Always.

**See also:**
- [SOC2_COMPLIANCE.md](SOC2_COMPLIANCE.md) - Full SOC2 implementation
- [AUDIT_TRAIL_IMPLEMENTATION.md](AUDIT_TRAIL_IMPLEMENTATION.md) - Complete audit guide
- [security-enforcement-hook.md](hooks/security-enforcement-hook.md) - Automatic enforcement