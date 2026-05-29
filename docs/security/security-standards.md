# Security Standards

This page summarizes the mandatory security standards for BlockAuth.

## Immediate Rules

### Never

- Log sensitive data (passwords, tokens, private keys)
- Use weak random (`random.random()`, `uuid.uuid4()` for security tokens)
- Hardcode secrets in source code
- Use `eval()`, `exec()`, or `pickle.loads()` with user data
- Trust user input without validation

### Always

- Use `secrets.token_urlsafe()` for token generation
- Hash passwords with bcrypt (14+ rounds) via Django's `set_password()`
- Validate all input with Django validators
- Use parameterized queries (Django ORM)

## Password Standards

- Minimum 12 characters
- Require uppercase, lowercase, numbers, and special characters
- Maximum 3 consecutive identical characters
- Check against common password lists
- Prevent reuse of last 5 passwords

## JWT Standards

- HS256 with 256-bit minimum secret key
- Algorithm pinning on decode
- Required claims: `exp`, `iat`, `user_id`, `type`
- Access token lifetime: configurable (recommended <= 15 minutes for high-security)
- Refresh token rotation with blacklisting

## Key Derivation Standards

- PBKDF2: minimum 600,000 iterations (NIST 2024 recommendation)
- Key length: 256 bits minimum
- Salt length: 256 bits minimum
- Unique salt per user

## Rate Limiting

| Endpoint Type | Recommended Limit |
|--------------|-------------------|
| Login | 5/minute |
| Registration | 3/hour |
| Password reset | 3/hour |
| Token refresh | 10/minute |
| KDF derivation | 10/hour |
| TOTP setup | 10/hour |
| TOTP confirm / verify | 5/minute, 5 failures → cooldown |

### Throttle wire contract

When a request is throttled, the API returns HTTP `429` with a single,
stable body:

```json
{ "error": "throttled", "message": "..." }
```

This `error` code is a public contract — consumers should match `throttled`,
not the response message. Note that a `429` may also be returned by the TOTP
service-layer account lockout after repeated failed verification attempts; that
case carries the TOTP error envelope (e.g. `{"error": "totp_too_many_attempts"}`)
rather than the throttle envelope. Both use status `429`.

### Throttle bucket keying

Throttle counters (rate, failures, cooldown, daily) are keyed on the
authenticated principal when present, falling back to the client IP only for
unauthenticated flows. The client IP is read from `X-Forwarded-For` counted
from the right using `TRUSTED_PROXY_DEPTH` (default `1`); set it to `0` when the
app is directly internet-facing, or to the number of trusted proxy hops. For
brute-force-critical subjects the throttle fails **closed** if the cache backend
is unavailable.

## Input Validation

- Email: Django `validate_email` + format normalization
- Ethereum address: regex `^0x[a-fA-F0-9]{40}$` + checksum validation
- Zero address rejection
- Message size limits

## Security Headers (for deploying services)

```python
# Recommended Django settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
```

## Audit Logging

All authentication events should be logged:

- Login attempts (success and failure)
- Password changes and resets
- MFA enable/disable
- Token generation and revocation
- Rate limit exceeded
- Permission denied

## Pre-Deployment Checklist

- [ ] `DEBUG = False`
- [ ] Secret key is unique and >= 50 characters
- [ ] JWT secret is unique and >= 32 characters
- [ ] HTTPS enforced (`SECURE_SSL_REDIRECT`)
- [ ] `ALLOWED_HOSTS` does not contain `*`
- [ ] Rate limiting is configured
- [ ] Security headers middleware is active
- [ ] Audit logging is enabled
- [ ] Dependencies scanned for vulnerabilities
- [ ] No hardcoded secrets in codebase
