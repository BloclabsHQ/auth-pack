# Security Standards

This page summarizes the mandatory security standards for BlockAuth. The full standards document is maintained at [`.claude/SECURITY_STANDARDS.md`](https://github.com/BloclabsHQ/auth-pack/blob/dev/.claude/SECURITY_STANDARDS.md) in the repository.

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
