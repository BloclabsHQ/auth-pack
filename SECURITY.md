# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BlockAuth, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email **security@bloclabs.com** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Security Practices

BlockAuth follows these security practices:

- All cryptographic comparisons use constant-time functions (`hmac.compare_digest`)
- JWT algorithms are pinned on decode (no algorithm confusion attacks)
- OTP generation uses `secrets.choice()` (cryptographically secure)
- No sensitive data (passwords, tokens, keys) in logs
- Rate limiting on all authentication endpoints
- Dependencies are regularly audited for vulnerabilities
