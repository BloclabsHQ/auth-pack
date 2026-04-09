# Security Overview

BlockAuth is designed with security as a core principle. This page summarizes the security measures built into the package.

## Password Security

- Passwords are hashed using Django's `set_password()` (bcrypt recommended with 14+ rounds)
- `BlockAuthPasswordValidator` enforces complexity requirements
- Passwords are never logged or included in trigger context

## JWT Security

- Algorithm pinning on decode: `algorithms=[...]` prevents algorithm confusion attacks
- Required claims validation: `exp`, `iat`, `user_id`, `type`
- Token type enforcement: access tokens cannot be used as refresh tokens
- Short-lived access tokens (default: 1 hour) with refresh rotation
- Refresh token blacklisting on rotation (`ROTATE_REFRESH_TOKENS`)

## OTP Security

- Generated with `secrets.choice()` (cryptographically secure random)
- Short validity window (default: 1 minute)
- Single-use: marked as used after verification
- Rate-limited: prevents brute-force attempts

## Wallet Security

- Signature verification with ECDSA recovery
- Signature malleability protection (s-value check)
- Zero address rejection
- Message size limits (DoS prevention)
- Replay protection via TTL (`WALLET_MESSAGE_TTL`)

## KDF Security

- PBKDF2 with 100k+ iterations or Argon2id (memory-hard)
- Timing-safe comparisons with `hmac.compare_digest()`
- Dual encryption: user password + platform key
- 256-bit minimum key lengths

## Rate Limiting

- Per-request throttling on all auth endpoints
- OTP-specific rate limiting
- Configurable limits per (identifier, subject, IP address)
- Progressive lockout for repeated failures

## WebAuthn / Passkeys

- No biometric data processed server-side
- Credential sign counter validation (clone detection)
- Challenge expiration
- GDPR compliant (see [DPIA](https://github.com/BloclabsHQ/auth-pack/blob/dev/docs/WEBAUTHN_PASSKEY_DPIA.md))

## Step-Up Authentication

- Short-lived receipts (default: 120 seconds)
- Audience-scoped to prevent cross-service replay
- Subject binding to prevent IDOR attacks
- Unique JTI per receipt

## General Practices

- No sensitive data in logs (passwords, tokens, keys filtered by `sensitive_fields`)
- No `traceback.print_exc()` in production paths
- Input validation on all endpoints via DRF serializers
- Feature flags to reduce attack surface by disabling unused features

For the full security standards, see [Security Standards](security-standards.md).
