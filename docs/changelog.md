# Changelog

## v0.4.0 (Unreleased)

### Added
- GitHub Pages documentation site with MkDocs Material
- Comprehensive guides for all authentication methods

### Security
- Wallet replay protection with configurable message TTL (`WALLET_MESSAGE_TTL`)
- Refresh token rotation with blacklisting (`ROTATE_REFRESH_TOKENS`)
- Progressive lockout for repeated auth failures
- Timing-attack remediation with constant-time comparisons
- Rate limiter hardening
- Error message sanitization to prevent information leakage

## v0.3.0

### Added
- **Step-Up Authentication** -- RFC 9470 receipt-based step-up auth (`blockauth.stepup`)
- **WebAuthn/Passkey Authentication** -- FIDO2 support for Face ID, Touch ID, Windows Hello
- **TOTP/2FA** -- Time-based one-time passwords with pluggable storage
- **Custom JWT Claims** -- Pluggable claims provider architecture
- **KDF System** -- PBKDF2 and Argon2 key derivation for Web2-to-Web3 bridging
- **Feature Flags** -- Enable/disable any auth feature independently
- **Rate Limiting** -- Per-request and OTP-specific throttling
- Email verification flow
- Password change and reset triggers
- Wallet email add endpoint
- OpenAPI/Swagger documentation via drf-spectacular

### Security
- Algorithm pinning on JWT decode
- OTP generation with `secrets.choice()`
- Signature malleability protection for wallet auth
- Sensitive field filtering in logs

## v0.2.0

### Added
- OAuth integration (Google, Facebook, LinkedIn)
- Passwordless login via OTP
- Web3 wallet authentication
- Trigger system for auth events
- Custom notification class support

## v0.1.0

### Added
- Initial release
- JWT authentication with HS256
- Email/password signup and login
- Token refresh
- Password reset
- Django REST Framework integration
