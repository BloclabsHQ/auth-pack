# Changelog

All notable changes to BlockAuth are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, breaking changes increment the minor version.

---

## [Unreleased]

### Breaking Changes

- `error_code` in wallet login responses changed from integer `4009` to string `"INVALID_SIGNATURE"`. Update any client code that checks this field by value.

### Fixed

- `POST /wallet/link/` with an invalid wallet address format now returns `400` instead of `500`.
- Business rule evaluation order in `WalletLinkSerializer` — user's existing wallet check now runs before the DB conflict query, preventing unnecessary database queries and wallet enumeration.

---

## [0.4.0] - 2026-04-09

### Added

- Passkey/WebAuthn authentication (FIDO2)
- TOTP 2FA
- Step-up authentication receipts (RFC 9470)
- RS256/ES256 asymmetric JWT support alongside HS256
- KDF services (PBKDF2, Argon2)
- Social auth (Google, Facebook, LinkedIn)
- Enhanced JWT with custom claims support

---

## [0.3.0] - 2026-04-08

### Added

- Initial public release
- JWT authentication (HS256)
- Basic auth (email + password)
- Passwordless login (OTP)
- Wallet login (MetaMask signature verification with replay protection)
- Feature-flag-driven URL routing
- Trigger system for post-action hooks
