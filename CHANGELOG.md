# Changelog

All notable changes to BlockAuth are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, breaking changes increment the minor version.

---

## [Unreleased]

### Breaking Changes

- **Wallet login now requires a server-issued SIWE (EIP-4361) challenge** (#90). Clients must call `POST /login/wallet/challenge/` to obtain a signed plaintext before calling `POST /login/wallet/`. The login response shape (`{access, refresh}`) is unchanged, and the error envelope is now `{"error": {"code": "...", "message": "..."}}` with distinct string codes (e.g. `invalid_signature`, `nonce_invalid`, `domain_mismatch`) for each failure mode. Consumers that were passing raw JSON-body payloads to the old endpoint must migrate to the two-round-trip flow. See the "Migration notes" section below.

### Added

- `POST /login/wallet/challenge/` — server mints a 128-bit nonce bound to the lowercased address with a configurable TTL and returns an EIP-4361 plaintext for the client to sign. The server owns every byte of the signed message.
- `WalletLoginNonce` model + migration (`blockauth/migrations/0002_walletloginnonce.py`). Single-use, TTL-bounded, indexed on `expires_at` for cheap reaping.
- `blockauth.utils.siwe` — minimal EIP-4361 parser/builder with CRLF tolerance, duplicate-field rejection, and a 4096-byte parse cap.
- `blockauth.services.wallet_login_service.WalletLoginService` — nonce issuance + SIWE verification + single-use consumption via `SELECT ... FOR UPDATE`. Rejects malleable high-s signatures.
- `blockauth.services.wallet_user_linker.WalletUserLinker` — atomic `get_or_create` + JWT issuance + post-commit trigger fan-out.
- `python manage.py prune_wallet_nonces` management command for scheduled reaping of expired / consumed nonce rows (see `blockauth/management/commands/prune_wallet_nonces.py`).
- Startup validation: non-DEBUG deployments refuse to boot without `WALLET_LOGIN_EXPECTED_DOMAINS` set (opt-out: `WALLET_LOGIN_SKIP_STARTUP_VALIDATION`).
- `WalletLoginThrottle` / `WalletChallengeThrottle` — per-(IP, address, scope) throttles so the challenge and login endpoints have independent buckets and so a load-balancer IP doesn't starve all legitimate users into one bucket.

### Fixed

- `POST /wallet/link/` with an invalid wallet address format now returns `400` instead of `500`.
- Business rule evaluation order in `WalletLinkSerializer` — user's existing wallet check now runs before the DB conflict query, preventing unnecessary database queries and wallet enumeration.
- `POST /wallet/email/add/` with an invalid email format now returns `400` instead of `500` (same root cause as the wallet address fix).
- Concurrent first-login race for an unseen address no longer trips a 500 IntegrityError; the losing side now returns the existing row via `get_or_create` inside `transaction.atomic()` (#90, hardening #1).
- A raising `POST_SIGNUP_TRIGGER` no longer loses the post-signup fan-out nor blocks the HTTP response; triggers run on `transaction.on_commit` wrapped in per-trigger `try/except logger.exception` (#90, hardening #2).
- With `WALLET_LOGIN_AUTO_CREATE=False` the endpoint no longer acts as a registration oracle -- unknown and known wallets both return a generic 401. Deployments that need the distinct 403 can opt in via `WALLET_LOGIN_EXPOSE_REGISTRATION_STATUS=True` (#90, hardening #4).
- Narrow exception handling in signature verification. A library regression surfaces as `signature_internal_error` (mapped to HTTP 500) with `logger.exception`, rather than masquerading as a 400 from bad input (#90, hardening #5).
- Token-issuance fallback now warns on `ImportError` instead of silently dropping custom claims (#90, hardening #6).
- Startup validation no longer fires during offline management commands. Docker builds that run `python manage.py collectstatic` / `migrate` / `check` / etc. no longer fail on a non-DEBUG deployment with an empty `WALLET_LOGIN_EXPECTED_DOMAINS`. The check still fires for `runserver` and for WSGI/ASGI boots (gunicorn, uvicorn, daphne), so a misconfigured deployment still refuses to serve traffic (#93).

### Migration notes

- Run `python manage.py migrate` to apply `blockauth.0002_walletloginnonce`.
- Set `WALLET_LOGIN_EXPECTED_DOMAINS` in production Django settings (the hard-failing startup check fires on `DEBUG=False` deployments without one).
- Update wallet-login clients to call `POST /login/wallet/challenge/` first, sign the returned `message` verbatim with the wallet's private key, and post `{wallet_address, message, signature}` to `POST /login/wallet/`.
- Schedule `python manage.py prune_wallet_nonces` every 5–15 minutes (Celery Beat, cron, or systemd timer).

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
