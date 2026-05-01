# Changelog

All notable changes to BlockAuth are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, breaking changes increment the minor version.

---

## [Unreleased]

### Added

### Changed

### Fixed

---

## [0.16.2] - 2026-05-01

### Added

- Added package-level per-IP throttles for Apple web callback, native verify, and server-to-server notification endpoints with overridable `BLOCK_AUTH_SETTINGS` rate tuples.

### Changed

- Apple server-to-server notifications now reject stale or future `event_time` values and suppress replayed notifications before mutating `SocialIdentity` rows or running `APPLE_NOTIFICATION_TRIGGER`.
- Apple server-to-server notifications now use Apple's documented `account-deleted` event type.

### Fixed

- Apple server-to-server notification triggers now call the package's public `BaseTrigger.trigger(context)` method, with the previous `run(context)` shape kept as a fallback for compatibility.

---

## [0.16.1] - 2026-04-29

### Changed

- Renamed the SocialIdentity table from `social_identity` to `blockauth_social_identity` with a forward migration so the table is package-scoped for reusable Django deployments.
- Replaced downstream-specific examples and comments with generic consumer-app guidance.
- Social identity sign-in now fails closed with `SOCIAL_IDENTITY_USER_UNAVAILABLE` when an existing identity points at a user hidden by the configured user model's default manager, preventing soft-deleted accounts from receiving fresh tokens through FK traversal.
- Wrapped the email-resync `user.save()` in `_sync_user_email_from_provider` in a savepoint so a DB-level unique violation on integrators with soft-delete-style managers no longer poisons the surrounding `upsert_and_link` transaction (subsequent saves on `existing_identity` previously failed with `TransactionManagementError` on PostgreSQL).

### Fixed

- Removed private integrator references from public docs, test comments, changelog entries, and Apple setup guidance.

---

## [0.16.0] - 2026-04-25

### Added

- **Apple Sign-In** — full surface:
  - `GET /apple/` web authorize (PKCE + nonce + form_post).
  - `POST /apple/callback/` form_post callback (state + PKCE verify, id_token verify with conditional nonce, SocialIdentity link, blockauth JWT).
  - `POST /apple/verify/` native id_token verify for iOS/macOS clients (optional `authorization_code` redemption for refresh-token-at-rest).
  - `pre_delete` signal that revokes Apple refresh tokens at `/auth/revoke` when an integrator deletes a user (App Store Review Guideline 5.1.1(v)).
  - `POST /apple/notifications/` server-to-server webhook (Korean SIWA mandate effective 2026-01-01) handling `consent-revoked`, `account-deleted`, `email-disabled`, `email-enabled` events. Trigger hook receives `{event_type, sub, event_time}` only — full JWT claims are NOT exposed (PII safety).
- **Google native id_token verify** — `POST /google/native/verify/` for Android Credential Manager, iOS Google Sign-In SDK, and Web One Tap. Audience set is `BLOCK_AUTH_SETTINGS["GOOGLE_NATIVE_AUDIENCES"]` (the integrator's web/server client IDs).
- **Generic `OIDCTokenVerifier`** (`blockauth.utils.jwt`) reused by every OIDC provider:
  - JWKSCache with TTL + rotation-on-kid-miss refetch + transient-failure preservation (a 5xx from the IdP no longer wipes a working cache).
  - Algorithm pinning before signature work (defense against algorithm confusion). Algorithm-aware key dispatch via `pyjwt.algorithms.get_default_algorithms()` (RSA + EC + ed25519 — not just RSA).
  - Audience allowlist, leeway, nonce check via `hmac.compare_digest`, required-email-claim option.
  - 9 specific exception subclasses (AlgorithmNotAllowed, AudienceMismatch, IssuerMismatch, JWKSUnreachable, KidNotFound, NonceMismatch, RequiredClaimMissing, SignatureInvalid, TokenExpired) all under `OIDCVerificationError`.
  - `OIDCVerifierConfig` validates fields at construction (no silent empty audiences/algorithms).
- **`SocialIdentity` model** + `SocialIdentityService` — durable `(provider, subject) → User` link with AES-GCM-256 refresh-token-at-rest. AAD binds each ciphertext to the (provider, subject) so a row-level ciphertext cannot be replayed onto another row. New table `social_identity` (additive); no `User` columns added.
- **`AccountLinkingPolicy`** — provider-aware verified-email auto-link:
  - **Google**: gmail.com / googlemail.com or `hd` claim cross-validated against email domain (defends against malicious `hd` injection).
  - **LinkedIn**: `email_verified=true` (LinkedIn requires verification at signup).
  - **Facebook**: email present (Facebook only returns email when verified).
  - **Apple**: never authoritative — pure `(apple, sub)` matching; collisions surface as HTTP 409.
  - Provider name normalised case-insensitively.
- **PKCE (RFC 7636)** on every web OAuth flow (Google/LinkedIn/Facebook/Apple). `compute_pkce_challenge` exposed for testing against the RFC 7636 Appendix B vector. Pair returned as a `NamedTuple` to defend against position-swap bugs at the four call sites.
- **`AppleClientSecretBuilder`** — ES256-signed client_secret JWT for Apple's `/auth/token`, lock-guarded in-process cache, 5-hour lifetime with 5-minute rebuild margin. Module-level `apple_client_secret_builder` singleton.
- New feature flags: `APPLE_LOGIN`, `GOOGLE_NATIVE_LOGIN` (independent of `SOCIAL_AUTH` so integrators can enable native-only or Apple-only without enabling the full social suite).
- New configuration: `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY_PEM` / `APPLE_PRIVATE_KEY_PATH`, `APPLE_SERVICES_ID`, `APPLE_BUNDLE_IDS`, `APPLE_REDIRECT_URI`, `APPLE_NOTIFICATION_TRIGGER`, `APPLE_CALLBACK_COOKIE_SAMESITE`, `GOOGLE_NATIVE_AUDIENCES`, `OIDC_JWKS_CACHE_TTL_SECONDS`, `OIDC_VERIFIER_LEEWAY_SECONDS`, `SOCIAL_IDENTITY_ENCRYPTION_KEY`.
- New constants: `Features.APPLE_LOGIN`, `Features.GOOGLE_NATIVE_LOGIN`, `SocialProviders.APPLE`, `AuthenticationType.APPLE`, `URLNames.APPLE_*`, `URLNames.GOOGLE_NATIVE_VERIFY`. Extended `SENSITIVE_FIELDS` with `client_secret`, `code_verifier`, `raw_nonce`, `apple_private_key_pem`, `payload`.

### Changed

- **Refactored Google web OAuth** (`/google/`, `/google/callback/`) — verifies the `id_token` cryptographically (drops the userinfo HTTP call), links via `SocialIdentity` by `sub`, adds PKCE + nonce. Existing email-based fallback path is preserved through `AccountLinkingPolicy` so legacy gmail-domain matches still link to the existing user.
- **Refactored LinkedIn web OAuth** (`/linkedin/`, `/linkedin/callback/`) onto OIDC (LinkedIn finished its OIDC migration in 2024). Same id_token-verify + SocialIdentity + PKCE + nonce treatment as Google.
- **Refactored Facebook web OAuth** (`/facebook/`, `/facebook/callback/`) — Facebook is not OIDC, so the Graph `/me` call is retained, but the flow now uses PKCE on the token exchange and matches by `(facebook, fb_user_id)` via `SocialIdentityService`. Email-present implies verified (Facebook only returns email when the user has verified it).
- **`SocialIdentityConflictError`** now extends `rest_framework.exceptions.APIException` with `status_code=409` — auto-mapped to HTTP 409 (RFC 7231 §6.5.8) instead of 400. The internal `SOCIAL_IDENTITY_CONFLICT` code identifies the case for clients that branch on code.
- **`oauth_state.verify_state` rewritten as a thin wrapper around the new `verify_state_values(cookie_state, provided_state)` pure helper** — supports Apple's form_post callback (state in body) without duplicating the CSRF logic.
- **`set_state_cookie` / `clear_state_cookie`** gain optional `samesite=` overrides — Apple's form_post requires SameSite=None+Secure on the deployed callback hop.
- **`social_login_data`** accepts `preexisting_user` in `provider_data` — when present, skips the `get_or_create(email=...)` step so `SocialIdentityService`'s subject-based linkage owns user creation. Backwards-compatible (`preexisting_user` is optional).

### Migrations

- New table `social_identity` (additive). `User` model unchanged; no `ALTER TABLE` on existing tables; no data backfill required. Existing users get a `SocialIdentity` row created on their next OAuth sign-in.

### Breaking changes

- **`SocialIdentityConflictError` HTTP status changed from 400 to 409** for any caller relying on the old behavior. The internal error code (`SOCIAL_IDENTITY_CONFLICT`, default code) is unchanged; clients branching on code only are unaffected.
- Integrators storing Apple refresh tokens must set `BLOCK_AUTH_SETTINGS["SOCIAL_IDENTITY_ENCRYPTION_KEY"]` (base64-encoded 32 bytes); without it, refresh tokens are silently dropped with a warning log. No-key deployments continue to work for Apple sign-in (just no revocation later).

---

## [0.14.0] - 2026-04-24

### Added

- **OAuth `state` parameter for CSRF protection** (#138). Google/Facebook/LinkedIn init flows now generate a 32-byte random token, set it as an HttpOnly `blockauth_oauth_state` cookie (Secure/SameSite env-gated), and mirror it in the `state=` query param. Callbacks verify cookie vs query via `hmac.compare_digest` **before** touching the provider's token endpoint — CSRF probes cannot burn real authorization codes. Cookie cleared on success to prevent replay.
- **`social_login_data()`** — data-returning variant that returns `SocialLoginResult(user, access, refresh, created)` without building a Response. Enables integrators to BFF-ify the OAuth callback (HttpOnly cookies + 302 to app origin) without forking the view.
- **`build_success_response(request, result)`** hook on Google/Facebook/LinkedIn callback views. Subclass and override to swap the JSON-body default for a redirect + cookies. Base `social_login()` stays as a thin wrapper for backwards compatibility.
- **`WalletItemSerializer`** — shapes `user.wallets` as `[{address, chain_id, linked_at, label, primary}]`.

### Changed

- **BREAKING: `user.wallets` is now `WalletItem[]` instead of `string[]`** (#139). Every auth endpoint (basic / passwordless / wallet / OAuth) now returns the object shape. Clients reading `wallets[0]` as a string must migrate to `wallets[0].address`.
- **SIWE wallet-first accounts created as `is_verified=True`** (#139). Cryptographic proof of key control is a stronger ownership guarantee than email click-through verification. Legacy unverified wallet rows self-heal on next SIWE login.
- **Google OAuth promotes existing unverified users to `is_verified=True`** (#139). Google's OIDC response carries a verified-email claim. Facebook and LinkedIn are NOT promoted — no OIDC guarantee there.
- **`OAUTH_STATE_COOKIE_SECURE` / `OAUTH_STATE_COOKIE_SAMESITE` configurable via `BLOCK_AUTH_SETTINGS`** (#141). Previously hardcoded `secure=True` broke Firefox local http dev (Chrome treats localhost as secure, Firefox doesn't). Defaults remain strict.

### Fixed

- CSRF gap on Google OAuth init (missing `state` param)
- Predictable-state-never-verified gap on Facebook / LinkedIn callbacks
- Client validation error on wallet-first signup due to `wallets` shape mismatch
- `is_verified=False` on wallet-first accounts despite SIWE proof
- `is_verified=False` on email-first users who later sign in with Google

---

## [0.13.0] - 2026-04-20

### Added

- **`POST /wallet/unlink/`** (#122). Symmetric primitive to `POST /wallet/link/` that clears the authenticated user's linked wallet. No request body — the wallet to unlink is derived from the authenticated user (one linked wallet per user today). Clears `wallet_address` and drops the `WALLET` authentication-type marker. Response: `{"status": "unlinked"}`. Idempotent: returns `404 no_wallet_linked` when the user has no wallet linked (or on a second call after a successful unlink). Gated by the existing `Features.WALLET_LINK` flag — link and unlink enable together. Policy decisions (last-auth-method safeguard, event publication, audit logging) are deliberately left to the consumer layer, matching how `WalletLinkView` works.

---

## [0.12.0] - 2026-04-20

### Added

- **Pluggable observability hook** (#118). New `BLOCK_AUTH_SETTINGS["METRICS_CALLBACK"]` setting takes a dotted path to a callable that receives wallet-login events — `wallet_login.challenge_issued`, `wallet_login.success` (tag: `flow=siwe`), `wallet_login.failure` (tag: `code=<machine-readable>`), `wallet_login.latency` (tag: `outcome`, carries `duration_s`), and `wallet_nonce.pruned` (carries `count`). Backend-agnostic — consumers translate events into Prometheus / StatsD / OpenTelemetry / structured logs / nothing. Missing setting = no-op. Callback exceptions are caught and logged so a broken metrics pipe cannot fail login. Event names are a stable public contract.
- **`prune_wallet_nonces` scheduling guidance** in the README (#116). Cadence, batch size, failure mode, and example invocations for cron / Celery Beat / Kubernetes CronJob / ECS scheduled tasks.
- **SIWE wiki rewrite** (#115). Security, Authentication-Flows Flow 4, and Wallet-Models Model A now describe the EIP-4361 two-round-trip flow and the 11 hardening items shipped in PR #91.

### Changed

- **SIWE URI-domain consistency check** (#117). `WalletLoginService.verify_login` now enforces that the SIWE `uri` hostname matches the SIWE `domain` (strict equality — no subdomain leniency). Rejected with a new error code `uri_host_mismatch`. Prevents phishing domains whose URI points at an attacker-controlled host from passing the domain allow-list (wallets display the URI, not the domain). Existing `domain_mismatch` bucket is unchanged; the new code lets observability distinguish "wrong domain claim" from "URI/domain desync inside a valid claim".

---

## [0.11.1] - 2026-04-17

### Fixed

- **`blockauth.utils.social.social_login()` no longer crashes on user models without a `first_name` field** (#109). Previously the `get_or_create(defaults={"first_name": name, ...})` call raised `FieldError: Invalid field name(s) for model ...` on the create path, breaking first-time OAuth signup for any consumer whose concrete user model didn't declare `first_name`. `social_login()` now probes the model with `_meta.get_field("first_name")` and only includes the default when the field exists. Populate behavior is preserved for models that do declare the field.

### Added

- 2 regression tests in `blockauth/views/tests/test_oauth_views.py` exercising the real `get_or_create` create path (no user pre-seed): one asserts no crash on a minimal user model, one asserts `first_name` still lands when the field exists.

---

## [0.11.0] - 2026-04-17

### Added

- **`POST /email/change/confirm/` returns fresh `{access, refresh, user}`** alongside the existing `message` field (#110). Any custom `CustomClaimsProvider` that pins `email` into the access token now sees the new value without a follow-up refresh.
- **`POST /wallet/email/add/` returns fresh `{access, refresh, user}`** alongside the existing `message` field (#110). `is_verified` flips to `False` as before; the new tokens correctly carry that unverified state.
- **`POST /wallet/link/` returns fresh `{access, refresh, user}`** alongside the existing `{message, wallet_address}` fields (#110). Consumers whose custom claims pin `wallet_address` can stop chaining a follow-up `/token/refresh/`.
- **`blockauth.utils.auth_state`** — new module housing the shared `build_user_payload` / `issue_auth_tokens` helpers. Consolidates the post-auth-state-change contract into one place; future endpoints that adopt the pattern pick up every field in the `user` payload automatically.

### Changed

- `blockauth.utils.social.social_login()` (OAuth callbacks) and `basic_auth_views.py` now import `build_user_payload` / `issue_auth_tokens` from `blockauth.utils.auth_state` instead of defining them locally. Pure refactor — no behavior change.
- **Additive wire changes only.** Existing consumers that read `message` (and `wallet_address` on `/wallet/link/`) are unaffected; new consumers can pick up the richer payload without version-gating.

### Notes

- Custom-claims compatibility audit posted to #110. Summary: `JWTTokenManager.generate_token` re-reads the user by id before calling providers, so provider output reflects post-commit state as long as `user.save()` has committed (Django default auto-commit ensures this).

### Fixed

---

## [0.10.0] - 2026-04-17

### Added

- **OAuth callbacks return the full auth-state tuple** (#107). `GET /google/callback/`, `GET /facebook/callback/`, and `GET /linkedin/callback/` now return `{access, refresh, user}` using the shared `AuthStateResponseSerializer` introduced in 0.9.0. OAuth-signup clients can drop the follow-up `GET /me/` call that email/password/wallet flows already avoid. Fix is single-point in `blockauth.utils.social.social_login()` — all three callback views funnel through it.
- Three parity tests in `blockauth/views/tests/test_oauth_views.py::TestSocialLoginResponseShape` — one per provider, asserting the full `LoginUserSerializer` field set is present and the `user.id` matches.

### Changed

- OAuth callback OpenAPI schemas in `blockauth/docs/social_auth_docs.py` now document the `user` field with full property-level typing. The previous schemas were technically correct (`{access, refresh}`) but silently misled consumers into `/me/` round-trips. Consumers reading only `access` / `refresh` are unaffected.

### Fixed

---

## [0.9.0] - 2026-04-17

### Added

- **`POST /token/refresh/` returns the user payload**. Response shape expands from `{access, refresh}` to `{access, refresh, user}` using the new shared `AuthStateResponseSerializer`. The user row is already loaded in the view for custom-claims population, so surfacing it is free. Consumers can drop the 5-min `/me/` poller pattern once on this version.
- **`POST /password/reset/confirm/` auto-signs-in after a successful reset**. Response shape changes from `{"message": "..."}` to `{access, refresh, user}`. The OTP + new password prove ownership — forcing a second `/login/basic/` round-trip was pure ceremony.
- **`POST /password/change/` returns a fresh token pair + user**. Response shape changes from `{"message": "..."}` to `{access, refresh, user}`. When `ROTATE_REFRESH_TOKENS` is enabled this is also the right moment to rotate out tokens issued under the prior password.
- **`blockauth.serializers.user_account_serializers.AuthStateResponseSerializer`** — shared response class for all three endpoints above. Reusable by downstream services that add similar "full post-mutation auth state" endpoints.

### Changed

- `POST /password/reset/confirm/` and `POST /password/change/` success bodies change from `{"message": "..."}` to `{access, refresh, user}`. Clients that only inspected the HTTP status code are unaffected; clients that read the `message` field must switch to the new shape or ignore extra keys.
- `POST /token/refresh/` adds a `user` field; existing consumers reading `access` / `refresh` are unaffected.

### Fixed

---

## [0.8.0] - 2026-04-17

### Added

- **Login response user payload now includes `first_name` and `last_name`**. `LoginUserSerializer` — shared by basic-login, passwordless-login confirm, and wallet-login — now exposes both fields so clients can drop the follow-up `GET /me/` round-trip for profile hydration. Both fields are nullable and tolerant of downstream user models that do not define them (views read via `getattr(user, "first_name", None)`).
- **`POST /signup/confirm/` issues JWTs and returns the user payload** on successful signup confirmation. New response shape `{access, refresh, user}` mirrors the login endpoints so the client is signed in immediately instead of following up with `POST /login/basic/` using the just-set password. `POST_SIGNUP_TRIGGER` fires before tokens are issued; its signature is unchanged. Added `SignUpConfirmResponseSerializer` for OpenAPI documentation.

### Changed

- `POST /signup/confirm/` success response body changes from `{"message": "Sign up success"}` to `{"access, refresh, user}`. Existing clients that only inspected the HTTP status code are unaffected; clients that parsed the `message` field must switch to the new shape or ignore extra keys.

### Fixed

---

## [0.7.0] - 2026-04-17

### Breaking Changes

- **Wallet login now requires a server-issued SIWE (EIP-4361) challenge** (#90). Clients must call `POST /login/wallet/challenge/` to obtain a signed plaintext before calling `POST /login/wallet/`. The login response shape (`{access, refresh}`) is unchanged, and the error envelope is now `{"error": {"code": "...", "message": "..."}}` with distinct string codes (e.g. `invalid_signature`, `nonce_invalid`, `domain_mismatch`) for each failure mode. Consumers that were passing raw JSON-body payloads to the old endpoint must migrate to the two-round-trip flow. See the "Migration notes" section below.
- **`ValidationErrorWithCode` now subclasses DRF's `ValidationError`** (#101). `.detail` is a DRF-native `{field: [ErrorDetail, ...]}` map; the top-level error code moves from `.detail["error_code"]` to the `.error_code` attribute on the exception instance.
  - Response body for DRF's default exception handler changes from `{"detail": {"error_code": "4000", "detail": {field: message}}}` to `{field: [message]}`. The top-level code is no longer in the body when using DRF's default handler.
  - Custom exception handlers that branch on `isinstance(exc, ValidationError)` now pick up `ValidationErrorWithCode` automatically and can iterate `exc.detail` as a DRF-native field map.
  - Per-field multi-message behavior changes: the old code joined multiple error messages per field into a single space-separated string. The new class preserves DRF's list of `ErrorDetail` so per-error codes and messages are iterable individually.
  - Scalar per-field `detail` values (e.g. `{"email": "msg"}`) are normalized into `[ErrorDetail("msg")]` on `__init__` so `.detail` always matches the `{field: [ErrorDetail, ...]}` shape. Caller-supplied `code=` now propagates to both `.error_code` and per-field wrapping so top-level and per-field codes stay consistent. Tuple per-field values and nested-serializer detail dicts are accepted when deriving `.error_code` (tuples alongside lists; nested dicts recurse to the deepest leaf).

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
- If your service uses a custom DRF `EXCEPTION_HANDLER` that special-cases `ValidationErrorWithCode` by reading `exc.detail["error_code"]` or `exc.detail["detail"]`, switch to reading `exc.error_code` and iterating `exc.detail` as a standard DRF field map. If your service relies on DRF's default handler and was parsing the legacy envelope, switch to the DRF-native `{field: [message]}` shape (#101).

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
