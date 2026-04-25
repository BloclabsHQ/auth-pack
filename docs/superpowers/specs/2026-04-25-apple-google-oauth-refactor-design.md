# Apple Sign-In, Google Native, and OAuth Refactor — Design

**Status:** Approved (after code audit + 2026-04-25 web research)
**Target version:** `blockauth` 0.16.0
**Audience:** engineers implementing the change; integrators upgrading from 0.15.x

---

## 1. Problem

The package today supports browser-based OAuth (authorization code flow) for Google, Facebook, and LinkedIn. The implementations have three structural issues that block production use across modern client surfaces:

1. **No id_token verification.** All three providers ignore the `id_token` returned from the token endpoint and call the provider's userinfo endpoint over TLS, trusting the response. There is no cryptographic check on the identity claims.
2. **Email-only user matching.** All three providers call `User.objects.get_or_create(email=...)`. There is no `(provider, subject)` link table. A pre-account-takeover at any provider that issues `email_verified=true` without authoritative ownership compromises the matched account.
3. **No native sign-in path.** There is no endpoint that accepts a client-obtained `id_token` from a platform SDK (Apple `AuthenticationServices`, Google Credential Manager, Sign in with Google for Web One Tap, Google iOS SDK).

Additionally, Apple Sign-In is absent — a hard requirement for App Store apps that ship third-party login (App Store Review Guideline 4.8) and account deletion (5.1.1(v)).

## 2. Goals

1. Add **Apple Sign-In** (web authorize+callback flow, native id_token verify flow, account revocation, server-to-server notification webhook).
2. Add **Google Native id_token verify** endpoint that accepts tokens from Android Credential Manager, iOS Google Sign-In SDK, and Web One Tap.
3. Add a **generic OIDC token verifier** (`OIDCTokenVerifier`) that any current or future OIDC provider reuses — JWKS-based, kid-rotation safe, algorithm-pinned, audience-allowlisted, nonce-aware.
4. Introduce a **`SocialIdentity` model** that stores `(provider, subject)` → `User` links durably. Refresh tokens (where issued) are encrypted at rest with AES-GCM.
5. Refactor **Google web**, **LinkedIn web**, and **Facebook web** flows to:
   - Use `OIDCTokenVerifier` to cryptographically verify the `id_token` returned from the token endpoint (Google + LinkedIn). Facebook stays on the Graph API since it is not OIDC.
   - Match users by `SocialIdentity(provider, subject)` instead of email.
   - Add **PKCE** (code_verifier / code_challenge S256) per OAuth 2.1.
   - Add **nonce** to the authorization request and verify it in the `id_token` (Google, LinkedIn, Apple web).
6. Implement an **account-linking policy** (`AccountLinkingPolicy`) that links a new social identity to an existing `User` only when the issuer is authoritative for the claimed email.
7. Comply with App Store Review Guideline 5.1.1(v): account deletion triggers Apple token revocation via `pre_delete` signal.
8. Comply with the Korean SIWA mandate (effective 2026-01-01): expose a server-to-server notifications webhook that handles `consent-revoked`, `account-delete`, `email-disabled`, `email-enabled` events.

## 3. Non-goals

- No UI, HTML templates, static assets, or client-side JavaScript shipped from this package. Endpoints return JSON, 302 redirects, or 200 OK on webhook receipt — nothing else.
- No retrofit of Apple-specific behavior into other providers' code paths beyond the shared `OIDCTokenVerifier` and `SocialIdentityService`.
- No **GitHub** OAuth (separate feature).
- No **Microsoft Identity Platform** integration (separate feature).
- No **Facebook Limited Login** (iOS/Android OIDC variant) — separate follow-up.
- No **Play Integrity / DeviceCheck / App Attest** attestation on native verify endpoints.
- No data backfill or migration of existing users. The `SocialIdentity` table is created empty and populated forward.
- No change to existing `User` model fields. No new columns, no altered fields.
- No authenticated "link account" endpoint in 0.16. Users hitting a non-authoritative-email collision get HTTP 409 with a clear message; explicit linking is a 0.17 follow-up.

## 4. Principles

These rules constrain every design and implementation decision below.

1. **Self-custody upheld.** No private keys derived from social identity. Wallet derivation is unaffected.
2. **Industry standards.** RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7519 (JWT), OpenID Connect Core 1.0, RFC 8252 (OAuth for Native Apps), OAuth 2.1 PKCE-mandatory profile. Apple SIWA per Apple Developer documentation. Google id_token per `accounts.google.com` discovery doc. LinkedIn OIDC per `https://www.linkedin.com/oauth/.well-known/openid-configuration`.
3. **Real data only.** Tests use real RSA keypairs (generated via `cryptography`) and produce real OIDC-shaped JWTs. No mocked crypto. No "dummy" base64 strings substituted for tokens.
4. **No workarounds.** When a refactor is needed, refactor — do not patch around. State-verification works for both GET-with-query and POST-with-form because the helper accepts values, not requests.
5. **Naming.** File / class / function / variable names describe the responsibility. `OIDCTokenVerifier` not `JWTHelper`. `SocialIdentity` not `OAuthAccount`. `AppleClientSecretBuilder` not `AppleHelper`.
6. **Not over-engineered.** One verifier class for all OIDC providers, parameterized by `OIDCVerifierConfig`. One link service. One JWKS cache class. No inheritance hierarchies.
7. **Modular.** Each component has one file, one responsibility, one entrypoint. Apple files live in `blockauth/apple/`. OIDC verifier lives in `blockauth/utils/jwt/`. SocialIdentity lives in `blockauth/social/`.
8. **Logged.** Every state transition emits a structured log line with a stable event name (`apple.web.authorize_started`, `oidc.verify.kid_miss_refetch`, `social_identity.linked_by_verified_email`). No PII in log bodies — only `user_id`, `provider`, `event_class`. The full sensitive-field list is in §9.

## 5. Architecture

### 5.1 New code locations

```
blockauth/
├── conftest.py                          # NEW — pytest fixtures: rsa_keypair, build_id_token, jwks_payload_bytes, aes_key
├── utils/
│   ├── jwt/                             # NEW
│   │   ├── __init__.py
│   │   ├── verifier.py                  # OIDCVerifierConfig, OIDCTokenVerifier
│   │   ├── jwks_cache.py                # JWKSCache
│   │   ├── exceptions.py                # OIDCVerificationError + subclasses
│   │   └── tests/
│   │       ├── test_jwks_cache.py
│   │       └── test_verifier.py
│   ├── pkce.py                          # NEW — RFC 7636 verifier + challenge helpers
│   └── oauth_state.py                   # MODIFIED — verify_state_values pure helper, samesite override, PKCE cookie helpers
├── social/                              # NEW (durable identity link)
│   ├── __init__.py
│   ├── apps.py                          # SocialAuthConfig
│   ├── models.py                        # SocialIdentity
│   ├── service.py                       # SocialIdentityService.upsert_and_link
│   ├── linking_policy.py                # AccountLinkingPolicy.can_link_to_existing_user
│   ├── encryption.py                    # AESGCMEncryptor
│   ├── exceptions.py                    # SocialIdentityConflictError
│   ├── migrations/0001_initial.py
│   └── tests/
│       ├── test_models.py
│       ├── test_service.py
│       ├── test_linking_policy.py
│       └── test_encryption.py
├── apple/                               # NEW (Apple-only logic)
│   ├── __init__.py
│   ├── apps.py                          # AppleAuthConfig — registers pre_delete signal
│   ├── constants.py                     # AppleEndpoints, AppleClaimKeys, AppleNotificationEvents
│   ├── exceptions.py                    # AppleAuthError + subclasses
│   ├── client_secret.py                 # AppleClientSecretBuilder (ES256 JWT, lock-guarded cache)
│   ├── id_token_verifier.py             # AppleIdTokenVerifier (wraps OIDCTokenVerifier; bool-string coercion; verify_raw)
│   ├── revocation_client.py             # AppleRevocationClient (POST /auth/revoke)
│   ├── notification_service.py          # AppleNotificationService (events string-or-object dispatch)
│   ├── nonce.py                         # generate_raw_nonce, hash_raw_nonce, set/clear nonce cookie
│   ├── signals.py                       # pre_delete handler revoking Apple tokens
│   ├── views.py                         # AppleWebAuthorizeView, AppleWebCallbackView, AppleNativeVerifyView, AppleServerToServerNotificationView
│   ├── serializers.py                   # AppleNativeVerifyRequestSerializer
│   ├── docs.py                          # drf-spectacular schemas
│   └── tests/
│       ├── test_client_secret.py
│       ├── test_id_token_verifier.py
│       ├── test_revocation_client.py
│       ├── test_notification_service.py
│       ├── test_signals.py
│       ├── test_web_views.py
│       └── test_native_view.py
├── views/
│   ├── google_auth_views.py             # MODIFIED — id_token verify, SocialIdentity link, PKCE, nonce
│   ├── facebook_auth_views.py           # MODIFIED — SocialIdentity link by FB user_id, PKCE
│   ├── linkedin_auth_views.py           # MODIFIED — id_token verify (LinkedIn is OIDC since 2024), SocialIdentity, PKCE, nonce
│   ├── google_native_views.py           # NEW — GoogleNativeIdTokenVerifyView
│   └── tests/
│       ├── test_google_native_view.py   # NEW
│       └── test_oauth_views.py          # MODIFIED — covers PKCE, id_token verify, SocialIdentity flow
├── constants/
│   ├── core.py                          # MODIFIED — Features.APPLE_LOGIN, Features.GOOGLE_NATIVE_LOGIN, SocialProviders.APPLE, URLNames
│   └── sensitive_fields.py              # MODIFIED — apple-specific + OIDC fields
├── enums.py                             # MODIFIED — AuthenticationType.APPLE
├── conf.py                              # MODIFIED — Apple/Google native defaults, SocialIdentity encryption key
├── urls.py                              # MODIFIED — wire new endpoints
└── utils/
    └── social.py                        # MODIFIED — social_login_data routes through SocialIdentityService
```

### 5.2 Component contracts

#### `OIDCVerifierConfig` (frozen dataclass)

```python
@dataclass(frozen=True)
class OIDCVerifierConfig:
    issuer: str                              # exact issuer string from id_token.iss
    jwks_uri: str                            # https URL serving JWKS
    audiences: tuple[str, ...]               # accepted aud values (allowlist)
    algorithms: tuple[str, ...]              # accepted alg values (e.g. ("RS256",))
    leeway_seconds: int = 60                 # exp/iat clock skew tolerance
    require_email_claim: bool = True         # most providers send email
```

#### `OIDCTokenVerifier`

- Single public entrypoint: `verify(token: str, expected_nonce: str | None) -> dict[str, Any]`.
- Decodes the JWT header without verification to read `kid` and `alg`.
- Pins `alg` to `OIDCVerifierConfig.algorithms` — rejects mismatches before fetching keys (defends against algorithm confusion).
- Fetches the JWK by `kid` via `JWKSCache`.
- Verifies signature via `pyjwt` with `algorithms=config.algorithms`.
- Validates `iss == config.issuer` (exact, no string-prefix matching).
- Validates `aud` ∈ `config.audiences` (handles string or list `aud`).
- Validates `exp` and `iat` with leeway.
- If `expected_nonce` is provided: requires `nonce` in claims and compares with `hmac.compare_digest`.
- Returns the decoded claims dict.
- Raises specific exceptions: `IssuerMismatch`, `AudienceMismatch`, `SignatureInvalid`, `KidNotFound`, `TokenExpired`, `NonceMismatch`, `AlgorithmNotAllowed`. All subclass `OIDCVerificationError`.

#### `JWKSCache`

- Constructor: `JWKSCache(jwks_uri: str, cache_ttl_seconds: int = 3600)`.
- `get_key_for_kid(kid: str) -> dict[str, Any]` returns the JWK dict for the given kid.
- Behavior:
  - First call fetches JWKS, stores in memory keyed by kid, records fetched timestamp.
  - Subsequent calls within TTL return cached.
  - On miss for an unknown kid (provider rotated keys mid-window): refetches once, returns the fresh key, raises `KidNotFound` if still absent.
- Lock-guarded refetch (`threading.Lock`) prevents thundering herd.

#### `SocialIdentity` model

```python
class SocialIdentity(models.Model):
    provider = models.CharField(max_length=20)
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="social_identities")
    email_at_link = models.EmailField(blank=True, null=True)
    email_verified_at_link = models.BooleanField()
    encrypted_refresh_token = models.BinaryField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("provider", "subject"),)
        indexes = [models.Index(fields=["user", "provider"])]
```

The model never stores a plaintext refresh token. `encrypted_refresh_token` holds `nonce(12) || ciphertext || tag(16)` produced by `AESGCMEncryptor`.

#### `AESGCMEncryptor`

- Constructor: `AESGCMEncryptor(key: bytes)` — requires 32-byte key.
- `encrypt(plaintext: str, associated_data: bytes) -> bytes`
- `decrypt(blob: bytes, associated_data: bytes) -> str`
- AAD is `f"social_identity:{provider}:{subject}".encode()` so a ciphertext from one identity cannot be replayed onto another.

#### `AccountLinkingPolicy`

Single class with one public method:

```python
def can_link_to_existing_user(
    *,
    provider: str,
    email: str | None,
    email_verified: bool,
    extra_claims: dict[str, Any],
) -> bool: ...
```

Provider rules:
- **Google**: `email_verified == True` AND (`email` ends with `@gmail.com` OR `extra_claims.get("hd")` is non-empty). Per Google's own guidance, only Google-authoritative domains can be auto-linked.
- **Apple**: returns `False` always. Apple's email is supplied (or relayed) by the user — never authoritative for cross-provider linking. Apple identities are matched only by `(apple, sub)`. If a `User` row already exists with the same email, sign-in is rejected with HTTP 409 — the existing account-holder must explicitly link via an authenticated flow (out of scope for v0.16).
- **LinkedIn**: `email_verified == True`. LinkedIn requires email verification at signup before issuing the OIDC claim.
- **Facebook**: returns `True` only if the response includes the `email` field (Facebook returns email only when verified by the user). No `email_verified` claim because Facebook is not OIDC.

#### `SocialIdentityService`

- `upsert_and_link(provider, subject, email, email_verified, extra_claims, refresh_token=None) -> tuple[User, SocialIdentity, bool]`. Returns `(user, social_identity, created)`.
- Lookup order:
  1. `SocialIdentity.objects.filter(provider=p, subject=s)` — if found: update `last_used_at`, optionally re-encrypt new refresh token, return.
  2. `User.objects.filter(email=email)` — if found AND `AccountLinkingPolicy.can_link_to_existing_user(...)`: create `SocialIdentity` linking to existing user; emit `social_identity.linked_to_existing_user`.
  3. Found but policy rejects: raise `SocialIdentityConflictError` (HTTP 409, code 4090).
  4. Not found: create new `User` (via the existing `social_login_data` user-creation path) plus a new `SocialIdentity`.
- All operations transactional (`@transaction.atomic`).

#### `AppleClientSecretBuilder`

- Builds an ES256-signed JWT used as `client_secret` for Apple's token endpoint.
- Reads `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY_PEM` (or `APPLE_PRIVATE_KEY_PATH`), and `APPLE_SERVICES_ID` from settings.
- `build() -> str` returns a JWT with claims: `iss=team_id, iat=now, exp=now+5h, aud="https://appleid.apple.com", sub=services_id`. Header includes `kid=key_id, alg=ES256`.
- Lock-guarded in-process cache. Cached secret reused until 5 minutes before expiry, then rebuilt on next call. Apple's documented max lifetime is 6 months; 5h is the conservative working ceiling Apple recommends.

#### `AppleIdTokenVerifier`

- Composes `OIDCTokenVerifier` with Apple-specific config:
  - `issuer = "https://appleid.apple.com"` (no trailing slash)
  - `jwks_uri = "https://appleid.apple.com/auth/keys"`
  - `audiences = (services_id, *bundle_ids)` from settings
  - `algorithms = ("RS256",)`
- Adds **bool coercion**: Apple sometimes serializes `email_verified`, `is_private_email` as the strings `"true"`/`"false"`. The verifier wraps the standard claims into `AppleIdTokenClaims` and coerces these fields.
- Adds **conditional nonce verification**: when `expected_nonce` is supplied:
  - If `nonce_supported == True` in claims → require nonce match (constant-time).
  - If `nonce_supported == False` or absent → skip nonce verification (older Apple devices); log `apple.idtoken.nonce_unsupported` so integrators see the rate of legacy-device traffic.
- Provides `verify_raw(token: str, audiences: tuple[str, ...]) -> dict` for the S2S notification path, where the audience is the integrator's Services ID and there is no nonce.

#### `AppleRevocationClient`

- `revoke(refresh_token: str) -> None`.
- POSTs to `https://appleid.apple.com/auth/revoke` with `client_id`, `client_secret` (from `AppleClientSecretBuilder`), `token`, `token_type_hint=refresh_token`.
- Treats 200 as success. Logs failures structured but does not raise — deletion must continue regardless of Apple's response.

#### `AppleNotificationService`

- `dispatch(payload_jwt: str) -> AppleNotificationDispatchResult`.
- Verifies the inner JWT via `AppleIdTokenVerifier.verify_raw` against the configured Services ID.
- Reads the `events` claim; if it is a string, JSON-parses it; if dict, uses as-is.
- Switches on `events.type`:
  - `consent-revoked` → delete the `SocialIdentity` row for `(apple, sub)`.
  - `account-delete` → delete the underlying `User` if no other `SocialIdentity` rows exist; otherwise just delete the Apple `SocialIdentity` row.
  - `email-disabled` / `email-enabled` → no-op for v0.16; logged for downstream integrator hooks.
- Fires `APPLE_NOTIFICATION_TRIGGER` (configurable, default no-op).

#### OAuth state + PKCE helpers (extension to `oauth_state.py`)

New helpers added without breaking the existing API:

- `verify_state_values(cookie_state: str | None, provided_state: str | None) -> None` — pure helper, accepts any source for `provided_state` (query string or form body). Existing `verify_state(request)` becomes a thin wrapper calling this with `request.query_params`.
- `set_state_cookie` accepts an optional `samesite` parameter override (Apple form_post requires `SameSite=None; Secure` on the deployed callback hop).
- `set_pkce_verifier_cookie(response, verifier: str, samesite: str | None = None)` / `read_pkce_verifier_cookie(request) -> str | None` / `clear_pkce_verifier_cookie(response, samesite: str | None = None)` — same lifecycle as state cookie, separate cookie name `blockauth_oauth_pkce`.

#### `pkce.py`

- `generate_pkce_pair() -> tuple[str, str]` returns `(verifier, challenge)`.
  - Verifier: 32 bytes from `secrets.token_urlsafe`, length 43–128 per RFC 7636.
  - Challenge: `base64url(sha256(verifier).digest())` with no padding, per RFC 7636.

### 5.3 Auth flow walkthroughs

#### Apple Sign-In Web

```
GET /apple/                                  # AppleWebAuthorizeView
  generate state, raw_nonce, pkce_verifier
  hashed_nonce = sha256(raw_nonce).hexdigest()
  code_challenge = base64url(sha256(pkce_verifier))
  set 3 HttpOnly cookies (state, raw_nonce, pkce_verifier) with samesite="None" + secure=True
  302 to https://appleid.apple.com/auth/authorize?
      response_type=code
      response_mode=form_post
      client_id={services_id}
      scope=name email
      redirect_uri={callback_url}
      state={state}
      nonce={hashed_nonce}                 # send hash, not raw
      code_challenge={code_challenge}
      code_challenge_method=S256

POST /apple/callback/  (form_post)           # AppleWebCallbackView
  read code, state from form body
  verify_state_values(cookie_state, form_state)
  pkce_verifier = read_pkce_verifier_cookie(request)
  raw_nonce = request.COOKIES["blockauth_oauth_nonce"]
  expected_nonce = sha256(raw_nonce).hexdigest()
  client_secret = AppleClientSecretBuilder.build()
  POST https://appleid.apple.com/auth/token  (code, client_id, client_secret, code_verifier=pkce_verifier, redirect_uri, grant_type=authorization_code)
  → id_token, refresh_token, access_token
  AppleIdTokenVerifier.verify(id_token, expected_nonce=expected_nonce)
  user, identity, _ = SocialIdentityService.upsert_and_link(
      provider="apple", subject=claims.sub,
      email=claims.email, email_verified=claims.email_verified,
      extra_claims={"is_private_email": claims.is_private_email},
      refresh_token=refresh_token,
  )
  social_login_data → JWT
  clear all 3 cookies
  return JSON {access, refresh, user}
```

#### Apple Sign-In Native (iOS / macOS)

```
Client:
  raw_nonce = secure random
  request.nonce = sha256(raw_nonce).hex()
  obtains identityToken (id_token), authorizationCode (optional), name (only on first sign-in)
  POST /apple/verify/
    {
      "id_token": "...",
      "raw_nonce": "...",
      "authorization_code": "..."   (optional — server redeems for refresh_token if present)
      "first_name": "..."           (optional — only on first sign-in per Apple's contract)
      "last_name": "..."            (optional)
    }

Server (AppleNativeVerifyView):
  serializer.is_valid(raise_exception=True)
  expected_nonce = sha256(raw_nonce).hexdigest()
  AppleIdTokenVerifier.verify(id_token, expected_nonce=expected_nonce)   # conditional via nonce_supported
  if authorization_code:
      client_secret = AppleClientSecretBuilder.build()
      POST https://appleid.apple.com/auth/token (grant_type=authorization_code, code=auth_code; no PKCE on native)
      receive refresh_token
  user, identity, _ = SocialIdentityService.upsert_and_link(
      provider="apple", subject=claims.sub,
      email=claims.email, email_verified=claims.email_verified,
      extra_claims={"is_private_email": claims.is_private_email},
      refresh_token=refresh_token_or_None,
  )
  social_login_data → JWT
  return JSON {access, refresh, user}
```

#### Google Native id_token verify

```
Client (Android Credential Manager / iOS Google SDK / Web One Tap):
  raw_nonce = secure random
  hashed_nonce = sha256(raw_nonce).hex()
  passes hashed_nonce as nonce param to platform SDK
    (Android: GetGoogleIdOption.Builder.setNonce; iOS: similar; Web One Tap: data-nonce)
  obtains id_token from Google identity service
  POST /google/native/verify/
    {"id_token": "...", "raw_nonce": "..."}

Server (GoogleNativeIdTokenVerifyView):
  serializer.is_valid(raise_exception=True)
  expected_nonce = sha256(raw_nonce).hexdigest()
  OIDCTokenVerifier(google_native_config).verify(id_token, expected_nonce=expected_nonce)
  user, identity, _ = SocialIdentityService.upsert_and_link(
      provider="google", subject=claims["sub"],
      email=claims.get("email"), email_verified=bool(claims.get("email_verified")),
      extra_claims={"hd": claims.get("hd"), "azp": claims.get("azp")},
  )
  social_login_data → JWT
  return JSON {access, refresh, user}
```

Audience for Google Native = the **Web (server) OAuth client ID** (the value clients pass to `setServerClientId`). The `azp` claim carries the Android/iOS client ID; captured in `extra_claims` but not enforced at the verifier.

#### Refactored Google Web

```
GET /google/                                 # GoogleAuthLoginView
  generate state, raw_nonce, pkce_verifier
  hashed_nonce = sha256(raw_nonce).hexdigest()
  code_challenge = base64url(sha256(pkce_verifier))
  set 3 cookies (state, raw_nonce, pkce_verifier)
  302 to Google authorize with:
      state, nonce=hashed_nonce, code_challenge, code_challenge_method=S256

GET /google/callback/                        # GoogleAuthCallbackView
  verify_state_values(cookie_state, query_state)
  pkce_verifier = read_pkce_verifier_cookie(request)
  expected_nonce = sha256(request.COOKIES["blockauth_oauth_nonce"]).hexdigest()
  POST Google token endpoint (code + code_verifier=pkce_verifier)
  → id_token, access_token (refresh_token absent for web flow without offline access)
  OIDCTokenVerifier(google_web_config).verify(id_token, expected_nonce=expected_nonce)
  # userinfo HTTP call removed — claims come from verified id_token
  user, identity, _ = SocialIdentityService.upsert_and_link(
      "google", sub, email, email_verified, extra_claims={"hd": ...},
  )
  social_login_data → JWT
  clear cookies; return JSON
```

#### Refactored LinkedIn Web

Same structure as Google Web but with LinkedIn's OIDC discovery values (issuer `https://www.linkedin.com`, JWKS `https://www.linkedin.com/oauth/openid/jwks`, audience = LinkedIn client ID, algorithms `("RS256",)`). Userinfo HTTP call dropped. PKCE + nonce added.

#### Refactored Facebook Web

Facebook is not OIDC. The flow keeps:
- Authorize → callback → token exchange with PKCE (Facebook supports PKCE).
- Graph API call to `/me?fields=id,name,email` for user info (Facebook does not return id_tokens on the standard flow).
- Match by `(provider="facebook", subject=user_info["id"])` via `SocialIdentityService` instead of email.
- `email_verified` is inferred as `True` if Facebook returns the `email` field at all (Facebook only includes email when verified).

### 5.4 Migration impact on existing data

| Object | Effect |
|---|---|
| `User` model | **No change** — no columns added, removed, or altered. |
| Existing `User` rows | **Untouched** — no backfill, no migration data step. |
| `SocialIdentity` table | **NEW**, created empty. Populated forward as users sign in via OAuth. |
| `authentication_types` JSONField | Unchanged behavior — providers continue to be appended on each social login (existing `social_login_data` code path). |
| Forgot-password for OAuth-created users | Unchanged — OAuth-created users have unusable password by Django default; password reset confirmation calls `set_password` which makes the password usable; subsequent email/password login works. |
| Email/password / passwordless / wallet flows | Unchanged. |

There is no schema migration on existing tables, no `ALTER TABLE` on `User`, and no data backfill. The only migration is `social/migrations/0001_initial.py` which creates the `social_identity` table.

### 5.5 Cross-provider behavior with the same email

For an end-user with `pramod@gmail.com` registered at all four providers, signing in via any of them lands on the **same `User.id`** because:

| Provider | Linking decision for first cross-provider login |
|---|---|
| Google (first) | Creates `User(email=pramod@gmail.com)` + `SocialIdentity(google, sub_g)`. |
| Apple (later) | `SocialIdentity(apple, sub_a)` not found. `AccountLinkingPolicy` returns `False` for Apple → 4090 conflict unless the existing account-holder explicitly links (deferred). |
| LinkedIn (later) | LinkedIn `email_verified=true` → policy returns `True` → links to existing user. New `SocialIdentity(linkedin, sub_l)` row. |
| Facebook (later) | Email present → policy returns `True` → links. New `SocialIdentity(facebook, fb_id)` row. |

The Apple gap is intentional: Apple's email is user-supplied and not authoritative. Without an explicit link UX, auto-linking by email risks pre-account-takeover. We document this; v0.17 adds the authenticated link endpoint.

## 6. API Endpoints

| Method | Path | Feature flag | Description |
|---|---|---|---|
| GET | `apple/` | `APPLE_LOGIN` | Initiate Apple web flow (302 to Apple authorize) |
| POST | `apple/callback/` | `APPLE_LOGIN` | Apple form_post callback handler |
| POST | `apple/verify/` | `APPLE_LOGIN` | Native id_token verify (iOS / macOS) |
| POST | `apple/notifications/` | `APPLE_LOGIN` | Server-to-server notifications webhook |
| POST | `google/native/verify/` | `GOOGLE_NATIVE_LOGIN` | Native id_token verify (Android / iOS / Web One Tap) |
| GET | `google/` | `SOCIAL_AUTH` | **Refactored** Google web flow (id_token verify, PKCE, nonce, SocialIdentity) |
| GET | `google/callback/` | `SOCIAL_AUTH` | **Refactored** Google web callback |
| GET | `linkedin/` | `SOCIAL_AUTH` | **Refactored** LinkedIn web flow (OIDC) |
| GET | `linkedin/callback/` | `SOCIAL_AUTH` | **Refactored** LinkedIn web callback |
| GET | `facebook/` | `SOCIAL_AUTH` | **Refactored** Facebook web flow (PKCE + SocialIdentity) |
| GET | `facebook/callback/` | `SOCIAL_AUTH` | **Refactored** Facebook web callback |

Existing endpoints (signup, login/basic, login/passwordless, login/wallet, token/refresh, password/reset, password/change, email/change, wallet/email/add, wallet/link, passkey/*, totp/*) are unchanged.

## 7. Configuration additions (`BLOCK_AUTH_SETTINGS`)

```python
# Apple Sign-In
"APPLE_TEAM_ID": "<Apple developer team ID>",
"APPLE_KEY_ID": "<Apple Sign-In key ID>",
"APPLE_PRIVATE_KEY_PEM": None,                 # one of these two must be set
"APPLE_PRIVATE_KEY_PATH": None,
"APPLE_SERVICES_ID": "<Services ID for web flow>",
"APPLE_BUNDLE_IDS": (),                        # tuple of bundle IDs for native iOS / macOS
"APPLE_REDIRECT_URI": "<https URL for /apple/callback/>",
"APPLE_NOTIFICATION_TRIGGER": None,            # optional dotted path for integrator hook
"APPLE_CALLBACK_COOKIE_SAMESITE": "None",      # form_post requires None+Secure on deployed TLS

# Google native
"GOOGLE_NATIVE_AUDIENCES": (),                 # tuple of web client IDs accepted in id_token.aud

# Generic OIDC verifier
"OIDC_JWKS_CACHE_TTL_SECONDS": 3600,
"OIDC_VERIFIER_LEEWAY_SECONDS": 60,

# SocialIdentity refresh-token-at-rest
"SOCIAL_IDENTITY_ENCRYPTION_KEY": None,        # base64-encoded 32 bytes; required when refresh tokens are stored
```

## 8. Error codes

Errors use the existing `ValidationErrorWithCode` mechanism (`code` in `4XXX` range).

| Code | Reason |
|---|---|
| 4050 | Apple state mismatch |
| 4051 | Apple PKCE verifier missing |
| 4052 | Apple token exchange failed |
| 4053 | Apple id_token signature invalid |
| 4054 | Apple id_token claim invalid (iss/aud/exp) |
| 4055 | Apple nonce mismatch (when `nonce_supported=true`) |
| 4056 | Apple S2S notification verification failed |
| 4057 | Apple revocation request failed (logged; not user-visible) |
| 4060 | Google native id_token signature invalid |
| 4061 | Google native id_token claim invalid (iss/aud/exp) or nonce mismatch |
| 4062 | Google native raw_nonce missing |
| 4070 | LinkedIn id_token verification failed |
| 4080 | Facebook user_info missing required fields |
| 4090 | Social identity conflict — email already linked to another user with non-authoritative provider |

## 9. Logging

All log lines use the existing `blockauth_logger` and a stable `event` key.

| Event | Logged context (no PII beyond user_id and provider) |
|---|---|
| `oidc.verify.started` | `provider`, `audience` |
| `oidc.verify.kid_miss_refetch` | `provider`, `kid` |
| `oidc.verify.signature_invalid` | `provider`, `kid`, `error_class` |
| `apple.web.authorize_started` | `client_id_suffix` (last 6 chars only) |
| `apple.web.callback_received` | `state_match: bool` |
| `apple.web.token_exchange_failed` | `status_code`, `error_class` |
| `apple.native.verify_started` | (no PII) |
| `apple.idtoken.nonce_unsupported` | (Apple device returned `nonce_supported=false`) |
| `apple.revocation.requested` | `provider="apple"`, `user_id` |
| `apple.revocation.failed` | `status_code` |
| `apple.notification.received` | `event_type` |
| `apple.notification.account_deleted` | `user_id` |
| `social_identity.matched_existing_subject` | `provider`, `user_id` |
| `social_identity.linked_to_existing_user` | `provider`, `user_id`, `linking_reason` |
| `social_identity.created_new_user` | `provider`, `user_id` |
| `social_identity.linking_rejected_unverified_email` | `provider`, `email_domain_only` |

`SENSITIVE_FIELDS` is extended to include: `id_token`, `refresh_token`, `client_secret`, `code_verifier`, `raw_nonce`, `nonce`, `authorization_code`, `code`, `apple_private_key_pem`, `payload`.

## 10. Testing approach

- **Real RSA keypairs** generated per-test-class using `cryptography.hazmat.primitives.asymmetric.rsa`. Fixtures live at `blockauth/conftest.py` so they're visible to every sub-package's test directory.
- **No mocking of `pyjwt`** — sign and verify with real keys end-to-end.
- **HTTP mocking** uses `unittest.mock.patch` on `requests.get` / `requests.post` to match the existing test style in `blockauth/views/tests/test_oauth_views.py`.
- **Encryption** tested with real AES-GCM (no mocks).
- **Apple S2S notification** tests use real signed JWTs with the test RSA key, configured as Apple's JWKS URI returning that key.
- **Account linking policy** tested per-provider with a parameterized truth table covering the 4 providers × `{email_verified=true, false}` × `{email match, no match}` × `{hd present, absent}`.

Tests do not use:
- "fake_token", "test123", "dummy_kid" string substitutes for real cryptographic material.
- Hardcoded JWTs from third-party blogs.
- Skipped/xfail markers — every test must pass.

## 11. Versioning

`pyproject.toml` and `blockauth/__init__.py` bump 0.15.0 → 0.16.0. CHANGELOG entry summarizes the new endpoints + the refactor + the schema delta.

## 12. Out-of-scope follow-ups

- Authenticated **link account** endpoint (v0.17) — when a logged-in user wants to link a new social identity (covers the Apple-email collision path).
- **Facebook Limited Login** (iOS/Android OIDC) — separate endpoint.
- **Microsoft Identity Platform** OIDC integration.
- **GitHub OAuth.** GitHub is non-OIDC; PKCE is now supported.
- **Step-up re-auth on link** — passkey/TOTP via `blockauth.stepup`.
- **Notification audit log** — store the JWT IDs of processed Apple S2S notifications for replay safety.
