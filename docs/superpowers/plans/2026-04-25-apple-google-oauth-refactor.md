# Apple Sign-In, Google Native, and OAuth Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Apple Sign-In (web + native + revocation + S2S notifications), Google native id_token verification (Android Credential Manager / iOS / Web One Tap), a generic `OIDCTokenVerifier` reused across providers, a `SocialIdentity` model with provider-aware account linking, and refactor Google / LinkedIn / Facebook web flows onto the new foundation.

**Architecture:** New code lives in three sub-packages (`blockauth/utils/jwt/`, `blockauth/social/`, `blockauth/apple/`) plus a new `views/google_native_views.py`. Existing OAuth views are modified in place to consume `OIDCTokenVerifier` and `SocialIdentityService`. PKCE (RFC 7636) is added to all web flows. The only schema change is one additive table (`social_identity`) — no `User` columns added.

**Tech Stack:** Python 3.12, Django 5+, DRF, PyJWT 2.8+, `cryptography` 46+, `requests`, `pytest`, `pytest-django`.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `blockauth/conftest.py` | Create | Shared pytest fixtures (RSA keypair, build_id_token, jwks_payload_bytes, aes_key) |
| `blockauth/utils/jwt/__init__.py` | Create | Public exports: `OIDCVerifierConfig`, `OIDCTokenVerifier`, `JWKSCache`, `OIDCVerificationError` |
| `blockauth/utils/jwt/exceptions.py` | Create | `OIDCVerificationError`, `IssuerMismatch`, `AudienceMismatch`, `SignatureInvalid`, `KidNotFound`, `TokenExpired`, `NonceMismatch`, `AlgorithmNotAllowed` |
| `blockauth/utils/jwt/jwks_cache.py` | Create | `JWKSCache` with TTL + lock-guarded refetch on kid miss |
| `blockauth/utils/jwt/verifier.py` | Create | `OIDCVerifierConfig`, `OIDCTokenVerifier.verify` |
| `blockauth/utils/jwt/tests/test_jwks_cache.py` | Create | Cache behavior, kid rotation, lock-guarded refetch |
| `blockauth/utils/jwt/tests/test_verifier.py` | Create | iss/aud/exp/nonce/alg pinning |
| `blockauth/utils/pkce.py` | Create | `generate_pkce_pair`, RFC 7636 S256 |
| `blockauth/utils/oauth_state.py` | Modify | `verify_state_values` pure helper, samesite override, PKCE cookie helpers |
| `blockauth/social/__init__.py` | Create | Exports `SocialIdentity`, `SocialIdentityService`, `SocialIdentityConflictError` |
| `blockauth/social/apps.py` | Create | `SocialAuthConfig` Django AppConfig |
| `blockauth/social/models.py` | Create | `SocialIdentity` model |
| `blockauth/social/encryption.py` | Create | `AESGCMEncryptor` |
| `blockauth/social/linking_policy.py` | Create | `AccountLinkingPolicy.can_link_to_existing_user` |
| `blockauth/social/exceptions.py` | Create | `SocialIdentityConflictError` |
| `blockauth/social/service.py` | Create | `SocialIdentityService.upsert_and_link` |
| `blockauth/social/migrations/0001_initial.py` | Create | `social_identity` table creation |
| `blockauth/social/tests/test_*.py` | Create | Model, service, encryption, linking policy tests |
| `blockauth/apple/__init__.py` | Create | Public exports |
| `blockauth/apple/apps.py` | Create | `AppleAuthConfig` — registers pre_delete signal |
| `blockauth/apple/constants.py` | Create | `AppleEndpoints`, `AppleClaimKeys`, `AppleNotificationEvents` |
| `blockauth/apple/exceptions.py` | Create | `AppleAuthError` + subclasses |
| `blockauth/apple/client_secret.py` | Create | `AppleClientSecretBuilder` |
| `blockauth/apple/id_token_verifier.py` | Create | `AppleIdTokenVerifier`, `AppleIdTokenClaims` |
| `blockauth/apple/revocation_client.py` | Create | `AppleRevocationClient.revoke` |
| `blockauth/apple/notification_service.py` | Create | `AppleNotificationService.dispatch` |
| `blockauth/apple/nonce.py` | Create | `generate_raw_nonce`, `hash_raw_nonce`, cookie helpers |
| `blockauth/apple/signals.py` | Create | `pre_delete` handler invoking `AppleRevocationClient` |
| `blockauth/apple/views.py` | Create | `AppleWebAuthorizeView`, `AppleWebCallbackView`, `AppleNativeVerifyView`, `AppleServerToServerNotificationView` |
| `blockauth/apple/serializers.py` | Create | `AppleNativeVerifyRequestSerializer`, `AppleServerToServerNotificationRequestSerializer` |
| `blockauth/apple/docs.py` | Create | drf-spectacular `extend_schema` definitions |
| `blockauth/apple/tests/test_*.py` | Create | Per-component tests |
| `blockauth/views/google_native_views.py` | Create | `GoogleNativeIdTokenVerifyView` |
| `blockauth/views/google_auth_views.py` | Modify | Add PKCE+nonce+id_token verify+SocialIdentity linkage |
| `blockauth/views/linkedin_auth_views.py` | Modify | OIDC discovery + id_token verify + PKCE + nonce + SocialIdentity |
| `blockauth/views/facebook_auth_views.py` | Modify | PKCE + SocialIdentity (Graph API stays) |
| `blockauth/views/tests/test_google_native_view.py` | Create | Endpoint tests |
| `blockauth/views/tests/test_oauth_views.py` | Modify | Updated to cover PKCE / id_token verify / SocialIdentity flow |
| `blockauth/constants/core.py` | Modify | `Features.APPLE_LOGIN`, `Features.GOOGLE_NATIVE_LOGIN`, `SocialProviders.APPLE`, `URLNames.*` |
| `blockauth/constants/sensitive_fields.py` | Modify | Add new sensitive field names |
| `blockauth/enums.py` | Modify | `AuthenticationType.APPLE` |
| `blockauth/conf.py` | Modify | New defaults: Apple, Google native, OIDC, SocialIdentity encryption |
| `blockauth/urls.py` | Modify | Wire new endpoints |
| `blockauth/utils/social.py` | Modify | `social_login_data` consumes `SocialIdentityService` |
| `pyproject.toml` | Modify | Bump version to 0.16.0 |
| `blockauth/__init__.py` | Modify | Bump `__version__` to 0.16.0 |
| `CHANGELOG.md` | Modify | 0.16.0 entry |

---

## Conventions

### Naming

- Verifier classes end in `Verifier`. Service classes end in `Service`. Builders end in `Builder`. Caches end in `Cache`. Errors end in `Error`.
- Sub-packages are lowercase, single-word (`apple`, `social`).
- Test modules are named `test_<file_under_test>.py` and live in a sibling `tests/` directory.

### Logging

- Use the existing `blockauth_logger` (`blockauth/utils/logger.py`).
- Every state transition logs with a stable `event` key (e.g. `"oidc.verify.started"`).
- Log context never includes: full email, plaintext token, raw nonce, refresh token, client secret, or claim values besides those listed in the spec §9 table.

### Testing

- TDD: write the failing test first, run it, see it fail with the expected error, then implement.
- Real RSA keypairs from `cryptography.hazmat.primitives.asymmetric.rsa`. No mocked crypto.
- HTTP requests mocked via `unittest.mock.patch` on `requests.get` / `requests.post` (matches existing `blockauth/views/tests/test_oauth_views.py` style).
- Run a single test: `uv run pytest <path>::<test_name> -v`.
- Run a phase's tests: `uv run pytest blockauth/<sub_package>/tests -v`.

### Commits

- Each task ends in a commit. Prefix follows existing style (`feat:`, `feat(apple):`, `refactor(google):`, `test:`, `chore:`).
- One logical change per commit.

---

## Phase 0: Branch baseline

### Task 0.1: Confirm branch + dependencies

**Files:** none modified — verification only.

- [ ] **Step 1: Verify current branch**

Run: `git rev-parse --abbrev-ref HEAD`
Expected: `feat/apple-google-oauth-refactor`

- [ ] **Step 2: Verify clean tree on a known commit**

Run: `git status --short`
Expected: only working-tree modifications you brought with you (e.g. local CLAUDE.md). No staged changes.

- [ ] **Step 3: Verify dependencies present**

Run: `uv run python -c "import jwt, cryptography, requests, rest_framework, django; print(jwt.__version__, cryptography.__version__, django.__version__)"`
Expected: PyJWT >= 2.8, cryptography >= 46.0.5, Django >= 5.0.

- [ ] **Step 4: Run baseline test suite**

Run: `uv run pytest -x -q`
Expected: all tests pass on the branch baseline.

---

## Phase 1: OIDC token verifier foundation

This phase produces `JWKSCache` and `OIDCTokenVerifier`. Every later phase that touches an OIDC provider depends on these.

### Task 1.1: Sub-package skeleton + shared test fixtures

**Files:**
- Create: `blockauth/conftest.py`
- Create: `blockauth/utils/jwt/__init__.py`
- Create: `blockauth/utils/jwt/exceptions.py`
- Create: `blockauth/utils/jwt/tests/__init__.py`

- [ ] **Step 1: Create `blockauth/utils/jwt/exceptions.py`**

```python
"""OIDC verification errors.

Each subclass corresponds to one specific failure mode so callers can branch on
class without inspecting message strings.
"""


class OIDCVerificationError(Exception):
    """Base class for every failure inside `OIDCTokenVerifier.verify`."""


class IssuerMismatch(OIDCVerificationError):
    pass


class AudienceMismatch(OIDCVerificationError):
    pass


class SignatureInvalid(OIDCVerificationError):
    pass


class KidNotFound(OIDCVerificationError):
    pass


class TokenExpired(OIDCVerificationError):
    pass


class NonceMismatch(OIDCVerificationError):
    pass


class AlgorithmNotAllowed(OIDCVerificationError):
    pass
```

- [ ] **Step 2: Create `blockauth/utils/jwt/__init__.py`**

> **Note:** This task ships an intermediate `__init__.py` that does NOT yet
> import `JWKSCache` or the verifier (those modules don't exist yet). Task 1.3
> adds `JWKSCache` to this file; Task 1.5 adds `OIDCTokenVerifier` and
> `OIDCVerifierConfig`. The final `__all__` (after Task 1.5) is:
>
> ```python
> __all__ = [
>     "AlgorithmNotAllowed", "AudienceMismatch", "IssuerMismatch",
>     "JWKSCache", "JWKSUnreachable", "KidNotFound", "NonceMismatch",
>     "OIDCTokenVerifier", "OIDCVerificationError", "OIDCVerifierConfig",
>     "SignatureInvalid", "TokenExpired",
> ]
> ```

```python
from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    KidNotFound,
    NonceMismatch,
    OIDCVerificationError,
    SignatureInvalid,
    TokenExpired,
)

__all__ = [
    "AlgorithmNotAllowed",
    "AudienceMismatch",
    "IssuerMismatch",
    "KidNotFound",
    "NonceMismatch",
    "OIDCVerificationError",
    "SignatureInvalid",
    "TokenExpired",
]
```

- [ ] **Step 3: Create `blockauth/utils/jwt/tests/__init__.py`** (empty file)

```python
```

- [ ] **Step 4: Create `blockauth/conftest.py` with shared OIDC + AES fixtures**

```python
"""Package-level pytest fixtures.

Exposes real RSA keypairs and a token-builder helper so any sub-package's tests
can produce signed JWTs without re-implementing the boilerplate.

Living at the package root means the fixtures are auto-discovered by
`blockauth/utils/jwt/tests/`, `blockauth/social/tests/`, `blockauth/apple/tests/`,
and `blockauth/views/tests/` without per-directory duplication.
"""

import base64
import json
import secrets
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session")
def rsa_keypair():
    """Return (private_pem_str, public_pem_str, kid)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    kid = "test-kid-" + secrets.token_hex(4)
    return private_pem, public_pem, kid


@pytest.fixture(scope="session")
def jwks_payload_bytes(rsa_keypair):
    """Return JWKS JSON bytes for the test public key, suitable as an HTTP body."""
    _, public_pem, kid = rsa_keypair
    public_key = serialization.load_pem_public_key(public_pem.encode())
    numbers = public_key.public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
        "e": base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode(),
    }
    return json.dumps({"keys": [jwk]}).encode()


@pytest.fixture
def build_id_token(rsa_keypair):
    """Factory: build an RS256-signed JWT with arbitrary claims and the test kid."""
    private_pem, _, kid = rsa_keypair

    def _build(claims: dict[str, Any], kid_override: str | None = None) -> str:
        defaults = {"iat": int(time.time()), "exp": int(time.time()) + 600}
        merged = {**defaults, **claims}
        return pyjwt.encode(
            merged,
            private_pem,
            algorithm="RS256",
            headers={"kid": kid_override or kid},
        )

    return _build


@pytest.fixture
def aes_key():
    """32-byte AES-GCM key for SocialIdentity encryption tests."""
    return secrets.token_bytes(32)
```

- [ ] **Step 5: Verify fixture import works**

Run: `uv run python -c "from blockauth.utils.jwt import OIDCVerificationError; print('ok')"`

Expected output:
```
Traceback (most recent call last):
  ...
ModuleNotFoundError: No module named 'blockauth.utils.jwt.jwks_cache'
```

This failure is expected — we have not yet created `jwks_cache.py` or `verifier.py`. Proceed to Task 1.2.

- [ ] **Step 6: Commit**

```bash
git add blockauth/conftest.py blockauth/utils/jwt/__init__.py blockauth/utils/jwt/exceptions.py blockauth/utils/jwt/tests/__init__.py
git commit -m "feat(oidc): scaffold OIDC verifier sub-package with exceptions and shared fixtures"
```

### Task 1.2: `JWKSCache` — failing test

**Files:**
- Test: `blockauth/utils/jwt/tests/test_jwks_cache.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""Tests for JWKSCache.

Strategy: stub `requests.get` to return real JWKS JSON bytes (from the session
`jwks_payload_bytes` fixture) and assert cache hit/miss behavior.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from blockauth.utils.jwt.exceptions import KidNotFound
from blockauth.utils.jwt.jwks_cache import JWKSCache


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock()
    response.status_code = 200
    response.content = jwks_payload_bytes
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


def test_first_call_fetches_jwks(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        key = cache.get_key_for_kid(kid)
    assert key["kid"] == kid
    assert mock_get.call_count == 1


def test_second_call_within_ttl_uses_cache(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json", cache_ttl_seconds=3600)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        cache.get_key_for_kid(kid)
        cache.get_key_for_kid(kid)
    assert mock_get.call_count == 1


def test_unknown_kid_triggers_one_refetch(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        cache.get_key_for_kid(kid)
        with pytest.raises(KidNotFound):
            cache.get_key_for_kid("rotated-kid-not-present")
    assert mock_get.call_count == 2


def test_unknown_kid_succeeds_when_refetch_returns_it(jwks_payload_bytes, rsa_keypair):
    _, _, kid = rsa_keypair
    rotated_jwks = json.loads(jwks_payload_bytes.decode())
    rotated_jwks["keys"][0]["kid"] = "rotated-kid-1"
    rotated_response = MagicMock()
    rotated_response.status_code = 200
    rotated_response.content = json.dumps(rotated_jwks).encode()
    rotated_response.json.return_value = rotated_jwks
    initial_response = MagicMock()
    initial_response.status_code = 200
    initial_response.json.return_value = {"keys": [{"kid": "old-kid", "kty": "RSA", "n": "x", "e": "AQAB"}]}

    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=[initial_response, rotated_response],
    ) as mock_get:
        cache.get_key_for_kid("old-kid")
        key = cache.get_key_for_kid("rotated-kid-1")
    assert key["kid"] == "rotated-kid-1"
    assert mock_get.call_count == 2


def test_jwks_fetch_failure_raises():
    """Non-200 from JWKS endpoint surfaces as JWKSUnreachable AND preserves (empty) cache state."""
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    failing_response = MagicMock(status_code=500)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=failing_response):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid("any-kid")
    # Cache state untouched — no spurious "fresh empty cache" pinning.
    assert cache._keys_by_kid == {}
    assert cache._fetched_at == 0.0


def test_transient_5xx_preserves_previously_cached_keys(jwks_payload_bytes, rsa_keypair):
    """A 5xx after a successful fetch must not wipe the cache or bump _fetched_at.

    Without this, a transient IdP outage would mark the empty cache as fresh and
    starve legitimate verifications for the entire TTL window.
    """
    _, _, kid = rsa_keypair
    initial_response = MagicMock()
    initial_response.status_code = 200
    initial_response.json.return_value = json.loads(jwks_payload_bytes.decode())
    failing_response = MagicMock(status_code=503)

    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=[initial_response, failing_response],
    ):
        cache.get_key_for_kid(kid)  # populates cache
        cache._fetched_at = 0.0  # force the cache to look stale so the next call attempts a fetch
        with pytest.raises((KidNotFound, JWKSUnreachable)):
            cache.get_key_for_kid("unknown-kid-rotation-attempt")

    # Original kid still recoverable; _keys_by_kid was not wiped.
    assert cache._keys_by_kid.get(kid) is not None
    # _fetched_at was not bumped by the failed fetch (still the value we forced).
    assert cache._fetched_at == 0.0


def test_network_error_does_not_propagate_raw(rsa_keypair):
    """RequestException from requests.get must surface as JWKSUnreachable, not raw exception."""
    import requests as _requests

    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=_requests.exceptions.ConnectionError("DNS failure"),
    ):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid(kid)
```

> **Note:** `JWKSUnreachable` is also imported at the top of this test module
> alongside `KidNotFound` (added by Task 1.3 alongside the exception split).

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/utils/jwt/tests/test_jwks_cache.py -v`
Expected: collection error with `ModuleNotFoundError: No module named 'blockauth.utils.jwt.jwks_cache'`.

### Task 1.3: `JWKSCache` — implementation

**Files:**
- Create: `blockauth/utils/jwt/jwks_cache.py`

- [ ] **Step 1: Implement `JWKSCache`**

```python
"""JWKS cache with rotation-on-kid-miss behavior.

Caches the keys fetched from a provider's JWKS endpoint. On a cache miss for an
unknown `kid` (e.g. provider rotated keys mid-window), refetches once and looks
again before reporting failure. Uses a threading lock to serialize concurrent
refetches so a thundering herd never multiplies the upstream call rate.

Failure policy: a transport-level failure (network error or non-200) leaves
`_keys_by_kid` and `_fetched_at` untouched. This avoids the failure mode where
a single transient 5xx wipes a working cache *and* marks the empty cache as
"fresh" for the entire TTL window. Surfaces as `JWKSUnreachable` when no key
is available; `KidNotFound` is reserved for "endpoint reachable, kid absent".
"""

import logging
import threading
import time
from typing import Any

import requests

from blockauth.utils.jwt.exceptions import JWKSUnreachable, KidNotFound

logger = logging.getLogger(__name__)


class JWKSCache:
    def __init__(self, jwks_uri: str, cache_ttl_seconds: int = 3600):
        self._jwks_uri = jwks_uri
        self._cache_ttl_seconds = cache_ttl_seconds
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def get_key_for_kid(self, kid: str) -> dict[str, Any]:
        cached = self._keys_by_kid.get(kid)
        if cached is not None and self._is_fresh():
            return cached

        with self._lock:
            cached = self._keys_by_kid.get(kid)
            if cached is not None and self._is_fresh():
                return cached

            # `last_fetch_ok` defaults True so the kid-miss-refetch branch below
            # still fires when the cache was simply fresh-but-missing-this-kid.
            last_fetch_ok = True
            if not self._is_fresh():
                last_fetch_ok = self._fetch_and_store()
                cached = self._keys_by_kid.get(kid)
                if cached is not None:
                    return cached
                # If the stale-refresh fetch itself failed, do not immediately
                # hammer the upstream again — short-circuit to JWKSUnreachable.
                if not last_fetch_ok:
                    raise JWKSUnreachable(
                        f"JWKS at {self._jwks_uri} unreachable; cannot resolve kid {kid!r}"
                    )

            logger.info("oidc.verify.kid_miss_refetch", extra={"kid": kid})
            last_fetch_ok = self._fetch_and_store()
            cached = self._keys_by_kid.get(kid)
            if cached is not None:
                return cached

            if not last_fetch_ok:
                raise JWKSUnreachable(
                    f"JWKS at {self._jwks_uri} unreachable; cannot resolve kid {kid!r}"
                )
            logger.warning(
                "oidc.verify.kid_not_found",
                extra={"kid": kid, "jwks_uri": self._jwks_uri},
            )
            raise KidNotFound(f"kid {kid!r} not present in JWKS at {self._jwks_uri}")

    def _is_fresh(self) -> bool:
        return (time.time() - self._fetched_at) < self._cache_ttl_seconds

    def _fetch_and_store(self) -> bool:
        """Fetch JWKS and update cache.

        Returns True if a fresh response was successfully consumed (200 or 304),
        False on any failure. On failure, `_keys_by_kid` and `_fetched_at` are
        left unchanged so a transient outage cannot evict a working cache.
        """
        try:
            response = requests.get(self._jwks_uri, timeout=10)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "oidc.jwks.fetch_failed",
                extra={
                    "jwks_uri": self._jwks_uri,
                    "error_class": exc.__class__.__name__,
                },
            )
            return False

        # 304 path is unreachable today (we send no conditional headers) but
        # coding it correctly now avoids a regression once ETag /
        # If-Modified-Since support is added.
        if response.status_code == 304:
            self._fetched_at = time.time()
            return True

        if response.status_code != 200:
            logger.warning(
                "oidc.jwks.fetch_failed",
                extra={
                    "jwks_uri": self._jwks_uri,
                    "status_code": response.status_code,
                },
            )
            return False

        payload = response.json()
        self._keys_by_kid = {jwk["kid"]: jwk for jwk in payload.get("keys", []) if "kid" in jwk}
        self._fetched_at = time.time()
        return True
```

- [ ] **Step 2: Run tests, verify they pass**

Run: `uv run pytest blockauth/utils/jwt/tests/test_jwks_cache.py -v`
Expected: 7 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/utils/jwt/jwks_cache.py blockauth/utils/jwt/tests/test_jwks_cache.py
git commit -m "feat(oidc): JWKSCache with TTL and rotation-on-kid-miss refetch"
```

### Task 1.4: `OIDCTokenVerifier` — failing test

**Files:**
- Test: `blockauth/utils/jwt/tests/test_verifier.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""End-to-end tests for OIDCTokenVerifier.

Generates real RS256 tokens with the session RSA keypair, stubs JWKS HTTP, and
asserts each failure mode raises the corresponding subclass of
OIDCVerificationError.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
    SignatureInvalid,
    TokenExpired,
)
from blockauth.utils.jwt.verifier import OIDCTokenVerifier, OIDCVerifierConfig


@pytest.fixture
def google_config():
    return OIDCVerifierConfig(
        issuer="https://accounts.google.com",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        audiences=("123-web.apps.googleusercontent.com",),
        algorithms=("RS256",),
    )


@pytest.fixture
def patch_requests_get(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=response):
        yield


def test_verify_ok(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "user-1", "email": "u@example.com"}
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert claims["sub"] == "user-1"


def test_issuer_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://evil.example", "aud": "123-web.apps.googleusercontent.com", "sub": "x"}
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(IssuerMismatch):
        verifier.verify(token, expected_nonce=None)


def test_audience_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "different.apps.googleusercontent.com", "sub": "x"}
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(AudienceMismatch):
        verifier.verify(token, expected_nonce=None)


def test_expired_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "x",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(TokenExpired):
        verifier.verify(token, expected_nonce=None)


def test_nonce_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "x",
            "nonce": "AAAA",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(NonceMismatch):
        verifier.verify(token, expected_nonce="BBBB")


def test_algorithm_not_allowed_raises(google_config, patch_requests_get):
    import jwt as pyjwt

    token = pyjwt.encode({"iss": "https://accounts.google.com"}, "shared-secret", algorithm="HS256")
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(AlgorithmNotAllowed):
        verifier.verify(token, expected_nonce=None)


def test_signature_invalid_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "x"}
    )
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(SignatureInvalid):
        verifier.verify(tampered, expected_nonce=None)


def test_aud_as_list_accepted(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": ["123-web.apps.googleusercontent.com", "other"],
            "sub": "x",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert "123-web.apps.googleusercontent.com" in (claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]])
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/utils/jwt/tests/test_verifier.py -v`
Expected: collection error with `ModuleNotFoundError: No module named 'blockauth.utils.jwt.verifier'`.

### Task 1.5: `OIDCTokenVerifier` — implementation

**Files:**
- Create: `blockauth/utils/jwt/verifier.py`

- [ ] **Step 1: Implement `OIDCVerifierConfig` and `OIDCTokenVerifier`**

```python
"""Generic OIDC id_token verifier.

Pins algorithms before signature work to defend against algorithm confusion.
Looks up signing keys via JWKSCache so every supported provider shares one
rotation-aware key cache. Returns decoded claims on success; raises a specific
OIDCVerificationError subclass on each distinct failure mode.
"""

import hmac
import logging
from dataclasses import dataclass

import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
    SignatureInvalid,
    TokenExpired,
)
from blockauth.utils.jwt.jwks_cache import JWKSCache

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OIDCVerifierConfig:
    issuer: str
    jwks_uri: str
    audiences: tuple[str, ...]
    algorithms: tuple[str, ...]
    leeway_seconds: int = 60
    require_email_claim: bool = True


class OIDCTokenVerifier:
    def __init__(self, config: OIDCVerifierConfig, jwks_cache: JWKSCache | None = None):
        self._config = config
        self._jwks_cache = jwks_cache or JWKSCache(config.jwks_uri)

    def verify(self, token: str, expected_nonce: str | None) -> dict:
        try:
            unverified_header = pyjwt.get_unverified_header(token)
        except pyjwt.DecodeError as exc:
            raise SignatureInvalid("Token header could not be decoded") from exc

        alg = unverified_header.get("alg")
        if alg not in self._config.algorithms:
            raise AlgorithmNotAllowed(f"alg {alg!r} not in allowlist {self._config.algorithms}")

        kid = unverified_header.get("kid")
        if not kid:
            raise SignatureInvalid("Token header missing kid")

        jwk = self._jwks_cache.get_key_for_kid(kid)
        public_key = RSAAlgorithm.from_jwk(jwk)

        logger.info(
            "oidc.verify.started",
            extra={"issuer": self._config.issuer, "audience": ",".join(self._config.audiences)},
        )

        try:
            claims = pyjwt.decode(
                token,
                public_key,
                algorithms=list(self._config.algorithms),
                audience=list(self._config.audiences),
                issuer=self._config.issuer,
                leeway=self._config.leeway_seconds,
                options={"require": ["iss", "aud", "exp", "iat"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpired(str(exc)) from exc
        except pyjwt.InvalidIssuerError as exc:
            raise IssuerMismatch(str(exc)) from exc
        except pyjwt.InvalidAudienceError as exc:
            raise AudienceMismatch(str(exc)) from exc
        except pyjwt.InvalidSignatureError as exc:
            raise SignatureInvalid(str(exc)) from exc
        except pyjwt.PyJWTError as exc:
            raise SignatureInvalid(str(exc)) from exc

        if expected_nonce is not None:
            actual = claims.get("nonce")
            if not actual or not hmac.compare_digest(str(actual), str(expected_nonce)):
                raise NonceMismatch("nonce claim missing or did not match")

        return claims
```

- [ ] **Step 2: Run all OIDC tests**

Run: `uv run pytest blockauth/utils/jwt/tests -v`
Expected: 20 passed (10 cache + 8 verifier + 2 surface).

- [ ] **Step 3: Commit**

```bash
git add blockauth/utils/jwt/verifier.py blockauth/utils/jwt/tests/test_verifier.py
git commit -m "feat(oidc): OIDCTokenVerifier with alg pinning, audience allowlist, nonce check"
```

- [ ] **Step 4: Add smoke test to lock in the public surface**

Now that `OIDCTokenVerifier` and `OIDCVerifierConfig` are exported from
`blockauth.utils.jwt`, add a one-line smoke test that asserts the public
surface — this guards against accidental `__all__` regressions in later
phases (e.g. when refactors temporarily collapse modules).

Run: `uv run python -c "from blockauth.utils.jwt import OIDCTokenVerifier, OIDCVerifierConfig, JWKSCache, JWKSUnreachable, KidNotFound, OIDCVerificationError; print('ok')"`
Expected output: `ok`.

---

## Phase 2: SocialIdentity model and service

### Task 2.1: SocialIdentity Django app skeleton

**Files:**
- Create: `blockauth/social/__init__.py`
- Create: `blockauth/social/apps.py`
- Create: `blockauth/social/exceptions.py`
- Create: `blockauth/social/migrations/__init__.py`
- Create: `blockauth/social/tests/__init__.py`

- [ ] **Step 1: Create `blockauth/social/exceptions.py`**

```python
"""Errors raised by the SocialIdentity layer."""

from rest_framework.exceptions import APIException


class SocialIdentityConflictError(APIException):
    """Raised when an OAuth/OIDC sign-in claims an email that maps to an
    existing user but the issuing provider is not authoritative for that
    email under `AccountLinkingPolicy`.

    Subclasses DRF's `APIException` so it auto-maps to HTTP 409 in the
    same way `WalletConflictError` does, keeping conflict semantics
    consistent across the package. `provider` and `existing_user_id`
    are stored on the exception instance so views can include
    structured context in the response body without re-deriving them.
    """

    status_code = 409
    default_detail = "This identity is already linked to a different account."
    default_code = "SOCIAL_IDENTITY_CONFLICT"

    def __init__(self, *, provider: str, existing_user_id: str):
        self.provider = provider
        self.existing_user_id = existing_user_id
        super().__init__(
            detail=f"social identity conflict for provider={provider}",
            code=self.default_code,
        )
```

- [ ] **Step 2: Create `blockauth/social/apps.py`**

```python
from django.apps import AppConfig


class SocialAuthConfig(AppConfig):
    name = "blockauth.social"
    label = "blockauth_social"
    default_auto_field = "django.db.models.BigAutoField"
```

- [ ] **Step 3: Create `blockauth/social/__init__.py`**

```python
"""SocialIdentity layer: durable links between OIDC `(provider, subject)` and User.

`blockauth.social` is registered as a separate Django app (label
`blockauth_social`) — distinct from sibling sub-packages `totp` and `passkey`,
which share the parent `blockauth` app label. The split is deliberate: the
`SocialIdentity` table belongs to its own migration namespace so it can be
introduced (and, if ever needed, retired) without entangling the existing
`blockauth` migrations.
"""
```

(Django 3.2+ no longer requires `default_app_config` — the AppConfig in
`apps.py` is auto-discovered. Documenting the architectural choice is more
useful than a deprecated declaration.)

- [ ] **Step 4: Create empty migration and test packages**

```python
# blockauth/social/migrations/__init__.py
```

```python
# blockauth/social/tests/__init__.py
```

- [ ] **Step 5: Register the app in test settings**

Note: `blockauth/settings.py` is a DRF `APISettings` wrapper (the
`BlockAuthSettings` class), NOT a Django settings module — it has no
`INSTALLED_APPS` list to modify. The actual test bootstrap lives in the
project-root `conftest.py` at `pytest_configure(...)`.

Add `"blockauth.social"` to the root conftest's `INSTALLED_APPS`:

```python
# /Users/.../auth-pack/conftest.py — within pytest_configure's INSTALLED_APPS
INSTALLED_APPS=[
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "blockauth",
    "blockauth.social",
    "tests",
],
```

- [ ] **Step 6: Verify Django can discover the app**

Run: `uv run python -c "import django; django.setup(); from django.apps import apps; print([a.label for a in apps.get_app_configs()])"`
Set `DJANGO_SETTINGS_MODULE=blockauth.settings` first if needed. Expected: list contains `"blockauth_social"`.

- [ ] **Step 7: Commit**

```bash
git add blockauth/social/__init__.py blockauth/social/apps.py blockauth/social/exceptions.py blockauth/social/migrations/__init__.py blockauth/social/tests/__init__.py conftest.py
git commit -m "feat(social): scaffold SocialIdentity app and conflict exception"
```

### Task 2.2: SocialIdentity model — failing test

**Files:**
- Test: `blockauth/social/tests/test_models.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""SocialIdentity model behaviour: uniqueness, FK cascade, indexes, encryption blob storage.

Uses Django's `get_user_model()` (which resolves to the test environment's
`auth.User`) — matches the pattern used by `passkey/tests/` and `totp/tests/`
in this codebase, which also reference `settings.AUTH_USER_MODEL` for the
user FK in their models.
"""

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

from blockauth.social.models import SocialIdentity

User = get_user_model()


@pytest.mark.django_db
def test_provider_subject_uniqueness():
    user_a = User.objects.create_user(username="user_a", email="a@example.com", password="pw")
    user_b = User.objects.create_user(username="user_b", email="b@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="google", subject="g_sub_1", user=user_a, email_at_link="a@example.com", email_verified_at_link=True
    )
    with pytest.raises(IntegrityError):
        SocialIdentity.objects.create(
            provider="google", subject="g_sub_1", user=user_b, email_at_link="b@example.com", email_verified_at_link=True
        )


@pytest.mark.django_db
def test_user_cascade_deletes_identities():
    user = User.objects.create_user(username="user_c", email="c@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple", subject="a_sub_1", user=user, email_at_link="c@example.com", email_verified_at_link=False
    )
    user.delete()
    assert SocialIdentity.objects.count() == 0


@pytest.mark.django_db
def test_encrypted_refresh_token_is_bytes():
    user = User.objects.create_user(username="user_d", email="d@example.com", password="pw")
    blob = b"\x00\x01\x02test-bytes"
    identity = SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_2",
        user=user,
        email_at_link="d@example.com",
        email_verified_at_link=True,
        encrypted_refresh_token=blob,
    )
    identity.refresh_from_db()
    assert bytes(identity.encrypted_refresh_token) == blob


@pytest.mark.django_db
def test_one_user_can_have_multiple_providers():
    user = User.objects.create_user(username="user_e", email="e@example.com", password="pw")
    SocialIdentity.objects.create(provider="google", subject="g1", user=user, email_at_link="e@example.com", email_verified_at_link=True)
    SocialIdentity.objects.create(provider="linkedin", subject="l1", user=user, email_at_link="e@example.com", email_verified_at_link=True)
    SocialIdentity.objects.create(provider="apple", subject="a1", user=user, email_at_link="e@example.com", email_verified_at_link=False)
    assert user.social_identities.count() == 3
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/social/tests/test_models.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.social.models'`.

### Task 2.3: SocialIdentity model — implementation + migration

**Files:**
- Create: `blockauth/social/models.py`
- Create: `blockauth/social/migrations/0001_initial.py`

- [ ] **Step 1: Implement model**

```python
"""SocialIdentity — durable link between an OIDC `(provider, subject)` and a User.

`user` cascades on delete so an account-deletion in the application
removes its OAuth links too.
`unique_together` on (provider, subject) is the primary lookup key the
verification path uses to find an existing user without falling back to email.
`encrypted_refresh_token` stores the AES-GCM blob (nonce || ciphertext || tag);
plaintext refresh tokens never reach the database.
"""

from django.conf import settings
from django.db import models


class SocialIdentity(models.Model):
    provider = models.CharField(max_length=20)
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="social_identities",
    )
    email_at_link = models.EmailField(blank=True, null=True)
    email_verified_at_link = models.BooleanField()
    encrypted_refresh_token = models.BinaryField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "blockauth_social"
        db_table = "social_identity"
        unique_together = (("provider", "subject"),)
        indexes = [models.Index(fields=["user", "provider"])]
```

The model FK uses `settings.AUTH_USER_MODEL` (the standard Django swappable
user pattern, matching `blockauth/passkey/models.py` and
`blockauth/totp/models.py`) rather than a `get_block_auth_user_model()`
call site. The latter resolves at import time and fights Django's
swappable-user contract.

- [ ] **Step 2: Generate migration**

Since `blockauth/settings.py` is a DRF APISettings wrapper (not a Django
settings module), use `manage.py` instead — but first add `"blockauth.social"`
to the INSTALLED_APPS list inside `manage.py`'s `settings.configure(...)`.
Then run:

    uv run python manage.py makemigrations blockauth_social

Inspect the generated `blockauth/social/migrations/0001_initial.py` and confirm
it uses `migrations.swappable_dependency(settings.AUTH_USER_MODEL)`,
`db_table = "social_identity"`, `unique_together` on `(provider, subject)`,
and an index on `(user, provider)`.

- [ ] **Step 3: Run model tests**

Run: `uv run pytest blockauth/social/tests/test_models.py -v`
Expected: 4 passed.

- [ ] **Step 4: Commit**

```bash
git add blockauth/social/models.py blockauth/social/migrations/0001_initial.py blockauth/social/tests/test_models.py manage.py
git commit -m "feat(social): SocialIdentity model with provider+subject uniqueness"
```

### Task 2.4: AESGCMEncryptor — failing test

**Files:**
- Test: `blockauth/social/tests/test_encryption.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""AES-GCM round-trip and AAD-binding tests."""

import pytest

from blockauth.social.encryption import AESGCMEncryptor


def test_round_trip(aes_key):
    enc = AESGCMEncryptor(aes_key)
    aad = b"social_identity:apple:sub_1"
    blob = enc.encrypt("refresh-token-xyz", aad)
    assert enc.decrypt(blob, aad) == "refresh-token-xyz"


def test_blob_is_random_per_call(aes_key):
    enc = AESGCMEncryptor(aes_key)
    aad = b"social_identity:apple:sub_1"
    a = enc.encrypt("same-plaintext", aad)
    b = enc.encrypt("same-plaintext", aad)
    assert a != b


def test_decrypt_with_wrong_aad_fails(aes_key):
    enc = AESGCMEncryptor(aes_key)
    blob = enc.encrypt("refresh", b"social_identity:apple:sub_1")
    with pytest.raises(Exception):  # cryptography raises InvalidTag
        enc.decrypt(blob, b"social_identity:apple:sub_2")


def test_decrypt_with_wrong_key_fails():
    enc1 = AESGCMEncryptor(b"\x00" * 32)
    enc2 = AESGCMEncryptor(b"\x11" * 32)
    blob = enc1.encrypt("refresh", b"aad")
    with pytest.raises(Exception):
        enc2.decrypt(blob, b"aad")


def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        AESGCMEncryptor(b"\x00" * 16)
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/social/tests/test_encryption.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.social.encryption'`.

### Task 2.5: AESGCMEncryptor — implementation

**Files:**
- Create: `blockauth/social/encryption.py`

- [ ] **Step 1: Implement encryptor**

```python
"""AES-GCM-256 encryptor for refresh-token-at-rest.

Each ciphertext blob is `nonce(12 bytes) || ciphertext || tag(16 bytes)` — a
single bytes value that fits a `BinaryField` on the SocialIdentity model.
Associated data binds the ciphertext to a specific (provider, subject) so a
ciphertext from one identity row cannot be replayed onto another.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
KEY_BYTES = 32


class AESGCMEncryptor:
    def __init__(self, key: bytes):
        if len(key) != KEY_BYTES:
            raise ValueError(f"AES-GCM key must be {KEY_BYTES} bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str, associated_data: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return nonce + ciphertext_with_tag

    def decrypt(self, blob: bytes, associated_data: bytes) -> str:
        nonce = blob[:NONCE_BYTES]
        ciphertext_with_tag = blob[NONCE_BYTES:]
        plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext_bytes.decode("utf-8")
```

- [ ] **Step 2: Run encryption tests**

Run: `uv run pytest blockauth/social/tests/test_encryption.py -v`
Expected: 5 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/social/encryption.py blockauth/social/tests/test_encryption.py
git commit -m "feat(social): AES-GCM-256 encryptor for refresh-token-at-rest"
```

### Task 2.6: AccountLinkingPolicy — failing test

**Files:**
- Test: `blockauth/social/tests/test_linking_policy.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""Per-provider account linking rules.

Truth table:
| provider | email_verified | gmail or hd | result |
| google   | True           | gmail       | True   |
| google   | True           | hd present  | True   |
| google   | True           | other       | False  |
| google   | False          | any         | False  |
| linkedin | True           | any         | True   |
| linkedin | False          | any         | False  |
| apple    | True           | any         | False  (Apple email never authoritative)
| apple    | False          | any         | False
| facebook | True           | any         | True (email present implies verified)
| facebook | False          | any         | False
"""

import pytest

from blockauth.social.linking_policy import AccountLinkingPolicy


@pytest.mark.parametrize(
    "provider,email,verified,extra,expected",
    [
        ("google", "u@gmail.com", True, {}, True),
        ("google", "u@workspace.com", True, {"hd": "workspace.com"}, True),
        ("google", "u@workspace.com", True, {}, False),
        ("google", "u@gmail.com", False, {}, False),
        ("linkedin", "u@example.com", True, {}, True),
        ("linkedin", "u@example.com", False, {}, False),
        ("apple", "u@example.com", True, {}, False),
        ("apple", "u@privaterelay.appleid.com", True, {}, False),
        ("facebook", "u@example.com", True, {}, True),
        ("facebook", "u@example.com", False, {}, False),
        ("facebook", None, False, {}, False),
    ],
)
def test_can_link_truth_table(provider, email, verified, extra, expected):
    assert (
        AccountLinkingPolicy.can_link_to_existing_user(
            provider=provider, email=email, email_verified=verified, extra_claims=extra
        )
        is expected
    )


def test_unknown_provider_rejects():
    assert (
        AccountLinkingPolicy.can_link_to_existing_user(
            provider="unsupported", email="u@example.com", email_verified=True, extra_claims={}
        )
        is False
    )
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/social/tests/test_linking_policy.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.social.linking_policy'`.

### Task 2.7: AccountLinkingPolicy — implementation

**Files:**
- Create: `blockauth/social/linking_policy.py`

- [ ] **Step 1: Implement linking policy**

```python
"""Per-provider rules for auto-linking a new social identity to an existing
User row by email.

Default posture is "do not link" — only providers that are demonstrably
authoritative for the claimed email opt in. The dispatcher keeps the rule for
each provider isolated so future additions (Microsoft, GitHub) get their own
explicit case rather than inheriting a default.
"""

from typing import Any


class AccountLinkingPolicy:
    @staticmethod
    def can_link_to_existing_user(
        *,
        provider: str,
        email: str | None,
        email_verified: bool,
        extra_claims: dict[str, Any],
    ) -> bool:
        if not email:
            return False

        if provider == "google":
            if not email_verified:
                return False
            if email.lower().endswith("@gmail.com"):
                return True
            if extra_claims.get("hd"):
                return True
            return False

        if provider == "linkedin":
            return bool(email_verified)

        if provider == "facebook":
            return bool(email_verified)

        if provider == "apple":
            return False

        return False
```

- [ ] **Step 2: Run policy tests**

Run: `uv run pytest blockauth/social/tests/test_linking_policy.py -v`
Expected: 12 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/social/linking_policy.py blockauth/social/tests/test_linking_policy.py
git commit -m "feat(social): AccountLinkingPolicy with per-provider authoritative-email rules"
```

### Task 2.8: SocialIdentityService — failing test

**Files:**
- Test: `blockauth/social/tests/test_service.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""SocialIdentityService.upsert_and_link behavior.

Covers: existing identity match, new identity linked to existing user via
authoritative email, conflict on non-authoritative provider, brand-new user
creation, refresh-token encryption round-trip.
"""

import base64
from unittest.mock import patch

import pytest
from django.test import override_settings

from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.models import SocialIdentity
from blockauth.social.service import SocialIdentityService
from blockauth.utils.config import get_block_auth_user_model

User = get_block_auth_user_model()


@pytest.fixture
def encryption_key_b64(aes_key):
    return base64.b64encode(aes_key).decode()


@pytest.fixture(autouse=True)
def _settings(encryption_key_b64):
    with override_settings(BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": encryption_key_b64}):
        yield


@pytest.mark.django_db
def test_existing_identity_returns_same_user():
    user = User.objects.create(email="x@gmail.com")
    SocialIdentity.objects.create(
        provider="google", subject="g_sub_1", user=user, email_at_link="x@gmail.com", email_verified_at_link=True
    )

    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_1",
        email="x@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user.id
    assert identity.provider == "google"
    assert created is False


@pytest.mark.django_db
def test_new_identity_links_to_existing_user_via_authoritative_email():
    user = User.objects.create(email="bob@gmail.com")

    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_new",
        email="bob@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user.id
    assert identity.subject == "g_sub_new"
    assert created is False


@pytest.mark.django_db
def test_apple_with_existing_email_raises_conflict():
    User.objects.create(email="bob@gmail.com")

    with pytest.raises(SocialIdentityConflictError) as excinfo:
        SocialIdentityService().upsert_and_link(
            provider="apple",
            subject="a_sub_1",
            email="bob@gmail.com",
            email_verified=True,
            extra_claims={},
        )
    assert excinfo.value.provider == "apple"


@pytest.mark.django_db
def test_brand_new_user_created():
    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_first",
        email="newuser@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.email == "newuser@gmail.com"
    assert identity.provider == "google"
    assert created is True


@pytest.mark.django_db
def test_refresh_token_encrypted_round_trip():
    service = SocialIdentityService()
    _, identity, _ = service.upsert_and_link(
        provider="apple",
        subject="a_sub_refresh",
        email="apple@example.com",
        email_verified=False,
        extra_claims={},
        refresh_token="apple-refresh-token-xyz",
    )

    blob = bytes(identity.encrypted_refresh_token)
    assert blob != b"apple-refresh-token-xyz"

    decrypted = service.decrypt_refresh_token(identity)
    assert decrypted == "apple-refresh-token-xyz"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/social/tests/test_service.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.social.service'`.

### Task 2.9: SocialIdentityService — implementation

**Files:**
- Create: `blockauth/social/service.py`
- Modify: `blockauth/social/__init__.py`

- [ ] **Step 1: Implement service**

```python
"""SocialIdentityService.

Single entrypoint `upsert_and_link` consolidates the four cases an OAuth/OIDC
sign-in can produce:
  1. Existing (provider, subject) — return the linked user.
  2. New (provider, subject), email matches existing User, policy permits — link.
  3. New (provider, subject), email matches existing User, policy rejects — raise.
  4. No email match — create a new User.

Refresh tokens are encrypted with `AESGCMEncryptor` and stored as the
`encrypted_refresh_token` blob; the AAD binds each ciphertext to the
(provider, subject) pair so a stolen blob from one identity cannot be
replayed onto another row.
"""

import base64
import logging
from typing import Any

from django.conf import settings
from django.db import transaction

from blockauth.social.encryption import AESGCMEncryptor
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.linking_policy import AccountLinkingPolicy
from blockauth.social.models import SocialIdentity
from blockauth.utils.config import get_block_auth_user_model

logger = logging.getLogger(__name__)


def _load_encryptor() -> AESGCMEncryptor | None:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    key_b64 = block_settings.get("SOCIAL_IDENTITY_ENCRYPTION_KEY")
    if not key_b64:
        return None
    return AESGCMEncryptor(base64.b64decode(key_b64))


def _aad_for(provider: str, subject: str) -> bytes:
    return f"social_identity:{provider}:{subject}".encode("utf-8")


class SocialIdentityService:
    def __init__(self, encryptor: AESGCMEncryptor | None = None):
        self._encryptor = encryptor or _load_encryptor()

    @transaction.atomic
    def upsert_and_link(
        self,
        *,
        provider: str,
        subject: str,
        email: str | None,
        email_verified: bool,
        extra_claims: dict[str, Any],
        refresh_token: str | None = None,
    ) -> tuple[Any, SocialIdentity, bool]:
        User = get_block_auth_user_model()

        existing_identity = SocialIdentity.objects.select_related("user").filter(provider=provider, subject=subject).first()
        if existing_identity is not None:
            self._maybe_store_refresh(existing_identity, refresh_token, provider, subject)
            existing_identity.save(update_fields=["last_used_at", "encrypted_refresh_token"])
            logger.info(
                "social_identity.matched_existing_subject",
                extra={"provider": provider, "user_id": str(existing_identity.user.id)},
            )
            return existing_identity.user, existing_identity, False

        existing_user = User.objects.filter(email=email).first() if email else None
        if existing_user is not None:
            if not AccountLinkingPolicy.can_link_to_existing_user(
                provider=provider, email=email, email_verified=email_verified, extra_claims=extra_claims
            ):
                logger.warning(
                    "social_identity.linking_rejected_unverified_email",
                    extra={"provider": provider, "email_domain_only": (email or "").split("@")[-1]},
                )
                raise SocialIdentityConflictError(provider=provider, existing_user_id=str(existing_user.id))

            identity = SocialIdentity(
                provider=provider,
                subject=subject,
                user=existing_user,
                email_at_link=email,
                email_verified_at_link=email_verified,
            )
            self._maybe_store_refresh(identity, refresh_token, provider, subject)
            identity.save()
            logger.info(
                "social_identity.linked_to_existing_user",
                extra={
                    "provider": provider,
                    "user_id": str(existing_user.id),
                    "linking_reason": self._linking_reason(provider, email, extra_claims),
                },
            )
            return existing_user, identity, False

        new_user = User.objects.create(email=email, is_verified=bool(email_verified))
        identity = SocialIdentity(
            provider=provider,
            subject=subject,
            user=new_user,
            email_at_link=email,
            email_verified_at_link=email_verified,
        )
        self._maybe_store_refresh(identity, refresh_token, provider, subject)
        identity.save()
        logger.info(
            "social_identity.created_new_user",
            extra={"provider": provider, "user_id": str(new_user.id)},
        )
        return new_user, identity, True

    def decrypt_refresh_token(self, identity: SocialIdentity) -> str | None:
        if identity.encrypted_refresh_token is None or self._encryptor is None:
            return None
        return self._encryptor.decrypt(
            bytes(identity.encrypted_refresh_token),
            _aad_for(identity.provider, identity.subject),
        )

    def _maybe_store_refresh(self, identity: SocialIdentity, refresh_token: str | None, provider: str, subject: str) -> None:
        if refresh_token is None:
            return
        if self._encryptor is None:
            logger.warning(
                "social_identity.refresh_token_dropped_no_key",
                extra={"provider": provider},
            )
            return
        identity.encrypted_refresh_token = self._encryptor.encrypt(refresh_token, _aad_for(provider, subject))

    @staticmethod
    def _linking_reason(provider: str, email: str | None, extra: dict[str, Any]) -> str:
        if provider == "google" and email and email.lower().endswith("@gmail.com"):
            return "google_authoritative_domain"
        if provider == "google" and extra.get("hd"):
            return "google_workspace_domain"
        if provider == "linkedin":
            return "linkedin_email_verified"
        if provider == "facebook":
            return "facebook_email_present"
        return "unknown"
```

- [ ] **Step 2: Update `blockauth/social/__init__.py` to export the service**

```python
default_app_config = "blockauth.social.apps.SocialAuthConfig"

from blockauth.social.exceptions import SocialIdentityConflictError  # noqa: E402
from blockauth.social.linking_policy import AccountLinkingPolicy  # noqa: E402
from blockauth.social.models import SocialIdentity  # noqa: E402
from blockauth.social.service import SocialIdentityService  # noqa: E402

__all__ = [
    "AccountLinkingPolicy",
    "SocialIdentity",
    "SocialIdentityConflictError",
    "SocialIdentityService",
]
```

- [ ] **Step 3: Run service tests**

Run: `uv run pytest blockauth/social/tests/test_service.py -v`
Expected: 5 passed.

- [ ] **Step 4: Run all social tests**

Run: `uv run pytest blockauth/social/tests -v`
Expected: 26 passed (4 model + 5 encryption + 12 linking + 5 service).

- [ ] **Step 5: Commit**

```bash
git add blockauth/social/service.py blockauth/social/__init__.py blockauth/social/tests/test_service.py
git commit -m "feat(social): SocialIdentityService.upsert_and_link with linking policy and refresh-at-rest"
```

---

## Phase 3: PKCE helper

### Task 3.1: PKCE pair generator — failing test

**Files:**
- Test: `blockauth/utils/tests/test_pkce.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""RFC 7636 PKCE pair generation tests."""

import base64
import hashlib

import pytest

from blockauth.utils.pkce import generate_pkce_pair


def test_pair_lengths_match_rfc_7636():
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert len(challenge) == 43  # base64url(sha256) without padding is always 43


def test_challenge_is_sha256_of_verifier():
    verifier, challenge = generate_pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    assert challenge == expected


def test_two_calls_produce_distinct_pairs():
    a = generate_pkce_pair()
    b = generate_pkce_pair()
    assert a != b


def test_verifier_charset_is_url_safe():
    verifier, _ = generate_pkce_pair()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(verifier).issubset(allowed)
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/utils/tests/test_pkce.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.utils.pkce'`.

### Task 3.2: PKCE pair generator — implementation

**Files:**
- Create: `blockauth/utils/pkce.py`

- [ ] **Step 1: Implement helper**

```python
"""RFC 7636 PKCE helper.

`generate_pkce_pair` returns `(code_verifier, code_challenge)` where the
verifier is a high-entropy URL-safe random string and the challenge is the
S256 derivation Apple, Google, LinkedIn, and Facebook all accept.
"""

import base64
import hashlib
import secrets

VERIFIER_BYTES = 32  # 32 random bytes → 43 url-safe chars, lower bound of RFC 7636


def generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(VERIFIER_BYTES)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge
```

- [ ] **Step 2: Run PKCE tests**

Run: `uv run pytest blockauth/utils/tests/test_pkce.py -v`
Expected: 4 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/utils/pkce.py blockauth/utils/tests/test_pkce.py
git commit -m "feat(pkce): RFC 7636 verifier+challenge helper"
```

---

## Phase 4: Constants, enums, configuration

### Task 4.1: Extend enums and constants

**Files:**
- Modify: `blockauth/enums.py`
- Modify: `blockauth/constants/core.py`
- Modify: `blockauth/constants/sensitive_fields.py`

- [ ] **Step 1: Read the existing `blockauth/enums.py`**

Run: `uv run python -c "from blockauth.enums import AuthenticationType; print(list(AuthenticationType))"`
Note the existing values (e.g. `EMAIL`, `WALLET`, `GOOGLE`, `FACEBOOK`, `LINKEDIN`).

- [ ] **Step 2: Add `APPLE` to `AuthenticationType`**

Edit `blockauth/enums.py`. Find the `AuthenticationType` class and add the new member alongside existing ones (placement matches alphabetic order if the existing file is alphabetic, otherwise place at the end of the providers block):

```python
APPLE = "apple"
```

- [ ] **Step 3: Add provider, features, URL names to `blockauth/constants/core.py`**

Open `blockauth/constants/core.py`. Find the `SocialProviders` class and add:

```python
APPLE = "apple"
```

Find the `Features` class and add (placement adjacent to existing `SOCIAL_AUTH`):

```python
APPLE_LOGIN = "apple_login"
GOOGLE_NATIVE_LOGIN = "google_native_login"
```

Find the `URLNames` class and add:

```python
APPLE_LOGIN = "apple-login"
APPLE_CALLBACK = "apple-callback"
APPLE_NATIVE_VERIFY = "apple-native-verify"
APPLE_NOTIFICATIONS = "apple-notifications"
GOOGLE_NATIVE_VERIFY = "google-native-verify"
```

- [ ] **Step 4: Add sensitive fields**

Open `blockauth/constants/sensitive_fields.py`. The existing module exposes a `SENSITIVE_FIELDS` set or tuple. Append:

```python
"id_token",
"refresh_token",
"client_secret",
"code_verifier",
"raw_nonce",
"nonce",
"authorization_code",
"code",
"apple_private_key_pem",
"payload",
```

- [ ] **Step 5: Verify no test regressed**

Run: `uv run pytest blockauth -x -q`
Expected: all existing tests still pass (no behavior change).

- [ ] **Step 6: Commit**

```bash
git add blockauth/enums.py blockauth/constants/core.py blockauth/constants/sensitive_fields.py
git commit -m "feat: add Apple + Google native enums, features, URL names, sensitive fields"
```

### Task 4.2: Configuration defaults

**Files:**
- Modify: `blockauth/conf.py`

- [ ] **Step 1: Inspect existing defaults**

Run: `uv run python -c "from blockauth.conf import DEFAULTS; import json; print(json.dumps({k: type(v).__name__ for k, v in DEFAULTS.items()}, indent=2))"`

Note the exact dict variable name (`DEFAULTS`) and the `IMPORT_STRINGS` tuple (used to convert dotted-path strings to objects).

- [ ] **Step 2: Add new defaults**

Edit `blockauth/conf.py`. Append these keys to `DEFAULTS` (placement adjacent to existing OAuth keys for readability):

```python
# Apple Sign-In
"APPLE_TEAM_ID": None,
"APPLE_KEY_ID": None,
"APPLE_PRIVATE_KEY_PEM": None,
"APPLE_PRIVATE_KEY_PATH": None,
"APPLE_SERVICES_ID": None,
"APPLE_BUNDLE_IDS": (),
"APPLE_REDIRECT_URI": None,
"APPLE_NOTIFICATION_TRIGGER": None,
"APPLE_CALLBACK_COOKIE_SAMESITE": "None",

# Google native id_token verify
"GOOGLE_NATIVE_AUDIENCES": (),

# Generic OIDC verifier
"OIDC_JWKS_CACHE_TTL_SECONDS": 3600,
"OIDC_VERIFIER_LEEWAY_SECONDS": 60,

# SocialIdentity refresh-token-at-rest (base64-encoded 32 bytes)
"SOCIAL_IDENTITY_ENCRYPTION_KEY": None,
```

If `IMPORT_STRINGS` exists, append:

```python
"APPLE_NOTIFICATION_TRIGGER",
```

- [ ] **Step 3: Verify defaults load**

Run: `uv run python -c "from blockauth.conf import DEFAULTS; print('APPLE_TEAM_ID' in DEFAULTS)"`
Expected: `True`.

- [ ] **Step 4: Commit**

```bash
git add blockauth/conf.py
git commit -m "feat: add Apple, Google native, OIDC, and social-identity encryption defaults"
```

---

## Phase 5: Apple client secret builder

### Task 5.1: Apple constants and exceptions

**Files:**
- Create: `blockauth/apple/__init__.py`
- Create: `blockauth/apple/apps.py`
- Create: `blockauth/apple/constants.py`
- Create: `blockauth/apple/exceptions.py`
- Create: `blockauth/apple/tests/__init__.py`

- [ ] **Step 1: Create `blockauth/apple/constants.py`**

```python
"""Apple Sign-In constants — endpoints, claim names, notification event types.

Endpoints are pulled out of source code so test stubs can patch them and so
integrators can override for staging environments.
"""


class AppleEndpoints:
    AUTHORIZE = "https://appleid.apple.com/auth/authorize"
    TOKEN = "https://appleid.apple.com/auth/token"
    REVOKE = "https://appleid.apple.com/auth/revoke"
    JWKS = "https://appleid.apple.com/auth/keys"
    AUDIENCE = "https://appleid.apple.com"


class AppleClaimKeys:
    SUB = "sub"
    EMAIL = "email"
    EMAIL_VERIFIED = "email_verified"
    IS_PRIVATE_EMAIL = "is_private_email"
    NONCE = "nonce"
    NONCE_SUPPORTED = "nonce_supported"
    EVENTS = "events"


class AppleNotificationEvents:
    CONSENT_REVOKED = "consent-revoked"
    ACCOUNT_DELETE = "account-delete"
    EMAIL_DISABLED = "email-disabled"
    EMAIL_ENABLED = "email-enabled"
```

- [ ] **Step 2: Create `blockauth/apple/exceptions.py`**

```python
"""Apple-flow specific errors. Each subclass maps to one error code in the spec."""


class AppleAuthError(Exception):
    """Base for Apple auth failures."""


class AppleStateMismatch(AppleAuthError):
    pass


class ApplePKCEMissing(AppleAuthError):
    pass


class AppleTokenExchangeFailed(AppleAuthError):
    def __init__(self, status_code: int, body: str):
        super().__init__(f"Apple token exchange failed: HTTP {status_code}")
        self.status_code = status_code
        self.body = body


class AppleIdTokenVerificationFailed(AppleAuthError):
    pass


class AppleNonceMismatch(AppleAuthError):
    pass


class AppleNotificationVerificationFailed(AppleAuthError):
    pass


class AppleClientSecretConfigError(AppleAuthError):
    pass
```

- [ ] **Step 3: Create `blockauth/apple/apps.py`**

```python
from django.apps import AppConfig


class AppleAuthConfig(AppConfig):
    name = "blockauth.apple"
    label = "blockauth_apple"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Import the signals module so the pre_delete handler is registered
        # exactly once at app startup. Imported here, not at module top level,
        # to avoid touching Django plumbing during test collection.
        from blockauth.apple import signals  # noqa: F401
```

- [ ] **Step 4: Create `blockauth/apple/__init__.py`**

```python
default_app_config = "blockauth.apple.apps.AppleAuthConfig"
```

- [ ] **Step 5: Create empty test package init**

```python
# blockauth/apple/tests/__init__.py
```

- [ ] **Step 6: Add the app to INSTALLED_APPS**

Edit `blockauth/settings.py`. Append `"blockauth.apple"` to `INSTALLED_APPS`.

- [ ] **Step 7: Commit**

```bash
git add blockauth/apple/__init__.py blockauth/apple/apps.py blockauth/apple/constants.py blockauth/apple/exceptions.py blockauth/apple/tests/__init__.py blockauth/settings.py
git commit -m "feat(apple): scaffold apple sub-package with constants and exceptions"
```

### Task 5.2: AppleClientSecretBuilder — failing test

**Files:**
- Test: `blockauth/apple/tests/test_client_secret.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""AppleClientSecretBuilder tests.

Strategy: generate a real ES256 keypair (P-256), point the builder at the PEM,
call build(), then verify the resulting JWT with the public key. We do not stub
PyJWT — the cryptography is exercised end-to-end.
"""

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import override_settings

from blockauth.apple.client_secret import AppleClientSecretBuilder
from blockauth.apple.exceptions import AppleClientSecretConfigError


@pytest.fixture
def es256_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def configured_settings(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_KEY_ID": "KEYID5678",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        yield


def test_build_returns_es256_jwt_with_required_claims(configured_settings, es256_keypair):
    _, public_pem = es256_keypair
    builder = AppleClientSecretBuilder()
    secret = builder.build()

    header = pyjwt.get_unverified_header(secret)
    assert header["alg"] == "ES256"
    assert header["kid"] == "KEYID5678"

    claims = pyjwt.decode(secret, public_pem, algorithms=["ES256"], audience="https://appleid.apple.com")
    assert claims["iss"] == "TEAMID1234"
    assert claims["sub"] == "com.example.services"
    assert claims["aud"] == "https://appleid.apple.com"
    assert claims["exp"] - claims["iat"] <= 6 * 30 * 24 * 3600


def test_cached_secret_reused_within_window(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    b = builder.build()
    assert a == b


def test_cache_rebuilt_when_near_expiry(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    builder._cached_secret_expires_at = time.time() - 10  # type: ignore[attr-defined]
    b = builder.build()
    assert a != b


def test_missing_team_id_raises():
    with override_settings(BLOCK_AUTH_SETTINGS={"APPLE_TEAM_ID": None, "APPLE_KEY_ID": "k", "APPLE_PRIVATE_KEY_PEM": "x", "APPLE_SERVICES_ID": "s"}):
        with pytest.raises(AppleClientSecretConfigError):
            AppleClientSecretBuilder().build()
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_client_secret.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.client_secret'`.

### Task 5.3: AppleClientSecretBuilder — implementation

**Files:**
- Create: `blockauth/apple/client_secret.py`

- [ ] **Step 1: Implement builder**

```python
"""Apple client_secret builder.

Apple's token endpoint requires a `client_secret` that is itself a JWT signed
with an ES256 .p8 key the integrator downloads from the Apple developer
console. This module builds and caches that JWT.

The cache holds a single secret for the process lifetime, rebuilding when the
remaining lifetime drops below 5 minutes. A `threading.Lock` serializes the
rebuild so concurrent requests never produce two different in-flight secrets.
"""

import logging
import threading
import time
from pathlib import Path

import jwt as pyjwt
from django.conf import settings

from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.exceptions import AppleClientSecretConfigError

logger = logging.getLogger(__name__)

CLIENT_SECRET_LIFETIME_SECONDS = 5 * 60 * 60  # 5 hours, well within Apple's 6-month max
CLIENT_SECRET_REBUILD_MARGIN_SECONDS = 5 * 60  # rebuild when < 5 min remain


class AppleClientSecretBuilder:
    def __init__(self):
        self._lock = threading.Lock()
        self._cached_secret: str | None = None
        self._cached_secret_expires_at: float = 0.0

    def build(self) -> str:
        now = time.time()
        if self._cached_secret is not None and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS:
            return self._cached_secret

        with self._lock:
            now = time.time()
            if self._cached_secret is not None and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS:
                return self._cached_secret

            team_id, key_id, private_pem, services_id = self._read_settings()
            issued_at = int(now)
            expires_at = issued_at + CLIENT_SECRET_LIFETIME_SECONDS
            secret = pyjwt.encode(
                {
                    "iss": team_id,
                    "iat": issued_at,
                    "exp": expires_at,
                    "aud": AppleEndpoints.AUDIENCE,
                    "sub": services_id,
                },
                private_pem,
                algorithm="ES256",
                headers={"kid": key_id, "alg": "ES256"},
            )
            self._cached_secret = secret
            self._cached_secret_expires_at = float(expires_at)
            logger.info("apple.client_secret.built", extra={"team_id_suffix": team_id[-4:]})
            return secret

    @staticmethod
    def _read_settings() -> tuple[str, str, str, str]:
        block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
        team_id = block_settings.get("APPLE_TEAM_ID")
        key_id = block_settings.get("APPLE_KEY_ID")
        services_id = block_settings.get("APPLE_SERVICES_ID")
        private_pem = block_settings.get("APPLE_PRIVATE_KEY_PEM")
        if not private_pem:
            path = block_settings.get("APPLE_PRIVATE_KEY_PATH")
            if path:
                private_pem = Path(path).read_text()
        if not all([team_id, key_id, services_id, private_pem]):
            raise AppleClientSecretConfigError(
                "APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_SERVICES_ID, and APPLE_PRIVATE_KEY_PEM (or APPLE_PRIVATE_KEY_PATH) must all be set"
            )
        return team_id, key_id, private_pem, services_id
```

- [ ] **Step 2: Run client-secret tests**

Run: `uv run pytest blockauth/apple/tests/test_client_secret.py -v`
Expected: 4 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/apple/client_secret.py blockauth/apple/tests/test_client_secret.py
git commit -m "feat(apple): ES256 client_secret builder with lock-guarded cache"
```

---

## Phase 6: Apple id_token verifier

### Task 6.1: AppleIdTokenVerifier — failing test

**Files:**
- Test: `blockauth/apple/tests/test_id_token_verifier.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""AppleIdTokenVerifier tests — bool coercion, conditional nonce, verify_raw.

Uses the session RSA keypair to generate Apple-shaped id_tokens. Patches the
JWKS HTTP fetch to return the test public key.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.exceptions import AppleNonceMismatch
from blockauth.apple.id_token_verifier import AppleIdTokenClaims, AppleIdTokenVerifier


@pytest.fixture
def configured_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


def _apple_token(build_id_token, **overrides):
    claims = {
        "iss": "https://appleid.apple.com",
        "aud": "com.example.services",
        "sub": "001234.abcdef.1234",
        "email": "user@privaterelay.appleid.com",
        "email_verified": "true",
        "is_private_email": "true",
        "nonce_supported": True,
    }
    claims.update(overrides)
    return build_id_token(claims)


def test_string_bool_email_verified_coerced_to_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify(token, expected_nonce=None)
    assert isinstance(claims, AppleIdTokenClaims)
    assert claims.email_verified is True
    assert claims.is_private_email is True


def test_native_bundle_audience_accepted(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, aud="com.example.app")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify(token, expected_nonce=None)
    assert claims.sub == "001234.abcdef.1234"


def test_nonce_required_when_nonce_supported_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce="hashed-from-server", nonce_supported=True)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleIdTokenVerifier().verify(token, expected_nonce="hashed-from-server")


def test_nonce_mismatch_raises_when_nonce_supported_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce="aaaa", nonce_supported=True)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(AppleNonceMismatch):
            AppleIdTokenVerifier().verify(token, expected_nonce="bbbb")


def test_nonce_skipped_when_nonce_supported_false(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce_supported=False)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleIdTokenVerifier().verify(token, expected_nonce="anything")


def test_verify_raw_for_s2s_uses_services_id_audience(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, aud="com.example.services", events="event-payload-string")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify_raw(token, audiences=("com.example.services",))
    assert claims["events"] == "event-payload-string"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_id_token_verifier.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.id_token_verifier'`.

### Task 6.2: AppleIdTokenVerifier — implementation

**Files:**
- Create: `blockauth/apple/id_token_verifier.py`

- [ ] **Step 1: Implement verifier**

```python
"""Apple id_token verifier.

Wraps the generic OIDCTokenVerifier with Apple-specific claim handling:
  - Apple sometimes serializes `email_verified` and `is_private_email` as the
    strings "true" / "false". We coerce those to bools.
  - Apple's `nonce_supported` claim signals whether the device participated in
    the nonce protocol. When True, we require nonce match. When False or
    absent, we skip nonce verification (older devices).
  - `verify_raw` is a thin convenience for the S2S notification path, which
    has a different audience expectation and no nonce.
"""

import hmac
import logging
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from blockauth.apple.constants import AppleClaimKeys, AppleEndpoints
from blockauth.apple.exceptions import AppleIdTokenVerificationFailed, AppleNonceMismatch
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppleIdTokenClaims:
    sub: str
    email: str | None
    email_verified: bool
    is_private_email: bool
    nonce_supported: bool
    raw: dict[str, Any]


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _audiences() -> tuple[str, ...]:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    services_id = block_settings.get("APPLE_SERVICES_ID")
    bundle_ids = tuple(block_settings.get("APPLE_BUNDLE_IDS") or ())
    audiences: list[str] = []
    if services_id:
        audiences.append(services_id)
    audiences.extend(bundle_ids)
    if not audiences:
        raise AppleIdTokenVerificationFailed("APPLE_SERVICES_ID and/or APPLE_BUNDLE_IDS must be configured")
    return tuple(audiences)


def _build_verifier(audiences: tuple[str, ...]) -> OIDCTokenVerifier:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    config = OIDCVerifierConfig(
        issuer="https://appleid.apple.com",
        jwks_uri=AppleEndpoints.JWKS,
        audiences=audiences,
        algorithms=("RS256",),
        leeway_seconds=int(block_settings.get("OIDC_VERIFIER_LEEWAY_SECONDS", 60)),
    )
    cache = JWKSCache(AppleEndpoints.JWKS, cache_ttl_seconds=int(block_settings.get("OIDC_JWKS_CACHE_TTL_SECONDS", 3600)))
    return OIDCTokenVerifier(config, jwks_cache=cache)


class AppleIdTokenVerifier:
    def verify(self, id_token: str, expected_nonce: str | None) -> AppleIdTokenClaims:
        verifier = _build_verifier(_audiences())
        try:
            claims = verifier.verify(id_token, expected_nonce=None)
        except OIDCVerificationError as exc:
            raise AppleIdTokenVerificationFailed(str(exc)) from exc

        nonce_supported = _coerce_bool(claims.get(AppleClaimKeys.NONCE_SUPPORTED))
        if expected_nonce is not None:
            if nonce_supported:
                actual = claims.get(AppleClaimKeys.NONCE)
                if not actual or not hmac.compare_digest(str(actual), str(expected_nonce)):
                    raise AppleNonceMismatch("Apple id_token nonce did not match expected value")
            else:
                logger.info("apple.idtoken.nonce_unsupported", extra={"sub_suffix": str(claims.get("sub", ""))[-4:]})

        return AppleIdTokenClaims(
            sub=str(claims["sub"]),
            email=claims.get(AppleClaimKeys.EMAIL),
            email_verified=_coerce_bool(claims.get(AppleClaimKeys.EMAIL_VERIFIED)),
            is_private_email=_coerce_bool(claims.get(AppleClaimKeys.IS_PRIVATE_EMAIL)),
            nonce_supported=nonce_supported,
            raw=claims,
        )

    def verify_raw(self, id_token: str, audiences: tuple[str, ...]) -> dict[str, Any]:
        verifier = _build_verifier(audiences)
        try:
            return verifier.verify(id_token, expected_nonce=None)
        except OIDCVerificationError as exc:
            raise AppleIdTokenVerificationFailed(str(exc)) from exc
```

- [ ] **Step 2: Run verifier tests**

Run: `uv run pytest blockauth/apple/tests/test_id_token_verifier.py -v`
Expected: 6 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/apple/id_token_verifier.py blockauth/apple/tests/test_id_token_verifier.py
git commit -m "feat(apple): id_token verifier with bool coercion and conditional nonce"
```

---

## Phase 7: Nonce helpers + oauth_state extension

### Task 7.1: Apple nonce helpers — failing test

**Files:**
- Test: `blockauth/apple/tests/test_nonce.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""Apple nonce helper tests."""

import hashlib

import pytest
from django.http import HttpResponse

from blockauth.apple.nonce import (
    APPLE_NONCE_COOKIE_NAME,
    clear_nonce_cookie,
    generate_raw_nonce,
    hash_raw_nonce,
    read_nonce_cookie,
    set_nonce_cookie,
)


def test_raw_nonce_is_url_safe_random():
    a = generate_raw_nonce()
    b = generate_raw_nonce()
    assert a != b
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(a).issubset(allowed)


def test_hash_is_sha256_hex_of_raw_value():
    raw = "abc"
    expected = hashlib.sha256(b"abc").hexdigest()
    assert hash_raw_nonce(raw) == expected


def test_cookie_set_clear_round_trip(rf):
    response = HttpResponse()
    set_nonce_cookie(response, "raw-nonce-value")
    assert response.cookies[APPLE_NONCE_COOKIE_NAME].value == "raw-nonce-value"

    request = rf.get("/")
    request.COOKIES[APPLE_NONCE_COOKIE_NAME] = "raw-nonce-value"
    assert read_nonce_cookie(request) == "raw-nonce-value"

    cleared = HttpResponse()
    clear_nonce_cookie(cleared)
    assert cleared.cookies[APPLE_NONCE_COOKIE_NAME]["max-age"] == 0
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_nonce.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.nonce'`.

### Task 7.2: Apple nonce helpers — implementation

**Files:**
- Create: `blockauth/apple/nonce.py`

- [ ] **Step 1: Implement helpers**

```python
"""Apple Sign-In nonce helpers.

The web flow stores the raw nonce in an HttpOnly cookie at /apple/, and on
callback hashes it (sha256 hex) before comparing against the id_token's
`nonce` claim.

Native flows pass the raw nonce inline in the request body — these helpers
also expose `hash_raw_nonce` which mobile servers reuse.
"""

import hashlib
import secrets

from django.http import HttpRequest, HttpResponse

from blockauth.utils.oauth_state import (  # noqa: F401  re-exported for callers
    OAUTH_STATE_COOKIE_MAX_AGE,
)

APPLE_NONCE_COOKIE_NAME = "blockauth_apple_nonce"
NONCE_BYTES = 32


def generate_raw_nonce() -> str:
    return secrets.token_urlsafe(NONCE_BYTES)


def hash_raw_nonce(raw_nonce: str) -> str:
    return hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()


def set_nonce_cookie(response: HttpResponse, raw_nonce: str, samesite: str | None = None) -> None:
    response.set_cookie(
        APPLE_NONCE_COOKIE_NAME,
        raw_nonce,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite=samesite or "None",
    )


def read_nonce_cookie(request: HttpRequest) -> str | None:
    return request.COOKIES.get(APPLE_NONCE_COOKIE_NAME)


def clear_nonce_cookie(response: HttpResponse, samesite: str | None = None) -> None:
    response.delete_cookie(APPLE_NONCE_COOKIE_NAME, samesite=samesite or "None")
```

- [ ] **Step 2: Run nonce tests**

Run: `uv run pytest blockauth/apple/tests/test_nonce.py -v`
Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/apple/nonce.py blockauth/apple/tests/test_nonce.py
git commit -m "feat(apple): nonce generation, sha256 hashing, and cookie helpers"
```

### Task 7.3: oauth_state extension — verify_state_values + samesite override + PKCE cookie

**Files:**
- Modify: `blockauth/utils/oauth_state.py`
- Test: `blockauth/utils/tests/test_oauth_state.py` (Modify)

- [ ] **Step 1: Read existing oauth_state.py to anchor edits**

The existing module exports `OAUTH_STATE_COOKIE_NAME`, `OAUTH_STATE_COOKIE_MAX_AGE`, `generate_state`, `set_state_cookie`, `verify_state`, `clear_state_cookie`. We extend without breaking those.

- [ ] **Step 2: Write failing tests for new helpers**

Append to `blockauth/utils/tests/test_oauth_state.py` (create it if missing — start the file with the standard imports if you do):

```python
"""Tests for oauth_state extensions: verify_state_values, samesite override,
PKCE verifier cookie helpers."""

import pytest
from django.http import HttpResponse
from rest_framework.exceptions import ValidationError

from blockauth.utils.oauth_state import (
    OAUTH_PKCE_VERIFIER_COOKIE_NAME,
    OAUTH_STATE_COOKIE_NAME,
    clear_pkce_verifier_cookie,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state_values,
)


def test_verify_state_values_matching():
    verify_state_values("abc", "abc")


def test_verify_state_values_missing_cookie_raises():
    with pytest.raises(ValidationError):
        verify_state_values(None, "abc")


def test_verify_state_values_missing_provided_raises():
    with pytest.raises(ValidationError):
        verify_state_values("abc", None)


def test_verify_state_values_mismatch_raises():
    with pytest.raises(ValidationError):
        verify_state_values("abc", "xyz")


def test_state_cookie_samesite_override():
    response = HttpResponse()
    set_state_cookie(response, "stateval", samesite="None")
    assert response.cookies[OAUTH_STATE_COOKIE_NAME]["samesite"] == "None"


def test_pkce_verifier_cookie_round_trip(rf):
    response = HttpResponse()
    set_pkce_verifier_cookie(response, "verifier-xyz")
    assert response.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value == "verifier-xyz"

    request = rf.get("/")
    request.COOKIES[OAUTH_PKCE_VERIFIER_COOKIE_NAME] = "verifier-xyz"
    assert read_pkce_verifier_cookie(request) == "verifier-xyz"

    cleared = HttpResponse()
    clear_pkce_verifier_cookie(cleared)
    assert cleared.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME]["max-age"] == 0
```

- [ ] **Step 3: Run test, verify it fails**

Run: `uv run pytest blockauth/utils/tests/test_oauth_state.py -v`
Expected: import error referencing `OAUTH_PKCE_VERIFIER_COOKIE_NAME` or `verify_state_values` (whichever pyimport hits first).

- [ ] **Step 4: Extend `blockauth/utils/oauth_state.py`**

Add these constants and helpers to the existing module. Keep the existing `verify_state(request)` function but rewrite its body to delegate to `verify_state_values`:

```python
OAUTH_PKCE_VERIFIER_COOKIE_NAME = "blockauth_oauth_pkce"


def verify_state_values(cookie_state: str | None, provided_state: str | None) -> None:
    """Constant-time compare of the cookie-stored state against any other
    source (query string for redirect callbacks, form body for `form_post`
    callbacks like Apple). Raises `ValidationError` on missing or mismatched
    values so callers can convert to HTTP 400 directly."""
    if not cookie_state or not provided_state:
        raise ValidationError({"detail": "OAuth state missing"}, 4030)
    if not hmac.compare_digest(cookie_state, provided_state):
        raise ValidationError({"detail": "OAuth state mismatch"}, 4030)


def verify_state(request) -> None:
    """Backwards-compatible wrapper that reads `state` from the request's
    query parameters."""
    verify_state_values(
        request.COOKIES.get(OAUTH_STATE_COOKIE_NAME),
        request.query_params.get("state"),
    )


def set_pkce_verifier_cookie(response, verifier: str, samesite: str | None = None) -> None:
    response.set_cookie(
        OAUTH_PKCE_VERIFIER_COOKIE_NAME,
        verifier,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=_cookie_secure(),
        samesite=samesite or _cookie_samesite(),
    )


def read_pkce_verifier_cookie(request) -> str | None:
    return request.COOKIES.get(OAUTH_PKCE_VERIFIER_COOKIE_NAME)


def clear_pkce_verifier_cookie(response, samesite: str | None = None) -> None:
    response.delete_cookie(OAUTH_PKCE_VERIFIER_COOKIE_NAME, samesite=samesite or _cookie_samesite())
```

Also extend the existing `set_state_cookie` signature to accept an optional `samesite` parameter that overrides the configured default:

```python
def set_state_cookie(response, state: str, samesite: str | None = None) -> None:
    response.set_cookie(
        OAUTH_STATE_COOKIE_NAME,
        state,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=_cookie_secure(),
        samesite=samesite or _cookie_samesite(),
    )
```

`clear_state_cookie` gains the same parameter:

```python
def clear_state_cookie(response, samesite: str | None = None) -> None:
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, samesite=samesite or _cookie_samesite())
```

- [ ] **Step 5: Run extension tests**

Run: `uv run pytest blockauth/utils/tests/test_oauth_state.py -v`
Expected: 6 passed.

- [ ] **Step 6: Run the full existing oauth_state test path to confirm no regression**

Run: `uv run pytest blockauth/utils -q`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add blockauth/utils/oauth_state.py blockauth/utils/tests/test_oauth_state.py
git commit -m "feat(oauth-state): verify_state_values pure helper + samesite override + PKCE cookie helpers"
```

---

## Phase 8: Apple web flow (authorize + form_post callback)

### Task 8.1: Apple serializers

**Files:**
- Create: `blockauth/apple/serializers.py`

- [ ] **Step 1: Create serializers**

```python
"""Request serializers for Apple endpoints.

`AppleNativeVerifyRequestSerializer` validates the body posted by mobile
clients with the platform-supplied id_token + raw nonce. Optional name fields
mirror Apple's "first sign-in only" contract — clients pass them on the very
first ASAuthorization and never again, so the field is optional.

`AppleServerToServerNotificationRequestSerializer` validates the
`{"payload": "..."}` envelope Apple delivers to the webhook.
"""

from rest_framework import serializers


class AppleNativeVerifyRequestSerializer(serializers.Serializer):
    id_token = serializers.CharField()
    raw_nonce = serializers.CharField()
    authorization_code = serializers.CharField(required=False, allow_blank=True)
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=120)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=120)


class AppleServerToServerNotificationRequestSerializer(serializers.Serializer):
    payload = serializers.CharField()
```

- [ ] **Step 2: Commit**

```bash
git add blockauth/apple/serializers.py
git commit -m "feat(apple): request serializers for native verify and S2S notifications"
```

### Task 8.2: AppleWebAuthorizeView — failing test

**Files:**
- Test: `blockauth/apple/tests/test_web_views.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""Apple web flow tests — authorize redirect + form_post callback.

Stubs Apple's token endpoint (requests.post) and the JWKS fetch (requests.get)
to return values produced by the test RSA keypair. The id_token returned from
the stubbed token endpoint is built with `build_id_token` so signature
verification runs end-to-end against the test public key.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from django.test import override_settings

from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.nonce import APPLE_NONCE_COOKIE_NAME
from blockauth.utils.oauth_state import OAUTH_PKCE_VERIFIER_COOKIE_NAME, OAUTH_STATE_COOKIE_NAME


@pytest.fixture
def apple_settings(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
            "APPLE_REDIRECT_URI": "https://callback.example.com/apple/callback/",
            "APPLE_CALLBACK_COOKIE_SAMESITE": "None",
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
        }
    ):
        yield


@pytest.fixture
def es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.mark.django_db
def test_authorize_view_redirects_with_required_params(apple_settings, client):
    response = client.get("/auth/apple/")
    assert response.status_code == 302
    parsed = urlparse(response["Location"])
    assert parsed.netloc == "appleid.apple.com"
    qs = parse_qs(parsed.query)
    assert qs["response_type"] == ["code"]
    assert qs["response_mode"] == ["form_post"]
    assert qs["scope"] == ["name email"]
    assert qs["client_id"] == ["com.example.services"]
    assert qs["redirect_uri"] == ["https://callback.example.com/apple/callback/"]
    assert qs["code_challenge_method"] == ["S256"]
    assert "state" in qs and "nonce" in qs and "code_challenge" in qs

    cookies = response.cookies
    assert OAUTH_STATE_COOKIE_NAME in cookies
    assert OAUTH_PKCE_VERIFIER_COOKIE_NAME in cookies
    assert APPLE_NONCE_COOKIE_NAME in cookies

    raw_nonce = cookies[APPLE_NONCE_COOKIE_NAME].value
    expected_nonce_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    assert qs["nonce"] == [expected_nonce_hash]


@pytest.mark.django_db
def test_callback_full_flow(apple_settings, client, build_id_token, jwks_payload_bytes):
    init_response = client.get("/auth/apple/")
    state_value = init_response.cookies[OAUTH_STATE_COOKIE_NAME].value
    raw_nonce = init_response.cookies[APPLE_NONCE_COOKIE_NAME].value
    pkce_verifier = init_response.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value
    expected_nonce_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()

    apple_id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "001234.unique.subject",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_nonce_hash,
            "nonce_supported": True,
        }
    )
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {
        "access_token": "apple-access",
        "refresh_token": "apple-refresh",
        "id_token": apple_id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with patch("blockauth.apple.views.requests.post", return_value=token_response) as mock_post, patch(
        "blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response
    ):
        callback = client.post(
            "/auth/apple/callback/",
            data={"code": "real-auth-code", "state": state_value},
        )

    assert callback.status_code == 200
    body = callback.json()
    assert "access" in body and "refresh" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code"] == "real-auth-code"
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    assert mock_post.call_args.kwargs["data"]["grant_type"] == "authorization_code"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_web_views.py -v`
Expected: 404 (URL not registered) or `ImportError` for `blockauth.apple.views`.

### Task 8.3: AppleWebAuthorizeView + AppleWebCallbackView

**Files:**
- Create: `blockauth/apple/views.py`
- Create: `blockauth/apple/docs.py`

- [ ] **Step 1: Create `blockauth/apple/docs.py` with drf-spectacular schemas**

```python
"""drf-spectacular schemas for Apple endpoints.

Kept minimal — only request/response examples that are not fully expressed by
the serializers. Heavy descriptions live in the README to avoid bloating
generated OpenAPI files.
"""

from drf_spectacular.utils import OpenApiResponse


apple_authorize_schema = {
    "summary": "Initiate Apple Sign-In (web)",
    "responses": {302: OpenApiResponse(description="Redirect to Apple authorize endpoint")},
}

apple_callback_schema = {
    "summary": "Apple Sign-In callback (web, form_post)",
    "responses": {200: OpenApiResponse(description="JWT tokens")},
}

apple_native_verify_schema = {
    "summary": "Verify Apple id_token from native client",
    "responses": {200: OpenApiResponse(description="JWT tokens")},
}

apple_notifications_schema = {
    "summary": "Apple server-to-server notifications webhook",
    "responses": {200: OpenApiResponse(description="OK")},
}
```

- [ ] **Step 2: Create the web views in `blockauth/apple/views.py`**

```python
"""Apple Sign-In views.

`AppleWebAuthorizeView` builds the 302 redirect with PKCE + nonce. The state,
raw nonce, and PKCE verifier are stored in HttpOnly cookies for the callback
to read. SameSite=None+Secure is required because Apple's `form_post` callback
is a cross-site POST.

`AppleWebCallbackView` handles the `form_post` POST. It verifies state,
exchanges code for tokens with the cached client_secret, verifies the id_token
including nonce, then upserts a SocialIdentity and issues blockauth JWTs.

`AppleNativeVerifyView` (added in Phase 9) and the S2S webhook
(`AppleServerToServerNotificationView`, Phase 11) live in this same module.
"""

import logging

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.apple.client_secret import AppleClientSecretBuilder
from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.docs import apple_authorize_schema, apple_callback_schema
from blockauth.apple.exceptions import (
    AppleClientSecretConfigError,
    AppleIdTokenVerificationFailed,
    AppleNonceMismatch,
    AppleTokenExchangeFailed,
)
from blockauth.apple.id_token_verifier import AppleIdTokenVerifier
from blockauth.apple.nonce import (
    clear_nonce_cookie,
    generate_raw_nonce,
    hash_raw_nonce,
    read_nonce_cookie,
    set_nonce_cookie,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.config import get_config
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state_values,
    OAUTH_STATE_COOKIE_NAME,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)


def _samesite_for_callback() -> str:
    return str(get_config("APPLE_CALLBACK_COOKIE_SAMESITE") or "None")


class AppleWebAuthorizeView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**apple_authorize_schema)
    def get(self, request):
        services_id = get_config("APPLE_SERVICES_ID")
        redirect_uri = get_config("APPLE_REDIRECT_URI")
        if not services_id or not redirect_uri:
            raise ValidationError({"detail": "Apple Sign-In is not configured"}, 4020)

        state = generate_state()
        raw_nonce = generate_raw_nonce()
        pkce_verifier, pkce_challenge = generate_pkce_pair()

        params = {
            "response_type": "code",
            "response_mode": "form_post",
            "client_id": services_id,
            "redirect_uri": redirect_uri,
            "scope": "name email",
            "state": state,
            "nonce": hash_raw_nonce(raw_nonce),
            "code_challenge": pkce_challenge,
            "code_challenge_method": "S256",
        }
        from urllib.parse import urlencode

        url = f"{AppleEndpoints.AUTHORIZE}?{urlencode(params)}"

        blockauth_logger.info(
            "apple.web.authorize_started",
            {"client_id_suffix": services_id[-6:]},
        )

        response = redirect(url)
        samesite = _samesite_for_callback()
        set_state_cookie(response, state, samesite=samesite)
        set_pkce_verifier_cookie(response, pkce_verifier, samesite=samesite)
        set_nonce_cookie(response, raw_nonce, samesite=samesite)
        return response


class AppleWebCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**apple_callback_schema)
    def post(self, request):
        code = request.data.get("code")
        form_state = request.data.get("state")
        if not code:
            raise ValidationError({"detail": "Missing authorization code"}, 4054)

        cookie_state = request.COOKIES.get(OAUTH_STATE_COOKIE_NAME)
        verify_state_values(cookie_state, form_state)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = read_nonce_cookie(request)
        if not raw_nonce:
            raise ValidationError({"detail": "Apple nonce cookie missing"}, 4055)

        try:
            client_secret = AppleClientSecretBuilder().build()
        except AppleClientSecretConfigError as exc:
            raise ValidationError({"detail": str(exc)}, 4020)

        token_response = requests.post(
            AppleEndpoints.TOKEN,
            data={
                "client_id": get_config("APPLE_SERVICES_ID"),
                "client_secret": client_secret,
                "code": code,
                "code_verifier": pkce_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": get_config("APPLE_REDIRECT_URI"),
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            blockauth_logger.error(
                "apple.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            raise AppleTokenExchangeFailed(token_response.status_code, token_response.text)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        refresh_token = token_payload.get("refresh_token")
        if not id_token:
            raise ValidationError({"detail": "Apple did not return id_token"}, 4054)

        expected_nonce = hash_raw_nonce(raw_nonce)
        try:
            claims = AppleIdTokenVerifier().verify(id_token, expected_nonce=expected_nonce)
        except AppleNonceMismatch as exc:
            raise ValidationError({"detail": str(exc)}, 4055)
        except AppleIdTokenVerificationFailed as exc:
            raise ValidationError({"detail": str(exc)}, 4054)

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="apple",
                subject=claims.sub,
                email=claims.email,
                email_verified=claims.email_verified,
                extra_claims={"is_private_email": claims.is_private_email},
                refresh_token=refresh_token,
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.email or "",
            name="",
            provider_data={"provider": "apple", "user_info": claims.raw, "preexisting_user": user},
        )

        response = self.build_success_response(request, result)
        samesite = _samesite_for_callback()
        clear_state_cookie(response, samesite=samesite)
        clear_pkce_verifier_cookie(response, samesite=samesite)
        clear_nonce_cookie(response, samesite=samesite)
        return response
```

- [ ] **Step 3: Wire URLs (preview — full URL wiring lands in Phase 16)**

Append to `blockauth/urls.py` `urlpatterns` (temporary placement; Phase 16 will move these into the feature-flag dispatch):

```python
from blockauth.apple.views import AppleWebAuthorizeView, AppleWebCallbackView
from blockauth.constants.core import URLNames

urlpatterns += [
    path("apple/", AppleWebAuthorizeView.as_view(), name=URLNames.APPLE_LOGIN),
    path("apple/callback/", AppleWebCallbackView.as_view(), name=URLNames.APPLE_CALLBACK),
]
```

- [ ] **Step 4: Run web view tests**

Run: `uv run pytest blockauth/apple/tests/test_web_views.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/apple/views.py blockauth/apple/docs.py blockauth/urls.py blockauth/apple/tests/test_web_views.py
git commit -m "feat(apple): web authorize + form_post callback with PKCE and nonce"
```

---

## Phase 9: Apple native verify

### Task 9.1: AppleNativeVerifyView — failing test + impl

**Files:**
- Test: `blockauth/apple/tests/test_native_view.py` (Create)
- Modify: `blockauth/apple/views.py` (append `AppleNativeVerifyView`)
- Modify: `blockauth/urls.py` (register route)

- [ ] **Step 1: Write failing test**

```python
"""Apple native id_token verify tests.

Covers: id_token verification path, conditional nonce on `nonce_supported`,
optional authorization_code redemption, missing raw_nonce.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings


@pytest.fixture
def apple_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": _es256_pem(),
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
        }
    ):
        yield


def _es256_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.mark.django_db
def test_native_verify_happy_path(apple_settings, client, build_id_token, jwks_payload_bytes):
    raw_nonce = "raw-nonce-value"
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.native.subject",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_hash,
            "nonce_supported": True,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/apple/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 200
    body = response.json()
    assert "access" in body and "refresh" in body and "user" in body


@pytest.mark.django_db
def test_native_verify_redeems_authorization_code(apple_settings, client, build_id_token, jwks_payload_bytes):
    raw_nonce = "raw-nonce-2"
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.native.code",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_hash,
            "nonce_supported": True,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"refresh_token": "apple-refresh-from-code"}

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response), patch(
        "blockauth.apple.views.requests.post", return_value=token_response
    ) as mock_post:
        response = client.post(
            "/auth/apple/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce, "authorization_code": "auth-code"},
            content_type="application/json",
        )

    assert response.status_code == 200
    assert mock_post.call_args.kwargs["data"]["code"] == "auth-code"
    assert mock_post.call_args.kwargs["data"]["grant_type"] == "authorization_code"


@pytest.mark.django_db
def test_native_verify_skips_nonce_when_unsupported(apple_settings, client, build_id_token, jwks_payload_bytes):
    """`nonce_supported=False` from older Apple devices: server must not reject."""
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.legacy.device",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce_supported": False,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/apple/verify/",
            data={"id_token": id_token, "raw_nonce": "anything"},
            content_type="application/json",
        )

    assert response.status_code == 200
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_native_view.py -v`
Expected: 404 — endpoint not yet registered.

- [ ] **Step 3: Append `AppleNativeVerifyView` to `blockauth/apple/views.py`**

```python
from blockauth.apple.docs import apple_native_verify_schema
from blockauth.apple.serializers import AppleNativeVerifyRequestSerializer


class AppleNativeVerifyView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**apple_native_verify_schema)
    def post(self, request):
        serializer = AppleNativeVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        expected_nonce = hash_raw_nonce(validated["raw_nonce"])
        try:
            claims = AppleIdTokenVerifier().verify(validated["id_token"], expected_nonce=expected_nonce)
        except AppleNonceMismatch as exc:
            raise ValidationError({"detail": str(exc)}, 4055)
        except AppleIdTokenVerificationFailed as exc:
            raise ValidationError({"detail": str(exc)}, 4054)

        refresh_token: str | None = None
        authorization_code = validated.get("authorization_code")
        if authorization_code:
            try:
                client_secret = AppleClientSecretBuilder().build()
            except AppleClientSecretConfigError as exc:
                raise ValidationError({"detail": str(exc)}, 4020)

            token_response = requests.post(
                AppleEndpoints.TOKEN,
                data={
                    "client_id": get_config("APPLE_SERVICES_ID"),
                    "client_secret": client_secret,
                    "code": authorization_code,
                    "grant_type": "authorization_code",
                    "redirect_uri": get_config("APPLE_REDIRECT_URI") or "",
                },
                timeout=10,
            )
            if token_response.status_code == 200:
                refresh_token = token_response.json().get("refresh_token")
            else:
                blockauth_logger.warning(
                    "apple.native.code_redemption_failed",
                    {"status_code": token_response.status_code},
                )

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="apple",
                subject=claims.sub,
                email=claims.email,
                email_verified=claims.email_verified,
                extra_claims={"is_private_email": claims.is_private_email},
                refresh_token=refresh_token,
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.email or "",
            name=" ".join(filter(None, [validated.get("first_name", ""), validated.get("last_name", "")])).strip(),
            provider_data={"provider": "apple", "user_info": claims.raw, "preexisting_user": user},
        )
        return self.build_success_response(request, result)
```

- [ ] **Step 4: Register route**

Edit `blockauth/urls.py`. Add to the temporary append block from Task 8.3:

```python
from blockauth.apple.views import AppleNativeVerifyView

urlpatterns += [
    path("apple/verify/", AppleNativeVerifyView.as_view(), name=URLNames.APPLE_NATIVE_VERIFY),
]
```

- [ ] **Step 5: Run native view tests**

Run: `uv run pytest blockauth/apple/tests/test_native_view.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add blockauth/apple/views.py blockauth/urls.py blockauth/apple/tests/test_native_view.py
git commit -m "feat(apple): native id_token verify endpoint with conditional nonce and code redemption"
```

---

## Phase 10: Apple revocation + pre_delete signal

### Task 10.1: AppleRevocationClient — failing test

**Files:**
- Test: `blockauth/apple/tests/test_revocation_client.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""AppleRevocationClient tests.

Behavior contract: POST to /auth/revoke with token + token_type_hint and the
ES256 client_secret. Treats HTTP 200 as success. On non-200, logs and returns
without raising — Apple deletion must continue regardless of network state.
"""

from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.revocation_client import AppleRevocationClient


@pytest.fixture
def configured(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        yield


@pytest.fixture
def es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def test_revoke_posts_to_apple(configured):
    success_response = MagicMock(status_code=200, text="")
    with patch("blockauth.apple.revocation_client.requests.post", return_value=success_response) as mock_post:
        AppleRevocationClient().revoke("apple-refresh-token")

    assert mock_post.call_count == 1
    call = mock_post.call_args
    assert call.args[0] == "https://appleid.apple.com/auth/revoke"
    assert call.kwargs["data"]["token"] == "apple-refresh-token"
    assert call.kwargs["data"]["token_type_hint"] == "refresh_token"
    assert call.kwargs["data"]["client_id"] == "com.example.services"


def test_revoke_swallows_non_200(configured):
    failing_response = MagicMock(status_code=500, text="server error")
    with patch("blockauth.apple.revocation_client.requests.post", return_value=failing_response):
        AppleRevocationClient().revoke("apple-refresh-token")
    # No exception raised; the test passes by reaching this line.


def test_revoke_swallows_network_error(configured):
    import requests as real_requests

    with patch(
        "blockauth.apple.revocation_client.requests.post",
        side_effect=real_requests.exceptions.ConnectionError("no network"),
    ):
        AppleRevocationClient().revoke("apple-refresh-token")
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_revocation_client.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.revocation_client'`.

### Task 10.2: AppleRevocationClient — implementation

**Files:**
- Create: `blockauth/apple/revocation_client.py`

- [ ] **Step 1: Implement client**

```python
"""Apple Sign-In revocation client.

Posts to https://appleid.apple.com/auth/revoke with the user's refresh token.
Failures (non-200, network errors) are logged but do not raise — account
deletion in the calling system must complete even if Apple's endpoint is
temporarily unreachable. Apple does not redeliver missed revocations
automatically; integrators with stricter requirements can re-call this with
the encrypted refresh token from a deleted SocialIdentity row before
finalising the deletion transaction.
"""

import logging

import requests

from blockauth.apple.client_secret import AppleClientSecretBuilder
from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.exceptions import AppleClientSecretConfigError
from blockauth.utils.config import get_config

logger = logging.getLogger(__name__)


class AppleRevocationClient:
    def revoke(self, refresh_token: str) -> None:
        try:
            client_secret = AppleClientSecretBuilder().build()
        except AppleClientSecretConfigError as exc:
            logger.error("apple.revocation.config_missing", extra={"error_class": exc.__class__.__name__})
            return

        try:
            response = requests.post(
                AppleEndpoints.REVOKE,
                data={
                    "client_id": get_config("APPLE_SERVICES_ID"),
                    "client_secret": client_secret,
                    "token": refresh_token,
                    "token_type_hint": "refresh_token",
                },
                timeout=10,
            )
        except requests.RequestException as exc:
            logger.error("apple.revocation.network_error", extra={"error_class": exc.__class__.__name__})
            return

        if response.status_code != 200:
            logger.error("apple.revocation.failed", extra={"status_code": response.status_code})
        else:
            logger.info("apple.revocation.requested")
```

- [ ] **Step 2: Run revocation tests**

Run: `uv run pytest blockauth/apple/tests/test_revocation_client.py -v`
Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/apple/revocation_client.py blockauth/apple/tests/test_revocation_client.py
git commit -m "feat(apple): revocation client with failure-tolerant revoke"
```

### Task 10.3: pre_delete signal handler — failing test

**Files:**
- Test: `blockauth/apple/tests/test_signals.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""pre_delete signal: when a User is deleted, every Apple SocialIdentity
attached to it must trigger a revocation call before the cascade removes the
SocialIdentity rows.
"""

from unittest.mock import patch

import pytest

from blockauth.social.models import SocialIdentity
from blockauth.utils.config import get_block_auth_user_model

User = get_block_auth_user_model()


@pytest.mark.django_db
def test_user_delete_revokes_each_apple_identity(aes_key):
    import base64
    from django.test import override_settings

    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create(email="apple-user@example.com")
        from blockauth.social.service import SocialIdentityService

        service = SocialIdentityService()
        _, identity_a, _ = service.upsert_and_link(
            provider="apple", subject="a_sub_1", email=None, email_verified=False, extra_claims={}, refresh_token="refresh-1"
        )
        identity_a.user = user
        identity_a.save()

        _, identity_b, _ = service.upsert_and_link(
            provider="apple", subject="a_sub_2", email=None, email_verified=False, extra_claims={}, refresh_token="refresh-2"
        )
        identity_b.user = user
        identity_b.save()

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()

        revoked_tokens = sorted([call.args[0] for call in mock_revoke.call_args_list])
        assert revoked_tokens == ["refresh-1", "refresh-2"]


@pytest.mark.django_db
def test_user_delete_skips_non_apple_identities(aes_key):
    import base64
    from django.test import override_settings

    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create(email="google-user@gmail.com")
        from blockauth.social.service import SocialIdentityService

        SocialIdentityService().upsert_and_link(
            provider="google", subject="g_sub_1", email="google-user@gmail.com", email_verified=True, extra_claims={}
        )

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()

        assert mock_revoke.call_count == 0
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_signals.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.signals'`.

### Task 10.4: pre_delete signal handler — implementation

**Files:**
- Create: `blockauth/apple/signals.py`

- [ ] **Step 1: Implement signal**

```python
"""Apple pre_delete signal handler.

When a User row is about to be deleted, find every linked Apple
`SocialIdentity` and revoke its refresh token at Apple's /auth/revoke endpoint.
The actual cascade-delete of SocialIdentity rows is done by Django's CASCADE.

`receiver` is wired in `apple/apps.py:ready()`; importing this module is
sufficient to register the handler.
"""

import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from blockauth.apple.revocation_client import AppleRevocationClient
from blockauth.social.models import SocialIdentity
from blockauth.social.service import SocialIdentityService
from blockauth.utils.config import get_block_auth_user_model

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=get_block_auth_user_model())
def revoke_apple_identities(sender, instance, **kwargs):
    apple_identities = SocialIdentity.objects.filter(user=instance, provider="apple")
    if not apple_identities.exists():
        return

    service = SocialIdentityService()
    client = AppleRevocationClient()
    for identity in apple_identities:
        try:
            refresh_token = service.decrypt_refresh_token(identity)
        except Exception as exc:  # decryption failure should not block deletion
            logger.error(
                "apple.revocation.refresh_decrypt_failed",
                extra={"user_id": str(instance.id), "error_class": exc.__class__.__name__},
            )
            continue
        if not refresh_token:
            continue
        client.revoke(refresh_token)
```

- [ ] **Step 2: Run signal tests**

Run: `uv run pytest blockauth/apple/tests/test_signals.py -v`
Expected: 2 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/apple/signals.py blockauth/apple/tests/test_signals.py
git commit -m "feat(apple): pre_delete signal revokes Apple refresh tokens on account deletion"
```

---

## Phase 11: Apple server-to-server notifications

### Task 11.1: AppleNotificationService — failing test

**Files:**
- Test: `blockauth/apple/tests/test_notification_service.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""AppleNotificationService tests.

Apple's S2S notification body is `{"payload": "<JWT>"}`. The JWT is signed with
the same Apple keys used for id_tokens. Inside, the `events` claim carries
either a JSON string (legacy) or a JSON object (newer).
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.notification_service import AppleNotificationService
from blockauth.social.models import SocialIdentity
from blockauth.utils.config import get_block_auth_user_model

User = get_block_auth_user_model()


@pytest.fixture
def apple_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": (),
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
def test_consent_revoked_deletes_social_identity_only(apple_settings, build_id_token, jwks_response):
    user = User.objects.create(email="alice@example.com")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.consent",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": json.dumps(
                {"type": "consent-revoked", "sub": "001234.consent", "event_time": 1700000000}
            ),
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.consent").exists()
    assert User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_account_delete_with_only_apple_link_deletes_user(apple_settings, build_id_token, jwks_response):
    user = User.objects.create(email="bob@example.com")
    SocialIdentity.objects.create(
        provider="apple", subject="001234.acct", user=user, email_at_link=None, email_verified_at_link=False
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "events": {"type": "account-delete", "sub": "001234.acct", "event_time": 1700000001},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_account_delete_with_other_links_keeps_user(apple_settings, build_id_token, jwks_response):
    user = User.objects.create(email="carol@example.com")
    SocialIdentity.objects.create(
        provider="apple", subject="001234.dual", user=user, email_at_link=None, email_verified_at_link=False
    )
    SocialIdentity.objects.create(
        provider="google", subject="g_dual", user=user, email_at_link="carol@example.com", email_verified_at_link=True
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "events": {"type": "account-delete", "sub": "001234.dual", "event_time": 1700000002},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.dual").exists()
    assert SocialIdentity.objects.filter(provider="google", subject="g_dual").exists()


@pytest.mark.django_db
def test_email_disabled_is_logged_only(apple_settings, build_id_token, jwks_response):
    user = User.objects.create(email="dave@example.com")
    SocialIdentity.objects.create(
        provider="apple", subject="001234.email", user=user, email_at_link=None, email_verified_at_link=False
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "events": {"type": "email-disabled", "sub": "001234.email", "event_time": 1700000003},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert SocialIdentity.objects.filter(provider="apple", subject="001234.email").exists()
    assert User.objects.filter(id=user.id).exists()


def test_invalid_jwt_raises(apple_settings, jwks_response):
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(Exception):
            AppleNotificationService().dispatch("not-a-jwt")
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/apple/tests/test_notification_service.py -v`
Expected: collection error `ModuleNotFoundError: No module named 'blockauth.apple.notification_service'`.

### Task 11.2: AppleNotificationService — implementation

**Files:**
- Create: `blockauth/apple/notification_service.py`

- [ ] **Step 1: Implement service**

```python
"""Apple server-to-server notification dispatcher.

Apple posts {"payload": "<JWT>"} to the integrator's webhook. The JWT is signed
with the same keys used for id_tokens; the audience is the integrator's
Services ID.

The `events` claim is sometimes a JSON string (legacy) and sometimes a JSON
object (newer). We parse defensively.

Event handling:
  - consent-revoked -> drop the SocialIdentity for (apple, sub)
  - account-delete  -> if user has no other social identities, delete the User
  - email-disabled / email-enabled -> log only
"""

import json
import logging
from dataclasses import dataclass
from typing import Any

from django.db import transaction

from blockauth.apple.constants import AppleClaimKeys, AppleNotificationEvents
from blockauth.apple.id_token_verifier import AppleIdTokenVerifier
from blockauth.social.models import SocialIdentity
from blockauth.utils.config import get_config
from blockauth.utils.generics import import_string_or_none

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppleNotificationDispatchResult:
    event_type: str
    handled: bool


def _parse_events_claim(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(raw)
    raise TypeError(f"Unexpected events claim type: {type(raw)!r}")


class AppleNotificationService:
    def dispatch(self, payload_jwt: str) -> AppleNotificationDispatchResult:
        services_id = get_config("APPLE_SERVICES_ID")
        if not services_id:
            raise RuntimeError("APPLE_SERVICES_ID is not configured")

        claims = AppleIdTokenVerifier().verify_raw(payload_jwt, audiences=(services_id,))
        events = _parse_events_claim(claims.get(AppleClaimKeys.EVENTS))
        event_type = str(events.get("type") or "")
        sub = str(events.get("sub") or "")
        logger.info("apple.notification.received", extra={"event_type": event_type})

        handled = False
        if event_type == AppleNotificationEvents.CONSENT_REVOKED:
            handled = self._handle_consent_revoked(sub)
        elif event_type == AppleNotificationEvents.ACCOUNT_DELETE:
            handled = self._handle_account_delete(sub)
        elif event_type in (AppleNotificationEvents.EMAIL_DISABLED, AppleNotificationEvents.EMAIL_ENABLED):
            handled = True

        trigger_path = get_config("APPLE_NOTIFICATION_TRIGGER")
        trigger = import_string_or_none(trigger_path) if trigger_path else None
        if trigger:
            try:
                trigger().run({"event_type": event_type, "sub": sub, "claims": claims})
            except Exception as exc:  # never let an integrator hook bring down the webhook
                logger.error("apple.notification.trigger_failed", extra={"error_class": exc.__class__.__name__})

        return AppleNotificationDispatchResult(event_type=event_type, handled=handled)

    @staticmethod
    @transaction.atomic
    def _handle_consent_revoked(sub: str) -> bool:
        identity = SocialIdentity.objects.filter(provider="apple", subject=sub).first()
        if identity is None:
            return False
        identity.delete()
        return True

    @staticmethod
    @transaction.atomic
    def _handle_account_delete(sub: str) -> bool:
        identity = SocialIdentity.objects.select_related("user").filter(provider="apple", subject=sub).first()
        if identity is None:
            return False
        user = identity.user
        other_count = SocialIdentity.objects.filter(user=user).exclude(provider="apple", subject=sub).count()
        if other_count == 0:
            user.delete()  # CASCADE removes the apple identity row too
            logger.info("apple.notification.account_deleted", extra={"user_id": str(user.id)})
            return True
        identity.delete()
        return True
```

- [ ] **Step 2: Add the helper `import_string_or_none` if it does not yet exist**

Inspect `blockauth/utils/generics.py`. If `import_string_or_none` is absent, add:

```python
from importlib import import_module
from typing import Any


def import_string_or_none(dotted_path: str | None) -> Any | None:
    if not dotted_path:
        return None
    module_name, _, attr = dotted_path.rpartition(".")
    if not module_name:
        return None
    return getattr(import_module(module_name), attr)
```

- [ ] **Step 3: Run notification service tests**

Run: `uv run pytest blockauth/apple/tests/test_notification_service.py -v`
Expected: 5 passed.

- [ ] **Step 4: Commit**

```bash
git add blockauth/apple/notification_service.py blockauth/utils/generics.py blockauth/apple/tests/test_notification_service.py
git commit -m "feat(apple): S2S notification dispatcher with events-string-or-object handling"
```

### Task 11.3: AppleServerToServerNotificationView

**Files:**
- Modify: `blockauth/apple/views.py` (append `AppleServerToServerNotificationView`)
- Modify: `blockauth/urls.py`

- [ ] **Step 1: Append view to `blockauth/apple/views.py`**

```python
from blockauth.apple.docs import apple_notifications_schema
from blockauth.apple.notification_service import AppleNotificationService
from blockauth.apple.serializers import AppleServerToServerNotificationRequestSerializer


class AppleServerToServerNotificationView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**apple_notifications_schema)
    def post(self, request):
        serializer = AppleServerToServerNotificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            AppleNotificationService().dispatch(serializer.validated_data["payload"])
        except Exception as exc:
            blockauth_logger.error(
                "apple.notification.verification_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Invalid Apple notification payload"}, 4056)
        return Response(status=drf_status.HTTP_200_OK)
```

- [ ] **Step 2: Register URL**

Edit `blockauth/urls.py`:

```python
from blockauth.apple.views import AppleServerToServerNotificationView

urlpatterns += [
    path("apple/notifications/", AppleServerToServerNotificationView.as_view(), name=URLNames.APPLE_NOTIFICATIONS),
]
```

- [ ] **Step 3: Smoke-test endpoint**

Add to `blockauth/apple/tests/test_notification_service.py` (a separate test file is fine too — keep with the service for cohesion):

```python
@pytest.mark.django_db
def test_notification_endpoint_returns_200_on_valid_payload(apple_settings, build_id_token, jwks_response, client):
    user = User.objects.create(email="end@example.com")
    SocialIdentity.objects.create(
        provider="apple", subject="001234.endpoint", user=user, email_at_link=None, email_verified_at_link=False
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "events": {"type": "consent-revoked", "sub": "001234.endpoint", "event_time": 1700000004},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/apple/notifications/",
            data={"payload": payload_jwt},
            content_type="application/json",
        )

    assert response.status_code == 200


@pytest.mark.django_db
def test_notification_endpoint_returns_400_on_bad_payload(apple_settings, jwks_response, client):
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/apple/notifications/",
            data={"payload": "not-a-real-jwt"},
            content_type="application/json",
        )

    assert response.status_code == 400
```

- [ ] **Step 4: Run notification endpoint tests**

Run: `uv run pytest blockauth/apple/tests/test_notification_service.py -v`
Expected: 7 passed total (5 service + 2 endpoint).

- [ ] **Step 5: Commit**

```bash
git add blockauth/apple/views.py blockauth/urls.py blockauth/apple/tests/test_notification_service.py
git commit -m "feat(apple): server-to-server notification webhook endpoint"
```

---

## Phase 12: Google Native id_token verify

### Task 12.1: GoogleNativeIdTokenVerifyView — failing test

**Files:**
- Test: `blockauth/views/tests/test_google_native_view.py` (Create)

- [ ] **Step 1: Write failing test**

```python
"""Google Native id_token verify endpoint.

Covers: happy path with valid id_token, raw_nonce missing -> 400, audience
mismatch -> 400, signature invalid -> 400.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings


@pytest.fixture
def google_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "GOOGLE_NATIVE_AUDIENCES": ("123-web.apps.googleusercontent.com",),
            "FEATURES": {"GOOGLE_NATIVE_LOGIN": True, "SOCIAL_AUTH": True},
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
def test_native_verify_happy_path(google_settings, client, build_id_token, jwks_response):
    raw_nonce = "raw-nonce-google"
    expected = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "google-native-sub-1",
            "email": "u@gmail.com",
            "email_verified": True,
            "azp": "android-client.apps.googleusercontent.com",
            "nonce": expected,
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/google/native/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 200
    body = response.json()
    assert "access" in body and "refresh" in body and "user" in body


@pytest.mark.django_db
def test_native_verify_audience_mismatch_rejected(google_settings, client, build_id_token, jwks_response):
    raw_nonce = "raw-nonce-google-2"
    expected = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "wrong-audience.apps.googleusercontent.com",
            "sub": "google-native-sub-2",
            "email": "u@gmail.com",
            "email_verified": True,
            "nonce": expected,
        }
    )
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/auth/google/native/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 400


@pytest.mark.django_db
def test_native_verify_missing_raw_nonce_rejected(google_settings, client, build_id_token, jwks_response):
    id_token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "x", "email": "u@gmail.com", "email_verified": True}
    )
    response = client.post("/auth/google/native/verify/", data={"id_token": id_token}, content_type="application/json")
    assert response.status_code == 400
```

- [ ] **Step 2: Run test, verify it fails**

Run: `uv run pytest blockauth/views/tests/test_google_native_view.py -v`
Expected: 404 (URL not registered) or import error for `blockauth.views.google_native_views`.

### Task 12.2: GoogleNativeIdTokenVerifyView — implementation

**Files:**
- Create: `blockauth/views/google_native_views.py`
- Modify: `blockauth/urls.py`

- [ ] **Step 1: Create the view**

```python
"""Google Native id_token verify endpoint.

Accepts a Google-issued id_token from Android Credential Manager, the iOS
Google Sign-In SDK, or Web One Tap, plus the raw_nonce the client passed when
requesting it. The audience allowlist contains the Web (server) OAuth client
IDs the integrator registered. The `azp` claim — which carries the platform
client ID — is captured but not enforced; integrators can validate it via a
post-login trigger if they wish.
"""

import hashlib
import logging

from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.serializers import CharField, Serializer
from rest_framework.views import APIView

from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.config import get_config
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)


GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"


class GoogleNativeIdTokenVerifyRequestSerializer(Serializer):
    id_token = CharField()
    raw_nonce = CharField()


def _build_google_native_verifier() -> OIDCTokenVerifier:
    audiences = tuple(get_config("GOOGLE_NATIVE_AUDIENCES") or ())
    if not audiences:
        raise ValidationError({"detail": "Google native audiences are not configured"}, 4020)
    cache_ttl = int(get_config("OIDC_JWKS_CACHE_TTL_SECONDS") or 3600)
    leeway = int(get_config("OIDC_VERIFIER_LEEWAY_SECONDS") or 60)
    config = OIDCVerifierConfig(
        issuer=GOOGLE_ISSUER,
        jwks_uri=GOOGLE_JWKS_URI,
        audiences=audiences,
        algorithms=("RS256",),
        leeway_seconds=leeway,
    )
    return OIDCTokenVerifier(config, jwks_cache=JWKSCache(GOOGLE_JWKS_URI, cache_ttl_seconds=cache_ttl))


class GoogleNativeIdTokenVerifyView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(summary="Verify Google id_token from native client")
    def post(self, request):
        serializer = GoogleNativeIdTokenVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        expected_nonce = hashlib.sha256(validated["raw_nonce"].encode("utf-8")).hexdigest()
        try:
            claims = _build_google_native_verifier().verify(validated["id_token"], expected_nonce=expected_nonce)
        except OIDCVerificationError as exc:
            blockauth_logger.error("google.native.verify_failed", {"error_class": exc.__class__.__name__})
            raise ValidationError({"detail": str(exc)}, 4061)

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="google",
                subject=str(claims["sub"]),
                email=claims.get("email"),
                email_verified=bool(claims.get("email_verified")),
                extra_claims={"hd": claims.get("hd"), "azp": claims.get("azp")},
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.get("email") or "",
            name=claims.get("name") or "",
            provider_data={"provider": "google", "user_info": claims, "preexisting_user": user},
        )
        return self.build_success_response(request, result)
```

- [ ] **Step 2: Wire URL**

Edit `blockauth/urls.py`. Add to the temporary append block:

```python
from blockauth.views.google_native_views import GoogleNativeIdTokenVerifyView

urlpatterns += [
    path("google/native/verify/", GoogleNativeIdTokenVerifyView.as_view(), name=URLNames.GOOGLE_NATIVE_VERIFY),
]
```

- [ ] **Step 3: Run native view tests**

Run: `uv run pytest blockauth/views/tests/test_google_native_view.py -v`
Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add blockauth/views/google_native_views.py blockauth/urls.py blockauth/views/tests/test_google_native_view.py
git commit -m "feat(google): native id_token verify endpoint shared OIDC verifier"
```

---

## Phase 13: Refactor Google web OAuth

### Task 13.1: Update Google web tests for new behavior

**Files:**
- Modify: `blockauth/views/tests/test_oauth_views.py` (replace Google tests)

- [ ] **Step 1: Replace existing Google web tests**

Open `blockauth/views/tests/test_oauth_views.py`. Locate the existing Google test class/section (search for `google_auth_views` or `google/callback`). Replace it with the following block. The new tests assert: PKCE in the authorize URL, nonce in the authorize URL, token endpoint called with code_verifier, id_token verified via JWKS, no userinfo HTTP call, user upserted via SocialIdentity.

```python
"""Refactored Google web OAuth — id_token verify, PKCE, nonce, SocialIdentity."""

import hashlib
import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from django.test import override_settings

from blockauth.apple.nonce import APPLE_NONCE_COOKIE_NAME  # not used; reference only
from blockauth.utils.oauth_state import OAUTH_PKCE_VERIFIER_COOKIE_NAME, OAUTH_STATE_COOKIE_NAME


@pytest.fixture
def google_web_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "GOOGLE_CLIENT_ID": "123-web.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "secret-shh",
            "GOOGLE_REDIRECT_URI": "https://app.example.com/auth/google/callback/",
            "GOOGLE_NATIVE_AUDIENCES": ("123-web.apps.googleusercontent.com",),
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
def test_google_authorize_includes_pkce_and_nonce(google_web_settings, client):
    response = client.get("/auth/google/")
    assert response.status_code == 302
    parsed = urlparse(response["Location"])
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["123-web.apps.googleusercontent.com"]
    assert qs["scope"][0].startswith("openid")
    assert qs["code_challenge_method"] == ["S256"]
    assert "code_challenge" in qs
    assert "nonce" in qs

    cookies = response.cookies
    assert OAUTH_STATE_COOKIE_NAME in cookies
    assert OAUTH_PKCE_VERIFIER_COOKIE_NAME in cookies
    assert "blockauth_google_nonce" in cookies


@pytest.mark.django_db
def test_google_callback_verifies_id_token_and_links_identity(google_web_settings, client, build_id_token, jwks_response):
    init = client.get("/auth/google/")
    state = init.cookies[OAUTH_STATE_COOKIE_NAME].value
    pkce_verifier = init.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value
    raw_nonce = init.cookies["blockauth_google_nonce"].value
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()

    google_id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "google-web-sub-1",
            "email": "u@gmail.com",
            "email_verified": True,
            "name": "User Example",
            "nonce": expected_hash,
        }
    )
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"access_token": "google-access", "id_token": google_id_token}

    with patch("blockauth.views.google_auth_views.requests.post", return_value=token_response) as mock_post, patch(
        "blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response
    ), patch("blockauth.views.google_auth_views.requests.get") as mock_get_userinfo:
        callback = client.get(f"/auth/google/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200
    body = callback.json()
    assert "access" in body and "refresh" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    mock_get_userinfo.assert_not_called()
```

- [ ] **Step 2: Run, verify failure (expected — old views still in place)**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k google -v`
Expected: failures referencing `code_challenge` not in query string, or test errors importing `blockauth_google_nonce` cookie name.

### Task 13.2: Refactor `google_auth_views.py`

**Files:**
- Modify: `blockauth/views/google_auth_views.py`

- [ ] **Step 1: Replace `GoogleAuthLoginView` and `GoogleAuthCallbackView`**

```python
"""Google OAuth web flow.

Refactored from the previous email-based matching path to use:
  - PKCE (RFC 7636) on the authorization request and token exchange.
  - Nonce: random raw value stored in HttpOnly cookie at /google/, sha256 of
    raw value sent as the `nonce` parameter, and compared to the id_token's
    `nonce` claim on callback.
  - id_token verification via OIDCTokenVerifier with Google's JWKS — replaces
    the previous `userinfo` HTTP call.
  - SocialIdentity link via `(provider="google", subject=sub)`. Falls back to
    linking by Google-authoritative email (gmail.com or `hd` claim) per
    `AccountLinkingPolicy`.
"""

import hashlib
import logging
import secrets
import urllib.parse

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import google_auth_callback_schema, google_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.config import get_config
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state,
    OAUTH_STATE_COOKIE_NAME,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_NONCE_COOKIE_NAME = "blockauth_google_nonce"
GOOGLE_NONCE_BYTES = 32


def _build_verifier() -> OIDCTokenVerifier:
    audiences = (get_config("GOOGLE_CLIENT_ID"),)
    cache_ttl = int(get_config("OIDC_JWKS_CACHE_TTL_SECONDS") or 3600)
    leeway = int(get_config("OIDC_VERIFIER_LEEWAY_SECONDS") or 60)
    config = OIDCVerifierConfig(
        issuer=GOOGLE_ISSUER,
        jwks_uri=GOOGLE_JWKS_URI,
        audiences=audiences,
        algorithms=("RS256",),
        leeway_seconds=leeway,
    )
    return OIDCTokenVerifier(config, jwks_cache=JWKSCache(GOOGLE_JWKS_URI, cache_ttl_seconds=cache_ttl))


class GoogleAuthLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**google_auth_login_schema)
    def get(self, request):
        client_id = get_config("GOOGLE_CLIENT_ID")
        redirect_uri = get_config("GOOGLE_REDIRECT_URI")
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        raw_nonce = secrets.token_urlsafe(GOOGLE_NONCE_BYTES)
        hashed_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()
        pkce_verifier, pkce_challenge = generate_pkce_pair()

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": hashed_nonce,
            "code_challenge": pkce_challenge,
            "code_challenge_method": "S256",
            "access_type": "online",
            "prompt": "select_account",
        }
        url = f"{GOOGLE_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info("google.web.authorize_started", {"client_id_suffix": client_id[-6:]})

        response = redirect(url)
        set_state_cookie(response, state)
        set_pkce_verifier_cookie(response, pkce_verifier)
        response.set_cookie(
            GOOGLE_NONCE_COOKIE_NAME,
            raw_nonce,
            max_age=600,
            httponly=True,
            secure=True,
            samesite="Lax",
        )
        return response


class GoogleAuthCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**google_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value)

        client_id = get_config("GOOGLE_CLIENT_ID")
        client_secret = get_config("GOOGLE_CLIENT_SECRET")
        redirect_uri = get_config("GOOGLE_REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value)

        verify_state(request)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = request.COOKIES.get(GOOGLE_NONCE_COOKIE_NAME)
        if not raw_nonce:
            raise ValidationError({"detail": "OAuth nonce missing"}, 4061)
        expected_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()

        token_response = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": pkce_verifier,
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            blockauth_logger.error(
                "google.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            return Response(data={"detail": "Token exchange failed"}, status=token_response.status_code)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        if not id_token:
            raise ValidationError({"detail": "Google did not return id_token"}, 4061)

        try:
            claims = _build_verifier().verify(id_token, expected_nonce=expected_nonce)
        except OIDCVerificationError as exc:
            blockauth_logger.error("google.web.id_token_verify_failed", {"error_class": exc.__class__.__name__})
            raise ValidationError({"detail": str(exc)}, 4061)

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="google",
                subject=str(claims["sub"]),
                email=claims.get("email"),
                email_verified=bool(claims.get("email_verified")),
                extra_claims={"hd": claims.get("hd")},
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.get("email") or "",
            name=claims.get("name") or "",
            provider_data={"provider": "google", "user_info": claims, "preexisting_user": user},
        )
        response = self.build_success_response(request, result)
        clear_state_cookie(response)
        clear_pkce_verifier_cookie(response)
        response.delete_cookie(GOOGLE_NONCE_COOKIE_NAME, samesite="Lax")
        return response
```

- [ ] **Step 2: Update `blockauth/utils/social.py` to accept a pre-existing user**

The existing `social_login_data` creates/updates by email. To preserve its trigger-firing and JWT-issuance behavior while letting `SocialIdentityService` own user creation, accept a `preexisting_user` in `provider_data` and skip the `get_or_create(email=...)` step when it is present:

```python
# inside social_login_data
preexisting_user = (provider_data or {}).get("preexisting_user") if provider_data else None
if preexisting_user is not None:
    user = preexisting_user
    created = False
else:
    user, created = _User.objects.get_or_create(email=email, defaults=defaults)
```

The remaining body (last_login, authentication_types append, is_verified promotion for Google, save, triggers, JWT issuance) runs unchanged.

- [ ] **Step 3: Run Google tests**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k google -v`
Expected: 2 passed.

- [ ] **Step 4: Run all OAuth tests to verify Facebook/LinkedIn still pass with the social_login_data change**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -v`
Expected: previously-passing tests for Facebook/LinkedIn still pass; only Google sections changed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/views/google_auth_views.py blockauth/utils/social.py blockauth/views/tests/test_oauth_views.py
git commit -m "refactor(google): web OAuth uses id_token verify, PKCE, nonce, SocialIdentity"
```

---

## Phase 14: Refactor LinkedIn web OAuth

LinkedIn is OIDC since 2024 (issuer `https://www.linkedin.com`, JWKS `https://www.linkedin.com/oauth/openid/jwks`). The refactor mirrors Google's: drop the userinfo HTTP call, verify the id_token, link by `(linkedin, sub)`, add PKCE + nonce.

### Task 14.1: Update LinkedIn tests

**Files:**
- Modify: `blockauth/views/tests/test_oauth_views.py` (replace LinkedIn tests)

- [ ] **Step 1: Replace LinkedIn test block**

Locate the existing LinkedIn test section and replace it with:

```python
@pytest.fixture
def linkedin_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "LINKEDIN_CLIENT_ID": "linkedin-client-id",
            "LINKEDIN_CLIENT_SECRET": "linkedin-secret",
            "LINKEDIN_REDIRECT_URI": "https://app.example.com/auth/linkedin/callback/",
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
        }
    ):
        yield


@pytest.fixture
def linkedin_jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
def test_linkedin_authorize_includes_pkce_and_nonce(linkedin_settings, client):
    response = client.get("/auth/linkedin/")
    assert response.status_code == 302
    parsed = urlparse(response["Location"])
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["linkedin-client-id"]
    assert "code_challenge" in qs
    assert qs["code_challenge_method"] == ["S256"]
    assert "nonce" in qs

    cookies = response.cookies
    assert OAUTH_STATE_COOKIE_NAME in cookies
    assert OAUTH_PKCE_VERIFIER_COOKIE_NAME in cookies
    assert "blockauth_linkedin_nonce" in cookies


@pytest.mark.django_db
def test_linkedin_callback_verifies_id_token(linkedin_settings, client, build_id_token, linkedin_jwks_response):
    init = client.get("/auth/linkedin/")
    state = init.cookies[OAUTH_STATE_COOKIE_NAME].value
    pkce_verifier = init.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value
    raw_nonce = init.cookies["blockauth_linkedin_nonce"].value
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()

    id_token = build_id_token(
        {
            "iss": "https://www.linkedin.com",
            "aud": "linkedin-client-id",
            "sub": "linkedin-sub-1",
            "email": "u@example.com",
            "email_verified": True,
            "name": "User Example",
            "nonce": expected_hash,
        }
    )
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"access_token": "li-access", "id_token": id_token}

    with patch("blockauth.views.linkedin_auth_views.requests.post", return_value=token_response) as mock_post, patch(
        "blockauth.utils.jwt.jwks_cache.requests.get", return_value=linkedin_jwks_response
    ), patch("blockauth.views.linkedin_auth_views.requests.get") as mock_userinfo:
        callback = client.get(f"/auth/linkedin/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200
    body = callback.json()
    assert "access" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    mock_userinfo.assert_not_called()
```

- [ ] **Step 2: Run, verify failure**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k linkedin -v`
Expected: failures (existing view does not implement PKCE / nonce / id_token verify yet).

### Task 14.2: Refactor `linkedin_auth_views.py`

**Files:**
- Modify: `blockauth/views/linkedin_auth_views.py`

- [ ] **Step 1: Replace both views**

```python
"""LinkedIn OAuth web flow.

LinkedIn finished its OIDC migration in 2024. We use the standard OIDC
discovery values: issuer `https://www.linkedin.com`, JWKS at
`https://www.linkedin.com/oauth/openid/jwks`. Audience is the integrator's
LinkedIn client ID.

Like the Google refactor, this drops the userinfo HTTP call in favor of the
id_token's email / name / sub claims, and links by `(linkedin, sub)`.
"""

import hashlib
import logging
import secrets
import urllib.parse

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import linkedin_auth_callback_schema, linkedin_auth_login_schema
from blockauth.schemas.examples.social_auth import social_authorization_code, social_invalid_auth_config
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.config import get_config
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)

LINKEDIN_AUTHORIZE_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_ISSUER = "https://www.linkedin.com"
LINKEDIN_JWKS_URI = "https://www.linkedin.com/oauth/openid/jwks"
LINKEDIN_NONCE_COOKIE_NAME = "blockauth_linkedin_nonce"
LINKEDIN_NONCE_BYTES = 32


def _build_verifier() -> OIDCTokenVerifier:
    audiences = (get_config("LINKEDIN_CLIENT_ID"),)
    config = OIDCVerifierConfig(
        issuer=LINKEDIN_ISSUER,
        jwks_uri=LINKEDIN_JWKS_URI,
        audiences=audiences,
        algorithms=("RS256",),
        leeway_seconds=int(get_config("OIDC_VERIFIER_LEEWAY_SECONDS") or 60),
    )
    return OIDCTokenVerifier(config, jwks_cache=JWKSCache(LINKEDIN_JWKS_URI, cache_ttl_seconds=int(get_config("OIDC_JWKS_CACHE_TTL_SECONDS") or 3600)))


class LinkedInAuthLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**linkedin_auth_login_schema)
    def get(self, request):
        client_id = get_config("LINKEDIN_CLIENT_ID")
        redirect_uri = get_config("LINKEDIN_REDIRECT_URI")
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        raw_nonce = secrets.token_urlsafe(LINKEDIN_NONCE_BYTES)
        hashed_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()
        pkce_verifier, pkce_challenge = generate_pkce_pair()

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": hashed_nonce,
            "code_challenge": pkce_challenge,
            "code_challenge_method": "S256",
        }
        url = f"{LINKEDIN_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info("linkedin.web.authorize_started", {"client_id_suffix": client_id[-6:]})

        response = redirect(url)
        set_state_cookie(response, state)
        set_pkce_verifier_cookie(response, pkce_verifier)
        response.set_cookie(
            LINKEDIN_NONCE_COOKIE_NAME,
            raw_nonce,
            max_age=600,
            httponly=True,
            secure=True,
            samesite="Lax",
        )
        return response


class LinkedInAuthCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**linkedin_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value)

        client_id = get_config("LINKEDIN_CLIENT_ID")
        client_secret = get_config("LINKEDIN_CLIENT_SECRET")
        redirect_uri = get_config("LINKEDIN_REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value)

        verify_state(request)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = request.COOKIES.get(LINKEDIN_NONCE_COOKIE_NAME)
        if not raw_nonce:
            raise ValidationError({"detail": "OAuth nonce missing"}, 4070)
        expected_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()

        token_response = requests.post(
            LINKEDIN_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": pkce_verifier,
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            blockauth_logger.error(
                "linkedin.web.token_exchange_failed", {"status_code": token_response.status_code}
            )
            return Response(data={"detail": "Token exchange failed"}, status=token_response.status_code)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        if not id_token:
            raise ValidationError({"detail": "LinkedIn did not return id_token"}, 4070)

        try:
            claims = _build_verifier().verify(id_token, expected_nonce=expected_nonce)
        except OIDCVerificationError as exc:
            blockauth_logger.error("linkedin.web.id_token_verify_failed", {"error_class": exc.__class__.__name__})
            raise ValidationError({"detail": str(exc)}, 4070)

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="linkedin",
                subject=str(claims["sub"]),
                email=claims.get("email"),
                email_verified=bool(claims.get("email_verified")),
                extra_claims={},
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.get("email") or "",
            name=claims.get("name") or "",
            provider_data={"provider": "linkedin", "user_info": claims, "preexisting_user": user},
        )
        response = self.build_success_response(request, result)
        clear_state_cookie(response)
        clear_pkce_verifier_cookie(response)
        response.delete_cookie(LINKEDIN_NONCE_COOKIE_NAME, samesite="Lax")
        return response
```

- [ ] **Step 2: Run LinkedIn tests**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k linkedin -v`
Expected: 2 passed.

- [ ] **Step 3: Commit**

```bash
git add blockauth/views/linkedin_auth_views.py blockauth/views/tests/test_oauth_views.py
git commit -m "refactor(linkedin): web OAuth uses OIDC id_token verify, PKCE, nonce, SocialIdentity"
```

---

## Phase 15: Refactor Facebook web OAuth

Facebook is not OIDC. The refactor adds PKCE and switches matching to `(facebook, user_id)` via `SocialIdentityService`. The Graph API call to `/me` stays — Facebook does not issue id_tokens on the standard flow.

### Task 15.1: Update Facebook tests

**Files:**
- Modify: `blockauth/views/tests/test_oauth_views.py` (replace Facebook tests)

- [ ] **Step 1: Replace Facebook test block**

```python
@pytest.fixture
def facebook_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "FACEBOOK_CLIENT_ID": "fb-client-id",
            "FACEBOOK_CLIENT_SECRET": "fb-secret",
            "FACEBOOK_REDIRECT_URI": "https://app.example.com/auth/facebook/callback/",
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
        }
    ):
        yield


@pytest.mark.django_db
def test_facebook_authorize_includes_pkce(facebook_settings, client):
    response = client.get("/auth/facebook/")
    assert response.status_code == 302
    parsed = urlparse(response["Location"])
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["fb-client-id"]
    assert "code_challenge" in qs
    assert qs["code_challenge_method"] == ["S256"]

    assert OAUTH_STATE_COOKIE_NAME in response.cookies
    assert OAUTH_PKCE_VERIFIER_COOKIE_NAME in response.cookies


@pytest.mark.django_db
def test_facebook_callback_links_by_subject(facebook_settings, client):
    init = client.get("/auth/facebook/")
    state = init.cookies[OAUTH_STATE_COOKIE_NAME].value

    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"access_token": "fb-access"}
    me_response = MagicMock(status_code=200)
    me_response.json.return_value = {"id": "fb_user_123", "name": "FB User", "email": "u@example.com"}

    with patch("blockauth.views.facebook_auth_views.requests.get", side_effect=[token_response, me_response]):
        callback = client.get(f"/auth/facebook/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200
    body = callback.json()
    assert "access" in body and "user" in body

    from blockauth.social.models import SocialIdentity
    assert SocialIdentity.objects.filter(provider="facebook", subject="fb_user_123").exists()
```

- [ ] **Step 2: Run, verify failure**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k facebook -v`
Expected: failures referencing `code_challenge`.

### Task 15.2: Refactor `facebook_auth_views.py`

**Files:**
- Modify: `blockauth/views/facebook_auth_views.py`

- [ ] **Step 1: Replace both views**

```python
"""Facebook OAuth web flow.

Facebook is not OIDC. The flow uses standard OAuth 2.0 + PKCE (S256). After
the code-for-token exchange we call Graph `/me?fields=id,name,email` to get
the user info — Facebook does not issue id_tokens on the standard login flow.

User matching: `(facebook, user_info["id"])` via SocialIdentityService.
Email is treated as verified when present (Facebook only returns the email
field for users who have verified it).
"""

import logging
import urllib.parse

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import facebook_auth_callback_schema, facebook_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
    social_user_info_missing,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.config import get_config
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)

FACEBOOK_AUTHORIZE_URL = "https://www.facebook.com/v18.0/dialog/oauth"
FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token"
FACEBOOK_USERINFO_URL = "https://graph.facebook.com/me"


class FacebookAuthLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**facebook_auth_login_schema)
    def get(self, request):
        client_id = get_config("FACEBOOK_CLIENT_ID")
        redirect_uri = get_config("FACEBOOK_REDIRECT_URI")
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        pkce_verifier, pkce_challenge = generate_pkce_pair()

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "email,public_profile",
            "response_type": "code",
            "state": state,
            "code_challenge": pkce_challenge,
            "code_challenge_method": "S256",
        }
        url = f"{FACEBOOK_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info("facebook.web.authorize_started", {"client_id_suffix": client_id[-6:]})

        response = redirect(url)
        set_state_cookie(response, state)
        set_pkce_verifier_cookie(response, pkce_verifier)
        return response


class FacebookAuthCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**facebook_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value)

        client_id = get_config("FACEBOOK_CLIENT_ID")
        client_secret = get_config("FACEBOOK_CLIENT_SECRET")
        redirect_uri = get_config("FACEBOOK_REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value)

        verify_state(request)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        token_response = requests.get(
            FACEBOOK_TOKEN_URL,
            params={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": pkce_verifier,
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            blockauth_logger.error("facebook.web.token_exchange_failed", {"status_code": token_response.status_code})
            return Response(data=token_response.json(), status=token_response.status_code)

        access_token = token_response.json().get("access_token")
        userinfo_response = requests.get(
            FACEBOOK_USERINFO_URL,
            params={"fields": "id,name,email", "access_token": access_token},
            timeout=10,
        )
        if userinfo_response.status_code != 200:
            return Response(data=userinfo_response.json(), status=userinfo_response.status_code)

        user_info = userinfo_response.json()
        fb_user_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name")
        if not fb_user_id or not name:
            raise ValidationError(social_user_info_missing.value, 4080)

        email_verified = bool(email)  # Facebook only returns email when verified

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="facebook",
                subject=str(fb_user_id),
                email=email,
                email_verified=email_verified,
                extra_claims={},
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=email or "",
            name=name,
            provider_data={"provider": "facebook", "user_info": user_info, "preexisting_user": user},
        )
        response = self.build_success_response(request, result)
        clear_state_cookie(response)
        clear_pkce_verifier_cookie(response)
        return response
```

- [ ] **Step 2: Run Facebook tests**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -k facebook -v`
Expected: 2 passed.

- [ ] **Step 3: Run all OAuth tests**

Run: `uv run pytest blockauth/views/tests/test_oauth_views.py -v`
Expected: all green (Google + Facebook + LinkedIn + native + apple covered above).

- [ ] **Step 4: Commit**

```bash
git add blockauth/views/facebook_auth_views.py blockauth/views/tests/test_oauth_views.py
git commit -m "refactor(facebook): web OAuth uses PKCE and SocialIdentity by FB user_id"
```

---

## Phase 16: URL registration via feature flags

The earlier phases appended URL routes to `urlpatterns` ad-hoc for testing. This phase moves them into the same feature-flag-driven dispatcher the existing OAuth providers use.

### Task 16.1: Wire Apple + Google native into URL pattern mappings

**Files:**
- Modify: `blockauth/urls.py`

- [ ] **Step 1: Inspect current dispatcher**

`blockauth/urls.py` already exposes `URL_PATTERN_MAPPINGS` (feature → list of `(path, view, name)` tuples) and `SOCIAL_URL_PATTERN_MAPPINGS` (provider → list). Confirm by reading the top of the file. The existing pattern is:

```python
for feature, patterns in URL_PATTERN_MAPPINGS.items():
    if is_feature_enabled(feature):
        urlpatterns.extend(...)
```

- [ ] **Step 2: Remove the temporary appends from earlier phases**

Delete the temporary `urlpatterns += [...]` blocks added in Tasks 8.3, 9.1, 11.3, 12.2.

- [ ] **Step 3: Add Apple + Google native to the mappings**

Inside the existing mapping definitions, add:

```python
# Apple endpoints — gated by APPLE_LOGIN feature, regardless of generic SOCIAL_AUTH
URL_PATTERN_MAPPINGS[Features.APPLE_LOGIN] = [
    ("apple/", AppleWebAuthorizeView, URLNames.APPLE_LOGIN),
    ("apple/callback/", AppleWebCallbackView, URLNames.APPLE_CALLBACK),
    ("apple/verify/", AppleNativeVerifyView, URLNames.APPLE_NATIVE_VERIFY),
    ("apple/notifications/", AppleServerToServerNotificationView, URLNames.APPLE_NOTIFICATIONS),
]

URL_PATTERN_MAPPINGS[Features.GOOGLE_NATIVE_LOGIN] = [
    ("google/native/verify/", GoogleNativeIdTokenVerifyView, URLNames.GOOGLE_NATIVE_VERIFY),
]
```

Adjust the import block at the top of `urls.py` accordingly:

```python
from blockauth.apple.views import (
    AppleNativeVerifyView,
    AppleServerToServerNotificationView,
    AppleWebAuthorizeView,
    AppleWebCallbackView,
)
from blockauth.views.google_native_views import GoogleNativeIdTokenVerifyView
```

- [ ] **Step 4: Verify URL resolution**

Run: `uv run pytest blockauth/apple/tests blockauth/views/tests/test_google_native_view.py -v`
Expected: all previously-passing tests still pass.

- [ ] **Step 5: Verify Django can `manage.py show_urls`-equivalent**

Run: `uv run python -c "
import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'blockauth.settings')
django.setup()
from django.urls import get_resolver
for p in get_resolver().url_patterns:
    print(p.pattern)
"`

Expected: list contains `apple/`, `apple/callback/`, `apple/verify/`, `apple/notifications/`, `google/native/verify/`.

- [ ] **Step 6: Commit**

```bash
git add blockauth/urls.py
git commit -m "feat(urls): wire Apple and Google native routes via feature flag dispatcher"
```

---

## Phase 17: Lint, format, migration verification

### Task 17.1: Lint and format check

**Files:** none modified — verification only.

- [ ] **Step 1: Run black**

Run: `uv run black --check blockauth/`
Expected: "All done!" with no diff. If it reports diffs, run `uv run black blockauth/` and re-commit:

```bash
uv run black blockauth/
git add blockauth/
git commit -m "chore: black format"
```

- [ ] **Step 2: Run isort**

Run: `uv run isort --check-only blockauth/`
Expected: no diff. If diffs exist, run `uv run isort blockauth/` and commit.

- [ ] **Step 3: Run flake8**

Run: `uv run flake8 blockauth/`
Expected: no warnings. Fix any reported issues.

- [ ] **Step 4: Run mypy on the new sub-packages**

Run: `uv run mypy blockauth/utils/jwt blockauth/social blockauth/apple blockauth/views/google_native_views.py`
Expected: success. Fix any annotation issues.

- [ ] **Step 5: Verify migrations are consistent**

Run: `uv run python -m django makemigrations --check --dry-run --settings=blockauth.settings`
Expected: "No changes detected" (the `social/migrations/0001_initial.py` from Task 2.3 should cover everything).

- [ ] **Step 6: Run the full test suite**

Run: `uv run pytest -v`
Expected: every test passes — no skipped, no xfail.

- [ ] **Step 7: Commit (if any auto-format changes were made)**

```bash
git status
# Only commit if there are unstaged formatting changes:
git add -A
git commit -m "chore: lint and format pass"
```

---

## Phase 18: Documentation, CHANGELOG, version bump

### Task 18.1: Update CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add 0.16.0 entry**

Open `CHANGELOG.md`. Insert above the most recent entry:

```markdown
## 0.16.0 — 2026-MM-DD

### Added
- **Apple Sign-In** — web flow (`GET /apple/`, `POST /apple/callback/` with form_post + PKCE + nonce), native verify (`POST /apple/verify/`), revocation via `pre_delete` signal, and server-to-server notifications webhook (`POST /apple/notifications/`).
- **Google native id_token verify** — `POST /google/native/verify/` for Android Credential Manager, iOS Google Sign-In SDK, and Web One Tap.
- **Generic OIDC token verifier** (`blockauth.utils.jwt.OIDCTokenVerifier`) with JWKS cache, kid rotation, audience allowlist, algorithm pinning, nonce check.
- **`SocialIdentity` model** — durable `(provider, subject)` link to User, with AES-GCM-256 refresh-token encryption at rest.
- **`AccountLinkingPolicy`** — provider-aware verified-email auto-link (gmail/hd for Google, verified-email for LinkedIn / Facebook; Apple identities are sub-only).
- **PKCE (RFC 7636)** on all web OAuth flows.
- New feature flags: `APPLE_LOGIN`, `GOOGLE_NATIVE_LOGIN`.
- New configuration: `APPLE_*`, `GOOGLE_NATIVE_AUDIENCES`, `OIDC_*`, `SOCIAL_IDENTITY_ENCRYPTION_KEY`.

### Changed
- **Refactored Google web OAuth** to verify the `id_token` cryptographically (drops the userinfo HTTP call) and link via `SocialIdentity` by subject. PKCE + nonce added.
- **Refactored LinkedIn web OAuth** onto OIDC (LinkedIn migrated in 2024). Same id_token verify + SocialIdentity + PKCE + nonce treatment as Google.
- **Refactored Facebook web OAuth** to use PKCE and link via `SocialIdentity` by Facebook user ID. Graph API call retained (Facebook is not OIDC).

### Migrations
- New table `social_identity` (additive). `User` model unchanged; no `ALTER TABLE` on existing tables; no data backfill required.

### Breaking changes
- None for existing email/password, passwordless, or wallet flows. OAuth integrators must migrate their config to provide PKCE-supporting redirects (handled internally) and set the new encryption key when storing refresh tokens (`SOCIAL_IDENTITY_ENCRYPTION_KEY`). Existing OAuth users are matched by their provider's stable subject; first-time sign-ins under the new code create a `SocialIdentity` row for the existing user.
```

- [ ] **Step 2: Bump versions in `pyproject.toml` and `blockauth/__init__.py`**

`pyproject.toml`:
```toml
version = "0.16.0"
```

`blockauth/__init__.py`:
```python
__version__ = "0.16.0"
```

- [ ] **Step 3: Verify version sync**

Run: `uv run python -c "import blockauth, tomllib; pyproject = tomllib.load(open('pyproject.toml','rb'))['project']['version']; assert blockauth.__version__ == pyproject; print('ok', pyproject)"`
Expected: `ok 0.16.0`.

- [ ] **Step 4: Update README**

Open `README.md`. Add the new endpoints to the API table. Add a short "Apple Sign-In" section with the minimum-viable settings example:

```markdown
### Apple Sign-In

```python
BLOCK_AUTH_SETTINGS = {
    ...,
    "APPLE_TEAM_ID": "<team id>",
    "APPLE_KEY_ID": "<key id>",
    "APPLE_PRIVATE_KEY_PEM": open("/path/to/AuthKey_<KEYID>.p8").read(),
    "APPLE_SERVICES_ID": "<services id>",
    "APPLE_BUNDLE_IDS": ("<your.app.bundle.id>",),
    "APPLE_REDIRECT_URI": "https://<your-app>/auth/apple/callback/",
    "FEATURES": {..., "APPLE_LOGIN": True},
}
```
```

Add a similar block for `GOOGLE_NATIVE_LOGIN`:

```markdown
### Google Native Sign-In (Credential Manager / iOS / Web One Tap)

```python
BLOCK_AUTH_SETTINGS = {
    ...,
    "GOOGLE_NATIVE_AUDIENCES": ("<web-client-id>.apps.googleusercontent.com",),
    "FEATURES": {..., "GOOGLE_NATIVE_LOGIN": True},
}
```
```

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md pyproject.toml blockauth/__init__.py README.md
git commit -m "chore(release): 0.16.0 — Apple Sign-In, Google Native, OAuth refactor"
```

### Task 18.2: Push branch and open PR

**Files:** none modified.

- [ ] **Step 1: Run final test suite once more**

Run: `uv run pytest -v`
Expected: green.

- [ ] **Step 2: Push branch**

```bash
git push -u origin feat/apple-google-oauth-refactor
```

- [ ] **Step 3: Open PR**

```bash
gh pr create --base dev --title "feat: Apple Sign-In, Google Native, and OAuth refactor (v0.16.0)" --body "$(cat <<'EOF'
## Summary
- Apple Sign-In: web (PKCE + nonce + form_post), native (id_token verify), revocation (pre_delete), S2S notifications webhook
- Google Native id_token verify (Android Credential Manager / iOS / Web One Tap)
- Generic `OIDCTokenVerifier` with JWKS cache + algorithm pinning + audience allowlist
- `SocialIdentity` model with provider-aware account-linking policy and AES-GCM-256 refresh-token-at-rest
- Refactored Google / LinkedIn / Facebook web OAuth onto the new foundation (PKCE everywhere; id_token verify on Google + LinkedIn; SocialIdentity matching on all four providers)
- v0.16.0 release

## Test plan
- [ ] `uv run pytest -v` (full suite green)
- [ ] `uv run pytest blockauth/apple/tests blockauth/social/tests blockauth/utils/jwt/tests blockauth/views/tests/test_oauth_views.py blockauth/views/tests/test_google_native_view.py -v` (new modules)
- [ ] `uv run black --check blockauth/`, `uv run isort --check-only blockauth/`, `uv run flake8 blockauth/` (lint)
- [ ] `uv run python -m django makemigrations --check --dry-run --settings=blockauth.settings` (only `social/0001_initial.py` produced)
- [ ] Manual smoke against staging Apple Services ID + Google Web Client ID

## Migration impact
- Adds one table: `social_identity`. No `ALTER TABLE`. No data backfill. Existing User rows untouched.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Reply with PR URL**

Capture the PR URL from `gh pr create` output and report it back.

---

## Self-review checklist

Run through this checklist after writing the plan, before handing off to execution. Each item is a "fix inline if found" — no need to re-review the whole plan.

### 1. Spec coverage

- [x] Apple Sign-In web — Phase 8
- [x] Apple Sign-In native — Phase 9
- [x] Apple revocation (App Store 5.1.1(v)) — Phase 10
- [x] Apple S2S notifications (Korea 2026-01-01 mandate) — Phase 11
- [x] Google native (Credential Manager / iOS / Web One Tap) — Phase 12
- [x] Generic `OIDCTokenVerifier` reused across providers — Phase 1
- [x] `SocialIdentity` model with AES-GCM refresh-at-rest — Phase 2
- [x] Account-linking policy with provider-aware verified-email gate — Phase 2 (Task 2.6/2.7)
- [x] Google web refactor (id_token verify, PKCE, nonce, SocialIdentity) — Phase 13
- [x] LinkedIn web refactor (OIDC, id_token verify, PKCE, nonce, SocialIdentity) — Phase 14
- [x] Facebook web refactor (PKCE, SocialIdentity by FB user_id) — Phase 15
- [x] Conditional Apple native nonce (verify when `nonce_supported=true`) — Phase 6 (Task 6.2) + Phase 9 (Task 9.1 test 3)
- [x] Apple S2S `events` claim string-or-object handling — Phase 11 (Task 11.2)
- [x] Google native audience = web client ID — Phase 12
- [x] PKCE on all four provider web flows — Phases 8, 13, 14, 15
- [x] Sensitive-fields registry extended — Phase 4 (Task 4.1 step 4)
- [x] Configuration defaults — Phase 4 (Task 4.2)
- [x] Logging events — covered in each impl task
- [x] Version bump — Phase 18 (Task 18.1)

### 2. Placeholder scan

Search the plan for the patterns called out by `writing-plans`:
- "TBD" / "TODO" / "fill in details" — none.
- "implement appropriate error handling" / "add validation" — none; specific error codes and exception classes named everywhere.
- "Write tests for the above" without code — none; every test step contains the test code.
- "Similar to Task N" — none; every task has its own complete code blocks.

### 3. Type / signature consistency

- `OIDCTokenVerifier.verify(token, expected_nonce)` — same signature in every consumer (Apple verifier, Google native, Google web, LinkedIn).
- `SocialIdentityService.upsert_and_link(provider, subject, email, email_verified, extra_claims, refresh_token=None)` — same kwargs across Apple web, Apple native, Google native, Google web, LinkedIn web, Facebook web.
- `AccountLinkingPolicy.can_link_to_existing_user(provider=, email=, email_verified=, extra_claims=)` — keyword-only call sites match definition.
- `set_state_cookie(response, state, samesite=None)` — used with and without `samesite` consistently across Apple, Google, LinkedIn, Facebook.
- `OAUTH_PKCE_VERIFIER_COOKIE_NAME` — single source of truth in `oauth_state.py`; tests reference the same name.

### 4. Risks I am explicitly comfortable with

- **Per-provider nonce cookie names** (`blockauth_google_nonce`, `blockauth_linkedin_nonce`, `blockauth_apple_nonce`). Could be unified into one helper, but the Google/LinkedIn flows are direct (no in-app browser hop) while Apple is `form_post` + `SameSite=None`, so they need different cookie configurations. One helper per provider keeps the configuration local; we are not over-engineering a generic helper that has to branch internally on samesite + cookie name.
- **`requests` HTTP timeout = 10 seconds** chosen consistently. Token endpoints are fast; cluster-internal retries belong to the integrator.
- **Apple S2S notifications: no replay-protection store** in v0.16. Documented as out-of-scope follow-up. Replay of a `consent-revoked` is idempotent (already-deleted = no-op); replay of `account-delete` is idempotent for the same reason. Replay of `email-disabled`/`email-enabled` is logged-only.
- **Account linking conflict (4090) for Apple-with-existing-email** is explicit and intentional. Apple users with an existing email/password account must use the existing method until the v0.17 link endpoint ships.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-25-apple-google-oauth-refactor.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?
