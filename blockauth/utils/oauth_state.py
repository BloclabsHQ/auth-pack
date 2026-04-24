"""
OAuth 2.0 `state` parameter helpers — CSRF protection for social-auth flows.

Per RFC 6749 §10.12, every OAuth init MUST bind the callback to the browser
session that started the flow. We do this by generating a cryptographically
random token at init time, setting it as an HttpOnly cookie (Secure /
SameSite are env-driven; defaults are the strictest values that work for
deployed TLS), and mirroring it in the `state=` query param to the authorize
URL.

On callback, the view compares the cookie and the query param with
`hmac.compare_digest` (constant-time) and rejects mismatches with 400 before
touching the provider's token endpoint — so a CSRF probe never causes a real
authorization code to be exchanged. The cookie is cleared on the successful
response so it cannot be replayed.

Why a cookie (rather than a server-side session store):
  - fabric-auth is stateless behind Kong; adding a session store just for
    OAuth state is heavier than a scoped, short-lived cookie.
  - Short TTL (10 min) + HttpOnly + SameSite=Lax + compare_digest is the
    pattern documented by OWASP for browser-initiated OAuth flows.

Why Secure and SameSite are configurable:
  - Local dev over plain `http://localhost` cannot set Secure cookies in
    production-equivalent mode — Chrome treats localhost as secure, but
    Firefox doesn't. A hardcoded `secure=True` locks out Firefox-based
    local dev entirely.
  - Tailscale hosts on `*.fabric.test` typically run http until an operator
    provisions a local TLS cert.
  - Deployed envs run TLS end-to-end and want `Secure=True` + the
    strictest SameSite policy the callback hop permits.

Read overrides from `BLOCK_AUTH_SETTINGS["OAUTH_STATE_COOKIE_SECURE"]` and
`["OAUTH_STATE_COOKIE_SAMESITE"]` so integrators can set one value per
environment via env vars without patching this file.
"""

import hmac
import secrets

from rest_framework.exceptions import ValidationError

OAUTH_STATE_COOKIE_NAME = "blockauth_oauth_state"
OAUTH_STATE_COOKIE_MAX_AGE = 600  # 10 minutes — covers human consent screens
OAUTH_STATE_TOKEN_BYTES = 32


def _get_setting(key: str, default):
    """Read a cookie-policy override from `BLOCK_AUTH_SETTINGS`.

    Local import so this module stays usable in non-Django contexts
    (unit tests, scripts) — `django.conf.settings` is only touched when
    the helper is actually called at request time.
    """
    try:
        from django.conf import settings as _settings

        block_settings = getattr(_settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    except Exception:
        block_settings = {}
    return block_settings.get(key, default)


def _cookie_secure() -> bool:
    """True unless explicitly disabled for local http dev."""
    return bool(_get_setting("OAUTH_STATE_COOKIE_SECURE", True))


def _cookie_samesite() -> str:
    """`Lax` by default — Lax permits the Google→callback top-level GET
    while still blocking CSRF via cross-site subresource requests.
    `Strict` would actually break the callback (cross-site navigation
    doesn't send Strict cookies). Keep Lax unless an integrator knows
    their topology permits Strict (e.g. same-origin callback).
    """
    return str(_get_setting("OAUTH_STATE_COOKIE_SAMESITE", "Lax"))


def generate_state() -> str:
    """Cryptographically random, URL-safe state token."""
    return secrets.token_urlsafe(OAUTH_STATE_TOKEN_BYTES)


def set_state_cookie(response, state: str) -> None:
    """Bind the state token to the browser session via a short-lived cookie.

    Secure / SameSite are read from `BLOCK_AUTH_SETTINGS` so deployments
    can downgrade to `secure=False` for http-only local dev without
    patching the library. HttpOnly stays on always — there is no JS
    reason to read state; the check is entirely server-side.
    """
    response.set_cookie(
        OAUTH_STATE_COOKIE_NAME,
        state,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=_cookie_secure(),
        samesite=_cookie_samesite(),
    )


def verify_state(request) -> None:
    """Compare the query `state` against the cookie in constant time.

    Raises `ValidationError` (400) on any of: missing cookie, missing query,
    mismatch. Callers MUST invoke this before making any call to the
    provider's token endpoint — otherwise a CSRF probe can still consume a
    real authorization code.
    """
    cookie_state = request.COOKIES.get(OAUTH_STATE_COOKIE_NAME)
    query_state = request.query_params.get("state")

    if not cookie_state or not query_state:
        raise ValidationError({"detail": "OAuth state missing"}, 4030)

    if not hmac.compare_digest(cookie_state, query_state):
        raise ValidationError({"detail": "OAuth state mismatch"}, 4030)


def clear_state_cookie(response) -> None:
    """Clear the state cookie on the outbound response.

    Must match the `samesite` attribute used at set time so browsers
    treat the delete as applying to the same cookie (Set-Cookie with
    Max-Age=0).
    """
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, samesite=_cookie_samesite())
