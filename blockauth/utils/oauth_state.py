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
OAUTH_PKCE_VERIFIER_COOKIE_NAME = "blockauth_oauth_pkce"
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


def set_state_cookie(response, state: str, samesite: str | None = None) -> None:
    """Bind the state token to the browser session via a short-lived cookie.

    Secure / SameSite are read from `BLOCK_AUTH_SETTINGS` so deployments
    can downgrade to `secure=False` for http-only local dev without
    patching the library. HttpOnly stays on always — there is no JS
    reason to read state; the check is entirely server-side.

    `samesite` may be passed explicitly to override the env-driven default
    on a per-call basis — Apple's `form_post` callback requires
    `SameSite=None` because the POST is cross-site, even when the rest of
    the integration runs on `Lax`.
    """
    response.set_cookie(
        OAUTH_STATE_COOKIE_NAME,
        state,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=_cookie_secure(),
        samesite=samesite or _cookie_samesite(),
    )


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


def clear_state_cookie(response, samesite: str | None = None) -> None:
    """Clear the state cookie on the outbound response.

    Must match the `samesite` attribute used at set time so browsers
    treat the delete as applying to the same cookie (Set-Cookie with
    Max-Age=0).
    """
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, samesite=samesite or _cookie_samesite())


def set_pkce_verifier_cookie(response, verifier: str, samesite: str | None = None) -> None:
    """Persist the PKCE `code_verifier` across the authorize → callback
    hop. Lifecycle (TTL, HttpOnly, Secure, SameSite) mirrors the state
    cookie since they share the same trust boundary."""
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
