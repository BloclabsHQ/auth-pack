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

Cookies are namespaced per provider (e.g. `blockauth_oauth_state_google`,
`blockauth_oauth_pkce_apple`) so two concurrent OAuth flows in the same
browser cannot stomp each other's state or PKCE verifier, and so each
provider can carry its own SameSite policy (Apple needs None for its
cross-site form_post POST; the others run on Lax).
"""

import hmac
import secrets

from rest_framework.exceptions import ValidationError

OAUTH_STATE_COOKIE_PREFIX = "blockauth_oauth_state"
OAUTH_PKCE_VERIFIER_COOKIE_PREFIX = "blockauth_oauth_pkce"
OAUTH_STATE_COOKIE_MAX_AGE = 600  # 10 minutes — covers human consent screens
OAUTH_STATE_TOKEN_BYTES = 32


def oauth_state_cookie_name(provider: str) -> str:
    """Cookie name for the OAuth `state` token, namespaced by provider."""
    return f"{OAUTH_STATE_COOKIE_PREFIX}_{provider}"


def oauth_pkce_verifier_cookie_name(provider: str) -> str:
    """Cookie name for the PKCE `code_verifier`, namespaced by provider."""
    return f"{OAUTH_PKCE_VERIFIER_COOKIE_PREFIX}_{provider}"


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
    """True unless explicitly disabled for local http dev.

    Local dev over plain `http://localhost` cannot set Secure cookies in
    production-equivalent mode in every browser. Deployed envs run TLS
    end-to-end and want Secure=True. Read the override from
    `BLOCK_AUTH_SETTINGS["OAUTH_STATE_COOKIE_SECURE"]` so integrators
    can set one value per environment via env vars.
    """
    return bool(_get_setting("OAUTH_STATE_COOKIE_SECURE", True))


def _cookie_samesite() -> str:
    """`Lax` by default — permits the IdP→callback top-level GET while
    still blocking CSRF via cross-site subresource requests.

    `Strict` would actually break the callback (cross-site navigation
    doesn't send Strict cookies). Keep Lax unless an integrator knows
    their topology permits Strict (e.g. same-origin callback). Apple's
    cross-site `form_post` POST needs `None` and passes it explicitly
    via the per-call `samesite` argument.
    """
    return str(_get_setting("OAUTH_STATE_COOKIE_SAMESITE", "Lax"))


def generate_state() -> str:
    """Cryptographically random, URL-safe state token (32 bytes of entropy)."""
    return secrets.token_urlsafe(OAUTH_STATE_TOKEN_BYTES)


def set_state_cookie(response, state: str, *, provider: str, samesite: str | None = None) -> None:
    """Bind the state token to the browser session via a short-lived HttpOnly cookie.

    `samesite` may override the env-driven default on a per-call basis — Apple's
    `form_post` callback needs `None` because the POST is cross-site, while the
    other providers run on `Lax`.
    """
    response.set_cookie(
        oauth_state_cookie_name(provider),
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


def verify_state(request, *, provider: str) -> None:
    """Backwards-compatible wrapper that reads `state` from the request's
    query parameters and compares against the per-provider state cookie."""
    verify_state_values(
        request.COOKIES.get(oauth_state_cookie_name(provider)),
        request.query_params.get("state"),
    )


def clear_state_cookie(response, *, provider: str, samesite: str | None = None) -> None:
    """Clear the per-provider state cookie. `samesite` must match the set-time
    value so browsers treat the delete as applying to the same cookie."""
    response.delete_cookie(
        oauth_state_cookie_name(provider),
        samesite=samesite or _cookie_samesite(),
    )


def set_pkce_verifier_cookie(response, verifier: str, *, provider: str, samesite: str | None = None) -> None:
    """Persist the PKCE `code_verifier` across the authorize → callback hop.

    Lifecycle (TTL, HttpOnly, Secure, SameSite) mirrors the state cookie since
    they share the same trust boundary.
    """
    response.set_cookie(
        oauth_pkce_verifier_cookie_name(provider),
        verifier,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=_cookie_secure(),
        samesite=samesite or _cookie_samesite(),
    )


def read_pkce_verifier_cookie(request, *, provider: str) -> str | None:
    """Return the PKCE `code_verifier` cookie value for `provider`, or None."""
    return request.COOKIES.get(oauth_pkce_verifier_cookie_name(provider))


def clear_pkce_verifier_cookie(response, *, provider: str, samesite: str | None = None) -> None:
    """Clear the per-provider PKCE verifier cookie. `samesite` must match the
    set-time value."""
    response.delete_cookie(
        oauth_pkce_verifier_cookie_name(provider),
        samesite=samesite or _cookie_samesite(),
    )
