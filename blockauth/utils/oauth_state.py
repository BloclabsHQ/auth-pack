"""
OAuth 2.0 `state` parameter helpers — CSRF protection for social-auth flows.

Per RFC 6749 §10.12, every OAuth init MUST bind the callback to the browser
session that started the flow. We do this by generating a cryptographically
random token at init time, setting it as an HttpOnly / Secure / SameSite=Lax
cookie, and mirroring it in the `state=` query param to the authorize URL.

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
"""

import hmac
import secrets

from rest_framework.exceptions import ValidationError

OAUTH_STATE_COOKIE_NAME = "blockauth_oauth_state"
OAUTH_STATE_COOKIE_MAX_AGE = 600  # 10 minutes — covers human consent screens
OAUTH_STATE_TOKEN_BYTES = 32


def generate_state() -> str:
    """Cryptographically random, URL-safe state token."""
    return secrets.token_urlsafe(OAUTH_STATE_TOKEN_BYTES)


def set_state_cookie(response, state: str) -> None:
    """Bind the state token to the browser session via a short-lived cookie.

    SameSite=Lax is required: the provider redirects back via a top-level
    navigation (GET), which Lax permits while still blocking cross-site
    subresource requests that could leak/replay the cookie.
    """
    response.set_cookie(
        OAUTH_STATE_COOKIE_NAME,
        state,
        max_age=OAUTH_STATE_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="Lax",
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

    Must match the `samesite` attribute used at set time so browsers treat
    the delete as applying to the same cookie (Set-Cookie with Max-Age=0).
    """
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, samesite="Lax")
