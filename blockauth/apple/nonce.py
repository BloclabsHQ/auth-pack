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
    # `secure=True` is hardcoded (not driven by OAUTH_STATE_COOKIE_SECURE)
    # because Apple's form_post callback requires HTTPS — there is no valid
    # local-http variant of this flow. SameSite default is "None" for the
    # same reason: Lax cookies are not sent on cross-site POSTs.
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
