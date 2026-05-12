"""Tests for the per-provider callback cookie-clear helpers.

`clear_google_callback_cookies`, `clear_facebook_callback_cookies`, and
`clear_linkedin_callback_cookies` mirror `clear_apple_callback_cookies`
(introduced in v0.16.5). They exist so BFF integrators that swap the
response shape (HttpOnly cookies + 302 redirect instead of JSON body) can
call a single helper per provider instead of re-implementing the
state/PKCE/nonce clear in every consumer.

These tests pin the contract: each helper marks every cookie set by its
provider's authorize view for deletion (max-age=0).
"""

import pytest
from django.http import HttpResponse

from blockauth.utils.oauth_state import (
    OAUTH_PKCE_VERIFIER_COOKIE_NAME,
    OAUTH_STATE_COOKIE_NAME,
)


def test_clear_google_callback_cookies_marks_state_pkce_and_nonce_for_deletion():
    """The helper must clear state, PKCE verifier, and the Google nonce
    cookie. Mirrors clear_apple_callback_cookies from v0.16.5."""
    from blockauth.views.google_auth_views import (
        GOOGLE_NONCE_COOKIE_NAME,
        clear_google_callback_cookies,
    )

    response = HttpResponse()
    clear_google_callback_cookies(response)

    for cookie_name in (
        OAUTH_STATE_COOKIE_NAME,
        OAUTH_PKCE_VERIFIER_COOKIE_NAME,
        GOOGLE_NONCE_COOKIE_NAME,
    ):
        assert cookie_name in response.cookies, f"{cookie_name} not cleared"
        assert response.cookies[cookie_name]["max-age"] == 0, f"{cookie_name} not marked for deletion (max-age != 0)"


def test_clear_facebook_callback_cookies_marks_state_and_pkce_for_deletion():
    """Facebook is not OIDC and does not set a nonce cookie, so the
    helper only clears state and PKCE verifier."""
    from blockauth.views.facebook_auth_views import clear_facebook_callback_cookies

    response = HttpResponse()
    clear_facebook_callback_cookies(response)

    for cookie_name in (
        OAUTH_STATE_COOKIE_NAME,
        OAUTH_PKCE_VERIFIER_COOKIE_NAME,
    ):
        assert cookie_name in response.cookies, f"{cookie_name} not cleared"
        assert response.cookies[cookie_name]["max-age"] == 0, f"{cookie_name} not marked for deletion (max-age != 0)"


def test_clear_linkedin_callback_cookies_marks_state_pkce_and_nonce_for_deletion():
    """The helper must clear state, PKCE verifier, and the LinkedIn nonce
    cookie."""
    from blockauth.views.linkedin_auth_views import (
        LINKEDIN_NONCE_COOKIE_NAME,
        clear_linkedin_callback_cookies,
    )

    response = HttpResponse()
    clear_linkedin_callback_cookies(response)

    for cookie_name in (
        OAUTH_STATE_COOKIE_NAME,
        OAUTH_PKCE_VERIFIER_COOKIE_NAME,
        LINKEDIN_NONCE_COOKIE_NAME,
    ):
        assert cookie_name in response.cookies, f"{cookie_name} not cleared"
        assert response.cookies[cookie_name]["max-age"] == 0, f"{cookie_name} not marked for deletion (max-age != 0)"


@pytest.mark.parametrize(
    ("helper_path", "samesite_value"),
    [
        ("blockauth.views.google_auth_views.clear_google_callback_cookies", "Strict"),
        ("blockauth.views.facebook_auth_views.clear_facebook_callback_cookies", "Strict"),
        ("blockauth.views.linkedin_auth_views.clear_linkedin_callback_cookies", "Strict"),
    ],
)
def test_explicit_samesite_kwarg_overrides_default(helper_path, samesite_value):
    """The samesite kwarg lets integrators that diverge from the default
    override without monkey-patching. Assert the kwarg propagates to
    every cookie the helper touches (state, PKCE, and the provider's
    nonce cookie where applicable) — not just state — so a future helper
    that forgets to pass `samesite` through to one of its calls fails
    this test instead of silently leaking the wrong attribute."""
    import importlib

    module_path, _, attr = helper_path.rpartition(".")
    module = importlib.import_module(module_path)
    helper = getattr(module, attr)

    response = HttpResponse()
    helper(response, samesite=samesite_value)

    # Every cookie the helper actually sets must carry the requested
    # samesite. Iterate over response.cookies rather than a fixed list
    # so this test stays correct if a future helper grows another
    # cookie (Apple-style fourth-cookie case).
    assert response.cookies, "helper did not clear any cookies"
    for cookie_name, morsel in response.cookies.items():
        assert morsel["samesite"].lower() == samesite_value.lower(), (
            f"{cookie_name} samesite={morsel['samesite']!r} did not match override={samesite_value!r}"
        )
