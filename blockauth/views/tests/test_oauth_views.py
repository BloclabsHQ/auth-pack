"""
Tests for OAuth views: Google, Facebook, LinkedIn login + callback.

Only external HTTP calls (requests.get/post) are mocked. social_login()
is field-aware since #109 (v0.11.1): `first_name` is only included in the
`get_or_create` defaults when the configured user model declares it, so
OAuth-signup works against minimal user models like TestBlockUser.

State/CSRF hardening (RFC 6749 §10.12): every init sets an HttpOnly
`blockauth_oauth_state` cookie and mirrors the token in `state=`; every
callback requires the cookie and query param to match via
`hmac.compare_digest` before the provider's token endpoint is hit.

Phase 13 — Google web flow refactored onto OIDCTokenVerifier + PKCE +
nonce + SocialIdentity. The userinfo HTTP call is gone; claims now come
from the verified id_token. Tests below mock the token endpoint
(`requests.post`) and the JWKS fetch (`blockauth.utils.jwt.jwks_cache.requests.get`).
LinkedIn / Facebook tests are intentionally untouched here — Phases 14/15
cover those.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from blockauth.utils.oauth_state import OAUTH_PKCE_VERIFIER_COOKIE_NAME, OAUTH_STATE_COOKIE_NAME
from blockauth.utils.social import social_login


def _prime_state(api_client, value="valid-state-token"):
    """Seed the state cookie so a callback request looks like it came from a
    browser that actually started the flow. Returns the state value so tests
    can pass it as the query param."""
    api_client.cookies[OAUTH_STATE_COOKIE_NAME] = value
    return value


@pytest.fixture(autouse=True)
def _clear_google_verifier_cache():
    """Stale verifier from a prior override_settings block must not leak
    across cases — module-level cache keyed by (audiences,) tuple."""
    from blockauth.views.google_auth_views import _reset_verifier_cache

    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


@pytest.fixture
def google_web_settings():
    """Override `BLOCK_AUTH_SETTINGS` with a deterministic Google web client
    config for the Phase-13 refactored flow tests. The test RSA keypair's
    `aud` (`123-web.apps.googleusercontent.com`) must match what the verifier
    accepts, which is why we override the conftest defaults here."""
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "GOOGLE_CLIENT_ID": "123-web.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "secret-shh",
            "GOOGLE_REDIRECT_URI": "https://app.example.com/auth/google/callback/",
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
            "AUTH_PROVIDERS": {
                "GOOGLE": {
                    "CLIENT_ID": "123-web.apps.googleusercontent.com",
                    "CLIENT_SECRET": "secret-shh",
                    "REDIRECT_URI": "https://app.example.com/auth/google/callback/",
                },
            },
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
class TestGoogleAuthLoginView:

    def test_redirects_to_google(self, api_client):
        response = api_client.get(reverse("google-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "accounts.google.com" in response.url

    def test_init_sets_state_cookie_and_query_param(self, api_client):
        """Init must bind the browser session: cookie set + state= in the
        redirect URL + the two values must match."""
        response = api_client.get(reverse("google-login"))

        assert OAUTH_STATE_COOKIE_NAME in response.cookies
        cookie = response.cookies[OAUTH_STATE_COOKIE_NAME]
        assert cookie.value, "state cookie must carry a token"
        assert cookie["httponly"]
        assert cookie["secure"]
        assert cookie["samesite"].lower() == "lax"
        assert cookie["max-age"] == 600

        assert "state=" in response.url
        from urllib.parse import parse_qs, urlparse

        query_state = parse_qs(urlparse(response.url).query)["state"][0]
        assert query_state == cookie.value


@pytest.mark.django_db
def test_google_authorize_includes_pkce_and_nonce(google_web_settings, client):
    """Authorize URL must carry openid scope, S256 PKCE challenge, and a
    hashed nonce; the matching cookies must be set so callback can verify."""
    from urllib.parse import parse_qs, urlparse

    response = client.get("/google/")
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
def test_google_callback_verifies_id_token_and_links_identity(
    google_web_settings, client, build_id_token, jwks_response
):
    """Full round-trip: code-exchange request must include code_verifier
    (PKCE), id_token claims power user resolution, and the legacy userinfo
    HTTP call is gone."""
    init = client.get("/google/")
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
    token_response.json.return_value = {
        "access_token": "google-access",
        "id_token": google_id_token,
    }

    # Patching `requests.get` for userinfo would clobber the JWKS-cache
    # patch — both modules share the same `requests` module object. Instead,
    # spy on the post-Phase-13 callsite to assert the legacy userinfo HTTP
    # call is gone: after the refactor, the only `requests.get` invocation
    # is the JWKSCache fetch. We sample call count on the JWKSCache mock and
    # confirm the view itself made no other GETs.
    def _track_get(*args, **kwargs):
        _track_get.calls.append((args, kwargs))
        return jwks_response

    _track_get.calls = []
    with patch(
        "blockauth.views.google_auth_views.requests.post", return_value=token_response
    ) as mock_post:
        with patch(
            "blockauth.utils.jwt.jwks_cache.requests.get", side_effect=_track_get
        ):
            callback = client.get(f"/google/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200, callback.content
    body = callback.json()
    assert "access" in body and "refresh" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    # The userinfo HTTP call has been REMOVED from the refactor — claims now
    # come from the verified id_token. Only the JWKSCache fetch should hit
    # `requests.get`; the legacy `https://www.googleapis.com/oauth2/v2/userinfo`
    # GET must never appear in the spy.
    userinfo_calls = [
        call_args for call_args in _track_get.calls
        if "userinfo" in (call_args[0][0] if call_args[0] else "")
    ]
    assert userinfo_calls == [], "userinfo HTTP call should be gone"


@pytest.mark.django_db
class TestGoogleAuthCallbackView:
    """Negative-path tests for the refactored Google web callback. Positive
    path is covered by `test_google_callback_verifies_id_token_and_links_identity`
    above, which exercises the full PKCE + nonce + id_token-verify pipeline."""

    def test_callback_missing_code(self, api_client):
        response = api_client.get(reverse("google-login-callback"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_missing_state_cookie_rejects(self, mock_post, api_client):
        """No cookie → the request didn't originate from this browser. Must
        400 without ever calling the provider's token endpoint."""
        response = api_client.get(
            reverse("google-login-callback"),
            {"code": "auth-code", "state": "anything"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_post.assert_not_called()

    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_missing_state_query_rejects(self, mock_post, api_client):
        """Cookie present but no `state=` in the URL → provider didn't echo
        our token. Reject before burning a real code."""
        _prime_state(api_client)
        response = api_client.get(reverse("google-login-callback"), {"code": "auth-code"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_post.assert_not_called()

    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_mismatched_state_rejects(self, mock_post, api_client):
        """Classic CSRF shape: attacker controls `state=` in the URL but
        can't forge the victim's cookie. Must 400."""
        _prime_state(api_client, value="victim-state")
        response = api_client.get(
            reverse("google-login-callback"),
            {"code": "auth-code", "state": "attacker-state"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_post.assert_not_called()


@pytest.fixture
def facebook_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "FACEBOOK_CLIENT_ID": "fb-client-id",
            "FACEBOOK_CLIENT_SECRET": "fb-secret",
            "FACEBOOK_REDIRECT_URI": "https://app.example.com/auth/facebook/callback/",
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
            "AUTH_PROVIDERS": {
                "FACEBOOK": {
                    "CLIENT_ID": "fb-client-id",
                    "CLIENT_SECRET": "fb-secret",
                    "REDIRECT_URI": "https://app.example.com/auth/facebook/callback/",
                },
            },
        }
    ):
        yield


@pytest.mark.django_db
def test_facebook_authorize_includes_pkce(facebook_settings, client):
    from urllib.parse import parse_qs, urlparse

    response = client.get("/facebook/")
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
    init = client.get("/facebook/")
    state = init.cookies[OAUTH_STATE_COOKIE_NAME].value

    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"access_token": "fb-access"}
    me_response = MagicMock(status_code=200)
    me_response.json.return_value = {"id": "fb_user_123", "name": "FB User", "email": "u@example.com"}

    with patch("blockauth.views.facebook_auth_views.requests.get", side_effect=[token_response, me_response]):
        callback = client.get(f"/facebook/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200, callback.content
    body = callback.json()
    assert "access" in body and "user" in body

    from blockauth.social.models import SocialIdentity
    assert SocialIdentity.objects.filter(provider="facebook", subject="fb_user_123").exists()


@pytest.mark.django_db
class TestFacebookAuthLoginView:

    def test_redirects_to_facebook(self, api_client):
        response = api_client.get(reverse("facebook-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "facebook.com" in response.url

    def test_init_sets_state_cookie_and_query_param(self, api_client):
        response = api_client.get(reverse("facebook-login"))
        assert OAUTH_STATE_COOKIE_NAME in response.cookies
        from urllib.parse import parse_qs, urlparse

        query_state = parse_qs(urlparse(response.url).query)["state"][0]
        assert query_state == response.cookies[OAUTH_STATE_COOKIE_NAME].value


@pytest.mark.django_db
class TestFacebookAuthCallbackView:

    @patch("blockauth.views.facebook_auth_views.requests.get")
    def test_callback_mismatched_state_rejects(self, mock_get, api_client):
        _prime_state(api_client, value="victim-state")
        response = api_client.get(
            reverse("facebook-login-callback"),
            {"code": "auth-code", "state": "attacker-state"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_get.assert_not_called()

    def test_callback_missing_code(self, api_client):
        response = api_client.get(reverse("facebook-login-callback"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.fixture(autouse=True)
def _clear_linkedin_verifier_cache():
    """Stale verifier from a prior override_settings block must not leak
    across cases — module-level cache keyed by (audiences,) tuple."""
    from blockauth.views.linkedin_auth_views import _reset_verifier_cache as _li_reset

    _li_reset()
    yield
    _li_reset()


@pytest.fixture
def linkedin_settings():
    """Override `BLOCK_AUTH_SETTINGS` with a deterministic LinkedIn web client
    config for the Phase-14 refactored flow tests. The test RSA keypair's
    `aud` (`linkedin-client-id`) must match what the verifier accepts."""
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "LINKEDIN_CLIENT_ID": "linkedin-client-id",
            "LINKEDIN_CLIENT_SECRET": "linkedin-secret",
            "LINKEDIN_REDIRECT_URI": "https://app.example.com/auth/linkedin/callback/",
            "FEATURES": {"SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
            "AUTH_PROVIDERS": {
                "LINKEDIN": {
                    "CLIENT_ID": "linkedin-client-id",
                    "CLIENT_SECRET": "linkedin-secret",
                    "REDIRECT_URI": "https://app.example.com/auth/linkedin/callback/",
                },
            },
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
    """Authorize URL must carry openid scope, S256 PKCE challenge, and a
    hashed nonce; the matching cookies must be set so callback can verify."""
    from urllib.parse import parse_qs, urlparse

    response = client.get("/linkedin/")
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
def test_linkedin_callback_verifies_id_token(
    linkedin_settings, client, build_id_token, linkedin_jwks_response
):
    """Full round-trip: code-exchange request must include code_verifier
    (PKCE), id_token claims power user resolution, and the legacy userinfo
    HTTP call is gone."""
    init = client.get("/linkedin/")
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

    # Use a side_effect spy on requests.get so we can both stub JWKS AND
    # assert userinfo isn't fetched (the Phase 13 deviation pattern).
    seen_get_urls = []

    def _get_spy(url, *args, **kwargs):
        seen_get_urls.append(url)
        return linkedin_jwks_response

    with patch(
        "blockauth.views.linkedin_auth_views.requests.post", return_value=token_response
    ) as mock_post, patch(
        "blockauth.utils.jwt.jwks_cache.requests.get", side_effect=_get_spy
    ):
        callback = client.get(f"/linkedin/callback/?code=auth-code&state={state}")

    assert callback.status_code == 200, callback.content
    body = callback.json()
    assert "access" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    # Verifier fetched JWKS but no userinfo endpoint was hit.
    assert all("userinfo" not in url.lower() for url in seen_get_urls)


@pytest.mark.django_db
class TestLinkedInAuthLoginView:

    def test_redirects_to_linkedin(self, api_client):
        response = api_client.get(reverse("linkedin-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "linkedin.com" in response.url

    def test_init_sets_state_cookie_and_query_param(self, api_client):
        response = api_client.get(reverse("linkedin-login"))
        assert OAUTH_STATE_COOKIE_NAME in response.cookies
        from urllib.parse import parse_qs, urlparse

        query_state = parse_qs(urlparse(response.url).query)["state"][0]
        assert query_state == response.cookies[OAUTH_STATE_COOKIE_NAME].value


@pytest.mark.django_db
class TestLinkedInAuthCallbackView:
    """Negative-path tests for the refactored LinkedIn web callback. Positive
    path is covered by `test_linkedin_callback_verifies_id_token` above,
    which exercises the full PKCE + nonce + id_token-verify pipeline."""

    @patch("blockauth.views.linkedin_auth_views.requests.post")
    def test_callback_mismatched_state_rejects(self, mock_post, api_client):
        _prime_state(api_client, value="victim-state")
        response = api_client.get(
            reverse("linkedin-login-callback"),
            {"code": "auth-code", "state": "attacker-state"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_post.assert_not_called()


@pytest.mark.django_db
class TestCallbackSuccessResponseHook:
    """The BFF-cookie integration (fabric-auth#533) subclasses these
    callback views and overrides ``build_success_response`` to ship tokens
    via HttpOnly cookies + a 302 to the shell origin, instead of the
    default JSON body. These tests pin the hook surface so the override
    point doesn't silently disappear in a future refactor.
    """

    @patch("blockauth.views.google_auth_views.SocialIdentityService")
    @patch("blockauth.views.google_auth_views._build_verifier")
    @patch("blockauth.views.google_auth_views.social_login_data")
    @patch("blockauth.views.google_auth_views.requests.post")
    def test_integrator_override_receives_result_and_request(
        self,
        mock_post,
        mock_social_login_data,
        mock_build_verifier,
        mock_social_identity_service,
        api_client,
    ):
        """``build_success_response(request, result)`` must receive the
        full ``SocialLoginResult`` so integrators can read user + tokens
        and build whatever response shape they need.

        The Phase-13 refactor swapped userinfo-via-`requests.get` for an
        id_token verified by `_build_verifier`, so this hook test stubs
        `_build_verifier(...).verify(...)` to return Google-shaped claims
        instead of mocking the userinfo HTTP call.
        """
        from blockauth.utils.social import SocialLoginResult
        from blockauth.views.google_auth_views import GoogleAuthCallbackView

        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "t", "id_token": "fake-id-token"},
        )
        mock_build_verifier.return_value.verify.return_value = {
            "sub": "google-sub-override",
            "email": "g@test.com",
            "email_verified": True,
            "name": "Google User",
        }
        mock_user = MagicMock(id="01936f4e-0000-7abc-8def-000000000001", email="g@test.com")
        mock_social_identity_service.return_value.upsert_and_link.return_value = (
            mock_user,
            MagicMock(),
            False,
        )
        mock_social_login_data.return_value = SocialLoginResult(
            user=mock_user,
            access_token="override-access",
            refresh_token="override-refresh",
            created=False,
        )

        captured = {}
        original = GoogleAuthCallbackView.build_success_response

        def override(self, request, result):
            captured["result"] = result
            captured["request"] = request
            from django.http import HttpResponseRedirect

            return HttpResponseRedirect("https://shell.example/auth/callback")

        GoogleAuthCallbackView.build_success_response = override
        try:
            state = _prime_state(api_client)
            # The refactor requires PKCE verifier + raw nonce cookies on the
            # callback. Seed both so the override-hook test exercises the
            # successful build_success_response path rather than tripping
            # 4051/4061 short-circuits.
            api_client.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME] = "test-pkce-verifier"
            api_client.cookies["blockauth_google_nonce"] = "test-raw-nonce"
            response = api_client.get(
                reverse("google-login-callback"),
                {"code": "c", "state": state},
            )
        finally:
            GoogleAuthCallbackView.build_success_response = original

        assert response.status_code == 302
        assert response.url == "https://shell.example/auth/callback"
        assert captured["result"].access_token == "override-access"
        assert captured["result"].refresh_token == "override-refresh"
        # The override is a good place to attach cookies — confirm the
        # state cookie still gets cleared by the view wrapper after the
        # override returns (belt-and-braces).
        cleared = response.cookies.get(OAUTH_STATE_COOKIE_NAME)
        assert cleared is not None
        assert cleared["max-age"] == 0


@pytest.mark.django_db
class TestStateCookiePolicyConfigurable:
    """``set_state_cookie`` reads ``BLOCK_AUTH_SETTINGS['OAUTH_STATE_COOKIE_SECURE']``
    and ``['OAUTH_STATE_COOKIE_SAMESITE']`` so integrators can run over
    plain http in local dev without patching the library. Defaults stay
    secure (``secure=True``, ``samesite=Lax``) for deployed TLS envs.
    """

    def test_default_secure_and_samesite(self, api_client):
        response = api_client.get(reverse("google-login"))
        cookie = response.cookies[OAUTH_STATE_COOKIE_NAME]
        assert cookie["secure"]
        assert cookie["samesite"].lower() == "lax"

    def test_local_dev_can_disable_secure(self, api_client, settings):
        """Firefox doesn't treat ``http://localhost`` as a secure context,
        so hardcoded ``secure=True`` breaks local dev on non-Chromium.
        ``OAUTH_STATE_COOKIE_SECURE=False`` in ``BLOCK_AUTH_SETTINGS``
        downgrades the cookie for that env."""
        settings.BLOCK_AUTH_SETTINGS = {
            **settings.BLOCK_AUTH_SETTINGS,
            "OAUTH_STATE_COOKIE_SECURE": False,
        }
        response = api_client.get(reverse("google-login"))
        cookie = response.cookies[OAUTH_STATE_COOKIE_NAME]
        assert not cookie["secure"]


@pytest.mark.django_db
class TestSocialLoginResponseShape:
    """Issue #107 — all three OAuth callbacks funnel through social_login(),
    so one shape assertion per endpoint-equivalent exercise proves the
    {access, refresh, user} parity with /login/basic/ is in place without
    re-mocking requests.* three times.

    Since #109 (v0.11.1) social_login() is safe to call against user
    models that don't define `first_name`; the provider-specific tests
    still pre-seed to keep them focused on the shape contract, but the
    first_oauth_signup_* tests below exercise the real create path."""

    def _assert_full_auth_state_shape(self, response):
        assert response.status_code == 200
        assert "access" in response.data
        assert "refresh" in response.data
        assert response.data["access"]
        assert response.data["refresh"]
        assert "user" in response.data
        user_payload = response.data["user"]
        # Issue #131: AuthUser shell schema requires these to always be
        # present; first_name / last_name are intentionally omitted when
        # unset (z.optional() rejects null) and are covered separately.
        for field in ("id", "email", "is_verified", "is_active", "date_joined", "wallet_address", "wallets"):
            assert field in user_payload, f"OAuth response missing {field}"

    def test_google_callback_returns_full_auth_state(self, create_user):
        user = create_user(email="g@test.com")
        response = social_login(email="g@test.com", name="Google User", provider_data={"provider": "google"})
        self._assert_full_auth_state_shape(response)
        assert response.data["user"]["id"] == str(user.id)
        assert response.data["user"]["email"] == "g@test.com"

    def test_facebook_callback_returns_full_auth_state(self, create_user):
        user = create_user(email="f@test.com")
        response = social_login(email="f@test.com", name="FB User", provider_data={"provider": "facebook"})
        self._assert_full_auth_state_shape(response)
        assert response.data["user"]["id"] == str(user.id)

    def test_linkedin_callback_returns_full_auth_state(self, create_user):
        user = create_user(email="l@test.com")
        response = social_login(email="l@test.com", name="LI User", provider_data={"provider": "linkedin"})
        self._assert_full_auth_state_shape(response)
        assert response.data["user"]["id"] == str(user.id)

    def test_first_oauth_signup_does_not_crash_on_model_without_first_name(self, db):
        """#109: social_login()'s get_or_create previously passed
        `first_name=name` in defaults, which blows up on user models
        (like TestBlockUser) that don't define that field. The create
        path — i.e. the very first OAuth signup for a new email — must
        not crash.

        This test intentionally does NOT pre-seed the user so the
        `defaults` branch of get_or_create fires."""
        response = social_login(
            email="first-oauth@test.com",
            name="First OAuth User",
            provider_data={"provider": "google"},
        )
        self._assert_full_auth_state_shape(response)
        assert response.data["user"]["email"] == "first-oauth@test.com"
        # User was created and is verified (OAuth default)
        assert response.data["user"]["is_verified"] is True

    def test_google_promotes_existing_unverified_user_to_verified(self, create_user):
        """#533/#537 side-bug: a user who signed up via email/password and
        never clicked the verification link must get promoted to
        ``is_verified=True`` when they authenticate via Google, because
        Google's OIDC response carries an OIDC-verified email claim.
        Facebook and LinkedIn don't guarantee verified email, so they
        stay unmodified."""
        user = create_user(email="existing@test.com", is_verified=False)
        assert user.is_verified is False

        response = social_login(
            email="existing@test.com",
            name="Existing User",
            provider_data={"provider": "google"},
        )
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.is_verified is True

    def test_facebook_does_not_promote_unverified_user(self, create_user):
        """Facebook does not guarantee an OIDC-verified email claim.
        Leave ``is_verified`` as-is rather than over-trusting the
        provider."""
        user = create_user(email="fbunverified@test.com", is_verified=False)

        social_login(
            email="fbunverified@test.com",
            name="FB User",
            provider_data={"provider": "facebook"},
        )
        user.refresh_from_db()
        assert user.is_verified is False

    def test_first_oauth_signup_populates_first_name_when_field_exists(self, db):
        """If the user model defines `first_name`, the passed `name`
        should still be populated on first signup — don't regress the
        feature while fixing the compatibility bug."""
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()
        response = social_login(
            email="named@test.com",
            name="Ada Lovelace",
            provider_data={"provider": "google"},
        )
        self._assert_full_auth_state_shape(response)
        user = User.objects.get(email="named@test.com")
        if hasattr(user, "first_name"):
            assert user.first_name == "Ada Lovelace"
