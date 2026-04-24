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
"""

from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.utils.oauth_state import OAUTH_STATE_COOKIE_NAME
from blockauth.utils.social import social_login


def _prime_state(api_client, value="valid-state-token"):
    """Seed the state cookie so a callback request looks like it came from a
    browser that actually started the flow. Returns the state value so tests
    can pass it as the query param."""
    api_client.cookies[OAUTH_STATE_COOKIE_NAME] = value
    return value


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
class TestGoogleAuthCallbackView:

    @patch("blockauth.views.google_auth_views.social_login_data")
    @patch("blockauth.views.google_auth_views.requests.get")
    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_returns_tokens(self, mock_post, mock_get, mock_social_login_data, api_client):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "google-token"},
        )
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"email": "google@test.com", "name": "Google User"},
        )

        from blockauth.utils.social import SocialLoginResult

        mock_user = MagicMock()
        mock_user.id = "01936f4e-1234-7abc-8def-0123456789ab"
        mock_user.email = "google@test.com"
        mock_user.is_verified = True
        mock_user.is_active = True
        mock_user.wallet_address = None
        mock_user.date_joined = None
        mock_social_login_data.return_value = SocialLoginResult(
            user=mock_user,
            access_token="test-access",
            refresh_token="test-refresh",
            created=False,
        )
        state = _prime_state(api_client)

        response = api_client.get(
            reverse("google-login-callback"),
            {"code": "auth-code", "state": state},
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
        mock_social_login_data.assert_called_once()
        # Success clears the state cookie so it can't be replayed.
        cleared = response.cookies.get(OAUTH_STATE_COOKIE_NAME)
        assert cleared is not None
        assert cleared["max-age"] == 0

    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_token_exchange_failure(self, mock_post, api_client):
        mock_post.return_value = MagicMock(
            status_code=401,
            json=lambda: {"error": "invalid_grant"},
        )
        state = _prime_state(api_client)
        response = api_client.get(
            reverse("google-login-callback"),
            {"code": "bad-code", "state": state},
        )
        assert response.status_code == 401

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

    @patch("blockauth.views.facebook_auth_views.social_login_data")
    @patch("blockauth.views.facebook_auth_views.requests.get")
    def test_callback_returns_tokens(self, mock_get, mock_social_login_data, api_client):
        mock_get.side_effect = [
            MagicMock(status_code=200, json=lambda: {"access_token": "fb-token"}),
            MagicMock(status_code=200, json=lambda: {"email": "fb@test.com", "name": "FB User"}),
        ]
        from blockauth.utils.social import SocialLoginResult

        mock_user = MagicMock()
        mock_user.id = "01936f4e-1234-7abc-8def-0123456789ab"
        mock_user.email = "fb@test.com"
        mock_user.is_verified = False
        mock_user.is_active = True
        mock_user.wallet_address = None
        mock_user.date_joined = None
        mock_social_login_data.return_value = SocialLoginResult(
            user=mock_user,
            access_token="test-access",
            refresh_token="test-refresh",
            created=False,
        )
        state = _prime_state(api_client)

        response = api_client.get(
            reverse("facebook-login-callback"),
            {"code": "auth-code", "state": state},
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    @patch("blockauth.views.facebook_auth_views.requests.get")
    def test_callback_mismatched_state_rejects(self, mock_get, api_client):
        _prime_state(api_client, value="victim-state")
        response = api_client.get(
            reverse("facebook-login-callback"),
            {"code": "auth-code", "state": "attacker-state"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        mock_get.assert_not_called()


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

    @patch("blockauth.views.linkedin_auth_views.social_login_data")
    @patch("blockauth.views.linkedin_auth_views.requests.get")
    @patch("blockauth.views.linkedin_auth_views.requests.post")
    def test_callback_returns_tokens(self, mock_post, mock_get, mock_social_login_data, api_client):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "li-token"},
        )
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"email": "li@test.com", "name": "LI User"},
        )
        from blockauth.utils.social import SocialLoginResult

        mock_user = MagicMock()
        mock_user.id = "01936f4e-1234-7abc-8def-0123456789ab"
        mock_user.email = "li@test.com"
        mock_user.is_verified = False
        mock_user.is_active = True
        mock_user.wallet_address = None
        mock_user.date_joined = None
        mock_social_login_data.return_value = SocialLoginResult(
            user=mock_user,
            access_token="test-access",
            refresh_token="test-refresh",
            created=False,
        )
        state = _prime_state(api_client)

        response = api_client.get(
            reverse("linkedin-login-callback"),
            {"code": "auth-code", "state": state},
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

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

    @patch("blockauth.views.google_auth_views.social_login_data")
    @patch("blockauth.views.google_auth_views.requests.get")
    @patch("blockauth.views.google_auth_views.requests.post")
    def test_integrator_override_receives_result_and_request(
        self, mock_post, mock_get, mock_social_login_data, api_client
    ):
        """``build_success_response(request, result)`` must receive the
        full ``SocialLoginResult`` so integrators can read user + tokens
        and build whatever response shape they need."""
        from blockauth.utils.social import SocialLoginResult
        from blockauth.views.google_auth_views import GoogleAuthCallbackView

        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t"})
        mock_get.return_value = MagicMock(
            status_code=200, json=lambda: {"email": "g@test.com", "name": "Google User"}
        )
        mock_user = MagicMock(id="01936f4e-0000-7abc-8def-000000000001", email="g@test.com")
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
