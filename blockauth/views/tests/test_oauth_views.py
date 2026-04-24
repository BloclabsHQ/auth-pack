"""
Tests for OAuth views: Google, Facebook, LinkedIn login + callback.

Only external HTTP calls (requests.get/post) are mocked. social_login()
is field-aware since #109 (v0.11.1): `first_name` is only included in the
`get_or_create` defaults when the configured user model declares it, so
OAuth-signup works against minimal user models like TestBlockUser.
"""

from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.utils.social import social_login


@pytest.mark.django_db
class TestGoogleAuthLoginView:

    def test_redirects_to_google(self, api_client):
        response = api_client.get(reverse("google-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "accounts.google.com" in response.url


@pytest.mark.django_db
class TestGoogleAuthCallbackView:

    @patch("blockauth.views.google_auth_views.social_login")
    @patch("blockauth.views.google_auth_views.requests.get")
    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_returns_tokens(self, mock_post, mock_get, mock_social_login, api_client):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "google-token"},
        )
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"email": "google@test.com", "name": "Google User"},
        )
        from rest_framework.response import Response

        mock_social_login.return_value = Response(
            {"access": "test-access", "refresh": "test-refresh"},
            status=200,
        )

        response = api_client.get(reverse("google-login-callback"), {"code": "auth-code"})
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
        mock_social_login.assert_called_once()

    @patch("blockauth.views.google_auth_views.requests.post")
    def test_callback_token_exchange_failure(self, mock_post, api_client):
        mock_post.return_value = MagicMock(
            status_code=401,
            json=lambda: {"error": "invalid_grant"},
        )
        response = api_client.get(reverse("google-login-callback"), {"code": "bad-code"})
        assert response.status_code == 401

    def test_callback_missing_code(self, api_client):
        response = api_client.get(reverse("google-login-callback"))
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestFacebookAuthLoginView:

    def test_redirects_to_facebook(self, api_client):
        response = api_client.get(reverse("facebook-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "facebook.com" in response.url


@pytest.mark.django_db
class TestFacebookAuthCallbackView:

    @patch("blockauth.views.facebook_auth_views.social_login")
    @patch("blockauth.views.facebook_auth_views.requests.get")
    def test_callback_returns_tokens(self, mock_get, mock_social_login, api_client):
        mock_get.side_effect = [
            MagicMock(status_code=200, json=lambda: {"access_token": "fb-token"}),
            MagicMock(status_code=200, json=lambda: {"email": "fb@test.com", "name": "FB User"}),
        ]
        from rest_framework.response import Response

        mock_social_login.return_value = Response(
            {"access": "test-access", "refresh": "test-refresh"},
            status=200,
        )

        response = api_client.get(reverse("facebook-login-callback"), {"code": "auth-code"})
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data


@pytest.mark.django_db
class TestLinkedInAuthLoginView:

    def test_redirects_to_linkedin(self, api_client):
        response = api_client.get(reverse("linkedin-login"))
        assert response.status_code == status.HTTP_302_FOUND
        assert "linkedin.com" in response.url


@pytest.mark.django_db
class TestLinkedInAuthCallbackView:

    @patch("blockauth.views.linkedin_auth_views.social_login")
    @patch("blockauth.views.linkedin_auth_views.requests.get")
    @patch("blockauth.views.linkedin_auth_views.requests.post")
    def test_callback_returns_tokens(self, mock_post, mock_get, mock_social_login, api_client):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "li-token"},
        )
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"email": "li@test.com", "name": "LI User"},
        )
        from rest_framework.response import Response

        mock_social_login.return_value = Response(
            {"access": "test-access", "refresh": "test-refresh"},
            status=200,
        )

        response = api_client.get(reverse("linkedin-login-callback"), {"code": "auth-code"})
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data


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
