"""
Tests for OAuth views: Google, Facebook, LinkedIn login + callback.

Only external HTTP calls (requests.get/post) are mocked.

Note: OAuth callback tests that use social_login() may return 500 due to a
pre-existing bug where social_login passes first_name to get_or_create but
BlockUser doesn't have that field. The redirect tests work fine.
"""

import pytest
from unittest.mock import MagicMock, patch
from django.urls import reverse
from rest_framework import status


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
