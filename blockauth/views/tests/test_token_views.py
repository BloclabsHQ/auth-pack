"""
Tests for AuthRefreshTokenView.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.utils.token import Token, generate_auth_token

REFRESH_URL = reverse("refresh-token")


@pytest.mark.django_db
class TestAuthRefreshTokenView:

    def test_refresh_returns_new_tokens(self, api_client, create_user):
        user = create_user()
        token = Token()
        _, refresh = generate_auth_token(token_class=token, user_id=str(user.id))

        response = api_client.post(REFRESH_URL, {"refresh_token": refresh})
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    def test_refresh_returns_user_payload(self, api_client, create_user):
        """api-optimization v0.9.0: refresh response includes the user so
        clients can drop the 5-min /me/ poller. The view already loads
        the user for custom-claims population."""
        user = create_user(email="ref@test.com")
        token = Token()
        _, refresh = generate_auth_token(token_class=token, user_id=str(user.id))

        response = api_client.post(REFRESH_URL, {"refresh_token": refresh})
        assert response.status_code == status.HTTP_200_OK
        assert "user" in response.data
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] == "ref@test.com"
        assert user_payload["is_verified"] is True
        assert "wallet_address" in user_payload
        # Issue #131: clients require is_active, date_joined, and wallets in
        # every login-shaped response. first_name / last_name are intentionally
        # omitted when unset.
        assert user_payload["is_active"] is True
        assert "date_joined" in user_payload
        assert user_payload["wallets"] == []
        assert "first_name" not in user_payload
        assert "last_name" not in user_payload

    def test_refresh_with_access_token_fails(self, api_client, create_user):
        """Access tokens should not be usable as refresh tokens."""
        user = create_user()
        token = Token()
        access, _ = generate_auth_token(token_class=token, user_id=str(user.id))

        response = api_client.post(REFRESH_URL, {"refresh_token": access})
        # Should fail because token type is "access" not "refresh"
        assert response.status_code in (
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    def test_refresh_with_invalid_token(self, api_client):
        response = api_client.post(REFRESH_URL, {"refresh_token": "invalid.jwt.token"})
        assert response.status_code in (
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        )

    def test_refresh_missing_token(self, api_client):
        response = api_client.post(REFRESH_URL, {})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_refresh_rotates_token(self, api_client, create_user):
        """New refresh token should be different from old one (rotation)."""
        user = create_user()
        token = Token()
        _, old_refresh = generate_auth_token(token_class=token, user_id=str(user.id))

        response = api_client.post(REFRESH_URL, {"refresh_token": old_refresh})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["refresh"] != old_refresh
