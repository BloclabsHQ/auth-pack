"""
Integration tests for WalletLinkView.

WalletAuthenticator.verify_signature is mocked — crypto is not under test here.
Focus: HTTP contract, persistence, trigger firing, rate limiting, auth gate.
"""

import json
import time
from unittest.mock import MagicMock, patch

from rest_framework import status
from rest_framework.test import APIRequestFactory

from blockauth.views.wallet_auth_views import WalletLinkView

factory = APIRequestFactory()
VIEW = WalletLinkView.as_view()

VALID_ADDRESS = "0xabcdef1234567890abcdef1234567890abcdef12"


def _make_payload(wallet_address=VALID_ADDRESS):
    return {
        "wallet_address": wallet_address,
        "message": json.dumps(
            {
                "nonce": "test-nonce-0000-1111-2222",
                "timestamp": int(time.time()),
                "body": "Link wallet to TestApp",
            }
        ),
        "signature": "0x" + "a" * 130,
    }


def _make_user(wallet_address=None):
    user = MagicMock()
    user.id = "user-test-uuid-123"
    user.pk = "user-test-uuid-123"
    user.wallet_address = wallet_address
    user.is_authenticated = True
    user.authentication_types = []
    return user


class TestAuthGate:
    def test_unauthenticated_returns_401(self):
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        # No authentication provided — JWT authenticator finds no token, returns 401
        response = VIEW(request)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestSuccessPath:
    def test_valid_request_returns_200(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
            patch("blockauth.views.wallet_auth_views.get_config") as mock_config,
            patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}),
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            response = VIEW(request)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["wallet_address"] == VALID_ADDRESS
        assert "message" in response.data

    def test_valid_request_saves_wallet_address_on_user(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
            patch("blockauth.views.wallet_auth_views.get_config") as mock_config,
            patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}),
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            VIEW(request)

        assert user.wallet_address == VALID_ADDRESS
        user.save.assert_called()

    def test_valid_request_adds_wallet_authentication_type(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
            patch("blockauth.views.wallet_auth_views.get_config") as mock_config,
            patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}),
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            VIEW(request)

        user.add_authentication_type.assert_called_once_with("WALLET")

    def test_post_wallet_link_trigger_fires_with_correct_context(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user
        mock_trigger = MagicMock()

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
            patch("blockauth.views.wallet_auth_views.get_config") as mock_config,
            patch("blockauth.views.wallet_auth_views.model_to_json", return_value={"id": "user-test-uuid-123"}),
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = mock_trigger
            VIEW(request)

        mock_trigger.trigger.assert_called_once()
        ctx = mock_trigger.trigger.call_args[1]["context"]
        assert ctx["wallet_address"] == VALID_ADDRESS
        assert "user" in ctx
        assert "password" not in str(ctx)


class TestErrorPaths:
    def test_wallet_already_linked_returns_400(self):
        user = _make_user(wallet_address="0x1111111111111111111111111111111111111111")
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_wallet_in_use_returns_409(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with (
            patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth,
            patch("blockauth.serializers.wallet_serializers._User") as mock_user_model,
        ):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = True
            response = VIEW(request)

        assert response.status_code == status.HTTP_409_CONFLICT

    def test_invalid_signature_returns_400(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.return_value = False
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_expired_message_returns_400(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request._force_auth_user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError(
                "Message has expired. Please sign a new message."
            )
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestFeatureFlag:
    def test_wallet_link_url_absent_when_feature_disabled(self):
        from blockauth.urls import build_urlpatterns

        with patch("blockauth.urls.is_feature_enabled", side_effect=lambda f: f != "WALLET_LINK"):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-link" not in names

    def test_wallet_link_url_present_when_feature_enabled(self):
        from blockauth.urls import build_urlpatterns

        with (
            patch("blockauth.urls.is_feature_enabled", return_value=True),
            patch("blockauth.urls.is_social_auth_configured", return_value=False),
        ):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-link" in names


class TestInvalidAddress:
    def test_invalid_address_returns_400_not_500(self):
        user = _make_user()
        request = factory.post(
            "/wallet/link/",
            data={**_make_payload(), "wallet_address": "notvalid"},
            format="json",
        )
        request._force_auth_user = user
        response = VIEW(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
