"""
Integration tests for WalletUnlinkView.

Focus: HTTP contract, credential wipe, idempotency, auth gate, feature flag.
No crypto here — unlink takes no body.
"""

from unittest.mock import MagicMock, patch

from rest_framework import status
from rest_framework.test import APIRequestFactory

from blockauth.views.wallet_auth_views import WalletUnlinkView

factory = APIRequestFactory()
VIEW = WalletUnlinkView.as_view()

LINKED_ADDRESS = "0xabcdef1234567890abcdef1234567890abcdef12"


def _make_user(wallet_address=LINKED_ADDRESS):
    user = MagicMock()
    user.id = "user-test-uuid-123"
    user.pk = "user-test-uuid-123"
    user.wallet_address = wallet_address
    user.is_authenticated = True
    user.authentication_types = ["WALLET"] if wallet_address else []
    return user


class TestAuthGate:
    def test_unauthenticated_returns_401(self):
        request = factory.post("/wallet/unlink/")
        response = VIEW(request)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestSuccessPath:
    def test_valid_request_returns_200_with_unlinked_status(self):
        user = _make_user()
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        response = VIEW(request)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"status": "unlinked"}

    def test_clears_wallet_address(self):
        user = _make_user()
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        VIEW(request)

        assert user.wallet_address is None
        user.save.assert_called()

    def test_removes_wallet_authentication_type(self):
        user = _make_user()
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        VIEW(request)

        user.remove_authentication_type.assert_called_once_with("WALLET")


class TestIdempotency:
    def test_user_with_no_wallet_returns_404_no_wallet_linked(self):
        user = _make_user(wallet_address=None)
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        response = VIEW(request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data["error"]["code"] == "no_wallet_linked"

    def test_user_with_empty_wallet_returns_404(self):
        user = _make_user(wallet_address="")
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        response = VIEW(request)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data["error"]["code"] == "no_wallet_linked"

    def test_second_unlink_after_success_returns_404(self):
        """First unlink clears wallet_address; second call sees None and 404s."""
        user = _make_user()
        request1 = factory.post("/wallet/unlink/")
        request1._force_auth_user = user
        first = VIEW(request1)
        assert first.status_code == status.HTTP_200_OK

        request2 = factory.post("/wallet/unlink/")
        request2._force_auth_user = user
        second = VIEW(request2)
        assert second.status_code == status.HTTP_404_NOT_FOUND
        assert second.data["error"]["code"] == "no_wallet_linked"

    def test_no_wallet_does_not_call_remove_auth_type(self):
        user = _make_user(wallet_address=None)
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        VIEW(request)

        user.remove_authentication_type.assert_not_called()
        user.save.assert_not_called()


class TestFeatureFlag:
    def test_wallet_unlink_url_absent_when_wallet_link_disabled(self):
        from blockauth.urls import build_urlpatterns

        with patch("blockauth.urls.is_feature_enabled", side_effect=lambda f: f != "WALLET_LINK"):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-unlink" not in names

    def test_wallet_unlink_url_present_when_wallet_link_enabled(self):
        from blockauth.urls import build_urlpatterns

        with (
            patch("blockauth.urls.is_feature_enabled", return_value=True),
            patch("blockauth.urls.is_social_auth_configured", return_value=False),
        ):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-unlink" in names


class TestRateLimiter:
    def test_rate_limited_returns_429(self):
        user = _make_user()
        request = factory.post("/wallet/unlink/")
        request._force_auth_user = user

        with patch.object(WalletUnlinkView.unlink_throttle, "allow_request", return_value=False):
            with patch.object(WalletUnlinkView.unlink_throttle, "get_block_reason", return_value="rate_limit"):
                response = VIEW(request)

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
