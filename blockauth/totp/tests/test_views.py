"""
TOTP Views Tests

Tests for API endpoints including:
- Rate limiting behavior
- Authentication requirements
- Error responses
- Input validation
"""

import unittest
from unittest.mock import MagicMock, patch

from rest_framework import status
from rest_framework.test import APIRequestFactory, force_authenticate

from ..exceptions import TOTPAlreadyEnabledError, TOTPInvalidCodeError, TOTPNotEnabledError
from ..views import (
    TOTPConfirmView,
    TOTPDisableView,
    TOTPSetupView,
    TOTPStatusView,
    TOTPSubject,
    TOTPThrottles,
    TOTPVerifyView,
)


class MockUser:
    """Mock user for testing."""

    def __init__(self, user_id="test-user-123"):
        self.id = user_id
        self.pk = user_id
        self.email = "test@example.com"
        self.is_authenticated = True

    def check_password(self, password):
        return password == "correct_password"


class TestTOTPSubjects(unittest.TestCase):
    """Test rate limiting subjects are properly defined."""

    def test_all_subjects_defined(self):
        """All TOTP subjects should be defined."""
        self.assertEqual(TOTPSubject.SETUP, "totp_setup")
        self.assertEqual(TOTPSubject.CONFIRM, "totp_confirm")
        self.assertEqual(TOTPSubject.VERIFY, "totp_verify")
        self.assertEqual(TOTPSubject.DISABLE, "totp_disable")
        self.assertEqual(TOTPSubject.REGENERATE_BACKUP, "totp_regenerate_backup")
        self.assertEqual(TOTPSubject.STATUS, "totp_status")


class TestTOTPThrottles(unittest.TestCase):
    """Test rate limiting configurations."""

    def test_setup_throttle_configuration(self):
        """Setup should have 10/hour rate limit (relaxed: minting is low-risk)."""
        throttle = TOTPThrottles.SETUP
        self.assertEqual(throttle.num_requests, 10)
        self.assertEqual(throttle.duration, 3600)  # 1 hour
        self.assertEqual(throttle.daily_limit, 30)

    def test_verify_throttle_configuration(self):
        """Verify should have 5/minute rate limit and fail closed."""
        throttle = TOTPThrottles.VERIFY
        self.assertEqual(throttle.num_requests, 5)
        self.assertEqual(throttle.duration, 60)
        self.assertTrue(throttle.fail_closed)

    def test_confirm_throttle_configuration(self):
        """Confirm should have 5/minute rate limit and fail closed."""
        throttle = TOTPThrottles.CONFIRM
        self.assertEqual(throttle.num_requests, 5)
        self.assertEqual(throttle.duration, 60)
        self.assertTrue(throttle.fail_closed)

    def test_disable_throttle_configuration(self):
        """Disable should have 3/hour rate limit and fail closed."""
        throttle = TOTPThrottles.DISABLE
        self.assertEqual(throttle.num_requests, 3)
        self.assertEqual(throttle.duration, 3600)
        self.assertTrue(throttle.fail_closed)

    def test_regenerate_backup_throttle_configuration(self):
        """Regenerate backup codes should have 3/hour rate limit and fail closed."""
        throttle = TOTPThrottles.REGENERATE_BACKUP
        self.assertEqual(throttle.num_requests, 3)
        self.assertEqual(throttle.duration, 3600)
        self.assertTrue(throttle.fail_closed)

    def test_status_throttle_configuration(self):
        """Status should have 30/minute rate limit and fail open (read-only)."""
        throttle = TOTPThrottles.STATUS
        self.assertEqual(throttle.num_requests, 30)
        self.assertEqual(throttle.duration, 60)
        self.assertFalse(throttle.fail_closed)


class TestRateLimitingBehavior(unittest.TestCase):
    """Test that rate limiting is enforced on views."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = MockUser()

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_setup_view_checks_rate_limit(self, mock_throttles):
        """Setup view should check rate limit."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = False
        mock_throttles.SETUP = mock_throttle

        request = self.factory.post("/totp/setup/", {})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPSetupView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_verify_view_checks_rate_limit(self, mock_throttles):
        """Verify view should check rate limit."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = False
        mock_throttles.VERIFY = mock_throttle

        request = self.factory.post("/totp/verify/", {"code": "123456"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPVerifyView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_rate_limit_response_format(self, mock_throttles):
        """Rate limit response should have proper error format."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = False
        mock_throttles.SETUP = mock_throttle

        request = self.factory.post("/totp/setup/", {})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPSetupView.as_view()
        response = view(request)

        self.assertIn("error", response.data)
        self.assertEqual(response.data["error"], "throttled")

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_verify_throttle_uses_unified_envelope(self, mock_throttles):
        """The in-method throttle path must emit the same {error: throttled}/429
        envelope as every other throttled path."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = False
        mock_throttles.VERIFY = mock_throttle

        request = self.factory.post("/totp/verify/", {"code": "123456"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        response = TOTPVerifyView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response.data["error"], "throttled")


class TestViewAuthentication(unittest.TestCase):
    """Test that views require authentication."""

    def setUp(self):
        self.factory = APIRequestFactory()

    def test_setup_requires_authentication(self):
        """Setup view should require authentication."""
        view = TOTPSetupView()
        from rest_framework.permissions import IsAuthenticated

        self.assertIn(IsAuthenticated, view.permission_classes)

    def test_verify_requires_authentication(self):
        """Verify view should require authentication."""
        view = TOTPVerifyView()
        from rest_framework.permissions import IsAuthenticated

        self.assertIn(IsAuthenticated, view.permission_classes)

    def test_status_requires_authentication(self):
        """Status view should require authentication."""
        view = TOTPStatusView()
        from rest_framework.permissions import IsAuthenticated

        self.assertIn(IsAuthenticated, view.permission_classes)

    def test_disable_requires_authentication(self):
        """Disable view should require authentication."""
        view = TOTPDisableView()
        from rest_framework.permissions import IsAuthenticated

        self.assertIn(IsAuthenticated, view.permission_classes)


class TestTOTPDisableView(unittest.TestCase):
    """Test TOTP disable behavior through the public view."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = MockUser()

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_disable_accepts_account_password_without_totp_code(self, mock_throttles, mock_get_service):
        """Disable should accept account password as a generic recovery path."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.DISABLE = mock_throttle

        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/disable/", {"password": "correct_password"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        response = TOTPDisableView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_service.verify.assert_not_called()
        mock_service.disable.assert_called_once_with(str(self.user.id))
        mock_throttle.record_success.assert_called_once()
        self.assertEqual(mock_throttle.record_success.call_args.args[1], TOTPSubject.DISABLE)

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_disable_rejects_wrong_account_password(self, mock_throttles, mock_get_service):
        """Wrong password should not disable TOTP."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.DISABLE = mock_throttle

        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/disable/", {"password": "wrong_password"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        response = TOTPDisableView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["error"], "invalid_password")
        mock_service.disable.assert_not_called()
        mock_throttle.record_failure.assert_called_once()
        self.assertEqual(mock_throttle.record_failure.call_args.args[1], TOTPSubject.DISABLE)

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_disable_accepts_verified_code(self, mock_throttles, mock_get_service):
        """Disable should accept a TOTP or backup code verified by the service."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.DISABLE = mock_throttle

        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/disable/", {"code": "BACKUP42"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_USER_AGENT"] = "Test Agent"

        response = TOTPDisableView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_service.verify.assert_called_once_with(
            user_id=str(self.user.id),
            code="BACKUP42",
            ip_address="127.0.0.1",
            user_agent="Test Agent",
        )
        mock_service.disable.assert_called_once_with(str(self.user.id))
        mock_throttle.record_success.assert_called_once()
        self.assertEqual(mock_throttle.record_success.call_args.args[1], TOTPSubject.DISABLE)


class TestErrorResponses(unittest.TestCase):
    """Test error response formatting."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = MockUser()

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_already_enabled_error_response(self, mock_throttles, mock_get_service):
        """Already enabled should return 409 Conflict."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.SETUP = mock_throttle

        mock_service = MagicMock()
        mock_service.setup_totp.side_effect = TOTPAlreadyEnabledError()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/setup/", {})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPSetupView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_not_enabled_error_response(self, mock_throttles, mock_get_service):
        """Not enabled should return 404 Not Found."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.VERIFY = mock_throttle

        mock_service = MagicMock()
        mock_service.verify.side_effect = TOTPNotEnabledError()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/verify/", {"code": "123456"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_USER_AGENT"] = "Test Agent"

        view = TOTPVerifyView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @patch("blockauth.totp.views.get_totp_service")
    @patch("blockauth.totp.views.TOTPThrottles")
    def test_invalid_code_error_response(self, mock_throttles, mock_get_service):
        """Invalid code should return 401 Unauthorized."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttle.record_failure = MagicMock()
        mock_throttles.VERIFY = mock_throttle

        mock_service = MagicMock()
        mock_service.verify.side_effect = TOTPInvalidCodeError()
        mock_get_service.return_value = mock_service

        request = self.factory.post("/totp/verify/", {"code": "000000"})
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_USER_AGENT"] = "Test Agent"

        view = TOTPVerifyView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TestInputValidation(unittest.TestCase):
    """Test input validation in views."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = MockUser()

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_verify_requires_code_field(self, mock_throttles):
        """Verify should require code in request body."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.VERIFY = mock_throttle

        request = self.factory.post("/totp/verify/", {})  # No code
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPVerifyView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("blockauth.totp.views.TOTPThrottles")
    def test_confirm_requires_code_field(self, mock_throttles):
        """Confirm should require code in request body."""
        mock_throttle = MagicMock()
        mock_throttle.allow_request.return_value = True
        mock_throttles.CONFIRM = mock_throttle

        request = self.factory.post("/totp/confirm/", {})  # No code
        force_authenticate(request, user=self.user)
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPConfirmView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


if __name__ == "__main__":
    unittest.main()
