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
from rest_framework.test import APIRequestFactory

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
        """Setup should have 3/hour rate limit."""
        throttle = TOTPThrottles.SETUP
        self.assertEqual(throttle.num_requests, 3)
        self.assertEqual(throttle.duration, 3600)  # 1 hour

    def test_verify_throttle_configuration(self):
        """Verify should have 5/minute rate limit."""
        throttle = TOTPThrottles.VERIFY
        self.assertEqual(throttle.num_requests, 5)
        self.assertEqual(throttle.duration, 60)

    def test_confirm_throttle_configuration(self):
        """Confirm should have 5/minute rate limit."""
        throttle = TOTPThrottles.CONFIRM
        self.assertEqual(throttle.num_requests, 5)
        self.assertEqual(throttle.duration, 60)

    def test_disable_throttle_configuration(self):
        """Disable should have 3/hour rate limit."""
        throttle = TOTPThrottles.DISABLE
        self.assertEqual(throttle.num_requests, 3)
        self.assertEqual(throttle.duration, 3600)

    def test_regenerate_backup_throttle_configuration(self):
        """Regenerate backup codes should have 3/hour rate limit."""
        throttle = TOTPThrottles.REGENERATE_BACKUP
        self.assertEqual(throttle.num_requests, 3)
        self.assertEqual(throttle.duration, 3600)

    def test_status_throttle_configuration(self):
        """Status should have 30/minute rate limit."""
        throttle = TOTPThrottles.STATUS
        self.assertEqual(throttle.num_requests, 30)
        self.assertEqual(throttle.duration, 60)


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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPSetupView.as_view()
        response = view(request)

        self.assertIn("error", response.data)
        self.assertEqual(response.data["error"], "rate_limit_exceeded")


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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
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
        request._force_auth_user = self.user
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        view = TOTPConfirmView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


if __name__ == "__main__":
    unittest.main()
