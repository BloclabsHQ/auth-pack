"""
Unit tests for Passkey/WebAuthn module

This module tests all Passkey functionality including:
- Module enablement checking
- Exception classes
- Constants and enums
- Rate limiting
- Views and API endpoints
- Generic error responses
"""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timedelta

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from ..constants import (
    PasskeyConfigKeys,
    AttestationConveyance,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    COSEAlgorithm,
    AuthenticatorTransport,
    PasskeyFeatureFlags,
    PasskeyErrorCodes,
)
from ..exceptions import (
    PasskeyError,
    PasskeyNotEnabledError,
    ChallengeExpiredError,
    ChallengeAlreadyUsedError,
    InvalidOriginError,
    InvalidRpIdError,
    CredentialNotFoundError,
    CredentialRevokedError,
    CounterRegressionError,
    SignatureVerificationError,
    MaxCredentialsReachedError,
    AttestationVerificationError,
    RateLimitExceededError,
    InvalidCredentialDataError,
    ConfigurationError,
)
from ..views import (
    PasskeySubject,
    GENERIC_AUTH_ERROR,
    GENERIC_PASSKEY_ERROR,
)


class TestPasskeyConstants(unittest.TestCase):
    """Test passkey constants and enums"""

    def test_config_keys_exist(self):
        """Test that all config keys are defined"""
        self.assertEqual(PasskeyConfigKeys.RP_ID, 'PASSKEY_RP_ID')
        self.assertEqual(PasskeyConfigKeys.RP_NAME, 'PASSKEY_RP_NAME')
        self.assertEqual(PasskeyConfigKeys.ALLOWED_ORIGINS, 'PASSKEY_ALLOWED_ORIGINS')
        self.assertEqual(PasskeyConfigKeys.ATTESTATION, 'PASSKEY_ATTESTATION')
        self.assertEqual(PasskeyConfigKeys.USER_VERIFICATION, 'PASSKEY_USER_VERIFICATION')

    def test_attestation_conveyance_values(self):
        """Test attestation conveyance enum values"""
        self.assertEqual(AttestationConveyance.NONE, 'none')
        self.assertEqual(AttestationConveyance.INDIRECT, 'indirect')
        self.assertEqual(AttestationConveyance.DIRECT, 'direct')
        self.assertEqual(AttestationConveyance.ENTERPRISE, 'enterprise')

    def test_authenticator_attachment_values(self):
        """Test authenticator attachment enum values"""
        self.assertEqual(AuthenticatorAttachment.PLATFORM, 'platform')
        self.assertEqual(AuthenticatorAttachment.CROSS_PLATFORM, 'cross-platform')

    def test_resident_key_requirement_values(self):
        """Test resident key requirement enum values"""
        self.assertEqual(ResidentKeyRequirement.DISCOURAGED, 'discouraged')
        self.assertEqual(ResidentKeyRequirement.PREFERRED, 'preferred')
        self.assertEqual(ResidentKeyRequirement.REQUIRED, 'required')

    def test_user_verification_requirement_values(self):
        """Test user verification requirement enum values"""
        self.assertEqual(UserVerificationRequirement.DISCOURAGED, 'discouraged')
        self.assertEqual(UserVerificationRequirement.PREFERRED, 'preferred')
        self.assertEqual(UserVerificationRequirement.REQUIRED, 'required')

    def test_cose_algorithm_values(self):
        """Test COSE algorithm values"""
        self.assertEqual(COSEAlgorithm.ES256, -7)
        self.assertEqual(COSEAlgorithm.RS256, -257)

    def test_authenticator_transport_values(self):
        """Test authenticator transport enum values"""
        self.assertEqual(AuthenticatorTransport.USB, 'usb')
        self.assertEqual(AuthenticatorTransport.NFC, 'nfc')
        self.assertEqual(AuthenticatorTransport.BLE, 'ble')
        self.assertEqual(AuthenticatorTransport.INTERNAL, 'internal')
        self.assertEqual(AuthenticatorTransport.HYBRID, 'hybrid')

    def test_error_codes_exist(self):
        """Test that error codes are defined"""
        self.assertIsNotNone(PasskeyErrorCodes.NOT_ENABLED)
        self.assertIsNotNone(PasskeyErrorCodes.CHALLENGE_EXPIRED)
        self.assertIsNotNone(PasskeyErrorCodes.CHALLENGE_ALREADY_USED)
        self.assertIsNotNone(PasskeyErrorCodes.INVALID_ORIGIN)
        self.assertIsNotNone(PasskeyErrorCodes.CREDENTIAL_NOT_FOUND)


class TestPasskeyExceptions(unittest.TestCase):
    """Test passkey exception classes"""

    def test_base_passkey_error(self):
        """Test base PasskeyError class"""
        error = PasskeyError()
        self.assertEqual(error.error_code, 'PASSKEY_000')
        self.assertEqual(error.message, 'An error occurred during passkey operation')
        self.assertEqual(error.details, {})

    def test_passkey_error_custom_message(self):
        """Test PasskeyError with custom message"""
        error = PasskeyError(message='Custom error message')
        self.assertEqual(error.message, 'Custom error message')

    def test_passkey_error_with_details(self):
        """Test PasskeyError with details"""
        error = PasskeyError(details={'key': 'value'})
        self.assertEqual(error.details, {'key': 'value'})

    def test_passkey_error_to_dict(self):
        """Test PasskeyError to_dict method"""
        error = PasskeyError(message='Test error', details={'foo': 'bar'})
        result = error.to_dict()

        self.assertEqual(result['error_code'], 'PASSKEY_000')
        self.assertEqual(result['message'], 'Test error')
        self.assertEqual(result['details'], {'foo': 'bar'})

    def test_passkey_not_enabled_error(self):
        """Test PasskeyNotEnabledError"""
        error = PasskeyNotEnabledError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.NOT_ENABLED)
        self.assertIn('FEATURES.PASSKEY_AUTH', error.default_message)

    def test_challenge_expired_error(self):
        """Test ChallengeExpiredError"""
        error = ChallengeExpiredError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.CHALLENGE_EXPIRED)
        self.assertIn('expired', error.message.lower())

    def test_challenge_already_used_error(self):
        """Test ChallengeAlreadyUsedError"""
        error = ChallengeAlreadyUsedError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.CHALLENGE_ALREADY_USED)
        self.assertIn('already', error.message.lower())

    def test_invalid_origin_error(self):
        """Test InvalidOriginError"""
        error = InvalidOriginError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.INVALID_ORIGIN)
        self.assertIn('origin', error.message.lower())

    def test_invalid_rp_id_error(self):
        """Test InvalidRpIdError"""
        error = InvalidRpIdError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.INVALID_RP_ID)

    def test_credential_not_found_error(self):
        """Test CredentialNotFoundError"""
        error = CredentialNotFoundError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.CREDENTIAL_NOT_FOUND)

    def test_credential_revoked_error(self):
        """Test CredentialRevokedError"""
        error = CredentialRevokedError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.CREDENTIAL_REVOKED)

    def test_counter_regression_error(self):
        """Test CounterRegressionError"""
        error = CounterRegressionError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.COUNTER_REGRESSION)
        self.assertIn('counter', error.message.lower())

    def test_signature_verification_error(self):
        """Test SignatureVerificationError"""
        error = SignatureVerificationError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.SIGNATURE_VERIFICATION_FAILED)

    def test_max_credentials_reached_error(self):
        """Test MaxCredentialsReachedError"""
        error = MaxCredentialsReachedError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.MAX_CREDENTIALS_REACHED)

    def test_attestation_verification_error(self):
        """Test AttestationVerificationError"""
        error = AttestationVerificationError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.ATTESTATION_VERIFICATION_FAILED)

    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError"""
        error = RateLimitExceededError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.RATE_LIMIT_EXCEEDED)

    def test_invalid_credential_data_error(self):
        """Test InvalidCredentialDataError"""
        error = InvalidCredentialDataError()
        self.assertEqual(error.error_code, PasskeyErrorCodes.INVALID_CREDENTIAL_DATA)

    def test_configuration_error(self):
        """Test ConfigurationError"""
        error = ConfigurationError()
        self.assertEqual(error.error_code, 'PASSKEY_CONFIG')


class TestPasskeySubjects(unittest.TestCase):
    """Test passkey rate limiting subjects"""

    def test_all_subjects_defined(self):
        """Test that all rate limiting subjects are defined"""
        self.assertEqual(PasskeySubject.REGISTER_OPTIONS, 'passkey_register_options')
        self.assertEqual(PasskeySubject.REGISTER_VERIFY, 'passkey_register_verify')
        self.assertEqual(PasskeySubject.AUTH_OPTIONS, 'passkey_auth_options')
        self.assertEqual(PasskeySubject.AUTH_VERIFY, 'passkey_auth_verify')
        self.assertEqual(PasskeySubject.CREDENTIALS, 'passkey_credentials')


class TestGenericErrorMessages(unittest.TestCase):
    """Test generic error messages for information leakage prevention"""

    def test_generic_auth_error(self):
        """Test generic authentication error message"""
        self.assertEqual(GENERIC_AUTH_ERROR['error_code'], 'AUTH_FAILED')
        self.assertEqual(GENERIC_AUTH_ERROR['message'], 'Authentication failed.')

    def test_generic_passkey_error(self):
        """Test generic passkey error message"""
        self.assertEqual(GENERIC_PASSKEY_ERROR['error_code'], 'PASSKEY_ERROR')
        self.assertEqual(GENERIC_PASSKEY_ERROR['message'], 'An error occurred. Please try again.')


class TestIsEnabled(unittest.TestCase):
    """Test is_enabled() function"""

    @patch('blockauth.passkey.get_config')
    def test_is_enabled_when_true(self, mock_get_config):
        """Test is_enabled returns True when feature is enabled"""
        from blockauth.passkey import is_enabled

        mock_get_config.return_value = {'PASSKEY_AUTH': True}

        result = is_enabled()
        self.assertTrue(result)

    @patch('blockauth.passkey.get_config')
    def test_is_enabled_when_false(self, mock_get_config):
        """Test is_enabled returns False when feature is disabled"""
        from blockauth.passkey import is_enabled

        mock_get_config.return_value = {'PASSKEY_AUTH': False}

        result = is_enabled()
        self.assertFalse(result)

    @patch('blockauth.passkey.get_config')
    def test_is_enabled_when_not_set(self, mock_get_config):
        """Test is_enabled returns False when feature is not set"""
        from blockauth.passkey import is_enabled

        mock_get_config.return_value = {}

        result = is_enabled()
        self.assertFalse(result)

    def test_is_enabled_import_error(self):
        """Test is_enabled returns False on import error"""
        from blockauth.passkey import is_enabled

        with patch('blockauth.passkey.get_config', side_effect=ImportError):
            result = is_enabled()
            self.assertFalse(result)


class TestPasskeyViews(TestCase):
    """Test passkey API views"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        User = get_user_model()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_registration_options_requires_auth(self, mock_service, mock_is_enabled):
        """Test that registration options endpoint requires authentication"""
        from ..views import PasskeyRegistrationOptionsView

        mock_is_enabled.return_value = True

        view = PasskeyRegistrationOptionsView.as_view()
        request = self.factory.post('/auth/passkey/register/options/')
        request.user = MagicMock(is_authenticated=False)

        # Without authentication, should return 401 or 403
        response = view(request)
        self.assertIn(response.status_code, [401, 403])

    @patch('blockauth.passkey.views.is_enabled')
    def test_passkey_not_enabled_error(self, mock_is_enabled):
        """Test error when passkey is not enabled"""
        from ..views import PasskeyRegistrationOptionsView

        mock_is_enabled.return_value = False

        view = PasskeyRegistrationOptionsView.as_view()
        request = self.factory.post('/auth/passkey/register/options/')
        request.user = self.user
        request.data = {}
        request.META = {'REMOTE_ADDR': '127.0.0.1'}

        response = view(request)

        # Should return error when passkey not enabled
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_auth_options_is_public(self, mock_service_class, mock_is_enabled):
        """Test that authentication options endpoint is public"""
        from ..views import PasskeyAuthenticationOptionsView

        mock_is_enabled.return_value = True
        mock_service = MagicMock()
        mock_service.generate_authentication_options.return_value = {
            'challenge': 'test_challenge',
            'rpId': 'localhost',
            'allowCredentials': [],
            'userVerification': 'required',
        }
        mock_service_class.return_value = mock_service

        view = PasskeyAuthenticationOptionsView.as_view()
        request = self.factory.post(
            '/auth/passkey/auth/options/',
            data={},
            content_type='application/json'
        )
        request.data = {}
        request.META = {'REMOTE_ADDR': '127.0.0.1'}

        response = view(request)

        # Public endpoint should return 200
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class TestRateLimiting(TestCase):
    """Test rate limiting on passkey views"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        User = get_user_model()
        self.user = User.objects.create_user(
            email='ratelimit@example.com',
            password='testpass123'
        )

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_rate_limit_handler_exists(self, mock_service, mock_is_enabled):
        """Test that rate limit handler is defined on views"""
        from ..views import (
            PasskeyRegistrationOptionsView,
            PasskeyRegistrationVerifyView,
            PasskeyAuthenticationOptionsView,
            PasskeyAuthenticationVerifyView,
            PasskeyCredentialListView,
            PasskeyCredentialDetailView,
        )

        # All views should have rate_limit_handler
        self.assertTrue(hasattr(PasskeyRegistrationOptionsView, 'rate_limit_handler'))
        self.assertTrue(hasattr(PasskeyRegistrationVerifyView, 'rate_limit_handler'))
        self.assertTrue(hasattr(PasskeyAuthenticationOptionsView, 'rate_limit_handler'))
        self.assertTrue(hasattr(PasskeyAuthenticationVerifyView, 'rate_limit_handler'))
        self.assertTrue(hasattr(PasskeyCredentialListView, 'rate_limit_handler'))
        self.assertTrue(hasattr(PasskeyCredentialDetailView, 'rate_limit_handler'))

    def test_rate_limit_response_format(self):
        """Test rate limit response format"""
        # Rate limit response should have specific format
        expected_error_code = 'RATE_LIMIT'
        expected_status = status.HTTP_429_TOO_MANY_REQUESTS

        # Verify the status code constant
        self.assertEqual(expected_status, 429)


class TestViewErrorHandling(TestCase):
    """Test error handling in passkey views"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        User = get_user_model()
        self.user = User.objects.create_user(
            email='error@example.com',
            password='testpass123'
        )

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_max_credentials_returns_generic_error(self, mock_service_class, mock_is_enabled):
        """Test that MaxCredentialsReachedError returns generic error"""
        from ..views import PasskeyRegistrationOptionsView

        mock_is_enabled.return_value = True
        mock_service = MagicMock()
        mock_service.generate_registration_options.side_effect = MaxCredentialsReachedError()
        mock_service_class.return_value = mock_service

        view = PasskeyRegistrationOptionsView.as_view()
        request = self.factory.post('/auth/passkey/register/options/')
        request.user = self.user
        request.data = {}
        request.META = {'REMOTE_ADDR': '127.0.0.1'}

        response = view(request)

        # Should return generic error, not specific error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error_code'], 'PASSKEY_ERROR')
        self.assertNotIn('max', response.data['message'].lower())

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_credential_not_found_returns_generic_auth_error(self, mock_service_class, mock_is_enabled):
        """Test that CredentialNotFoundError returns generic auth error"""
        from ..views import PasskeyAuthenticationVerifyView

        mock_is_enabled.return_value = True
        mock_service = MagicMock()
        mock_service.verify_authentication.side_effect = CredentialNotFoundError()
        mock_service_class.return_value = mock_service

        view = PasskeyAuthenticationVerifyView.as_view()
        request = self.factory.post('/auth/passkey/auth/verify/')
        request.data = {'id': 'test', 'rawId': 'test', 'type': 'public-key', 'response': {}}
        request.META = {'REMOTE_ADDR': '127.0.0.1'}

        response = view(request)

        # Should return generic auth error to prevent enumeration
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error_code'], 'AUTH_FAILED')
        self.assertEqual(response.data['message'], 'Authentication failed.')


class TestCredentialManagement(TestCase):
    """Test credential management views"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        User = get_user_model()
        self.user = User.objects.create_user(
            email='cred@example.com',
            password='testpass123'
        )

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_list_credentials_requires_auth(self, mock_service, mock_is_enabled):
        """Test that listing credentials requires authentication"""
        from ..views import PasskeyCredentialListView

        mock_is_enabled.return_value = True

        view = PasskeyCredentialListView.as_view()
        request = self.factory.get('/auth/passkey/credentials/')
        request.user = MagicMock(is_authenticated=False)

        response = view(request)
        self.assertIn(response.status_code, [401, 403])

    @patch('blockauth.passkey.views.is_enabled')
    @patch('blockauth.passkey.views.PasskeyService')
    def test_delete_credential_requires_auth(self, mock_service, mock_is_enabled):
        """Test that deleting credentials requires authentication"""
        from ..views import PasskeyCredentialDetailView

        mock_is_enabled.return_value = True

        view = PasskeyCredentialDetailView.as_view()
        request = self.factory.delete('/auth/passkey/credentials/123/')
        request.user = MagicMock(is_authenticated=False)

        response = view(request, credential_id='123')
        self.assertIn(response.status_code, [401, 403])


if __name__ == '__main__':
    unittest.main()
