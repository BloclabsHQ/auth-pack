"""
Passkey/WebAuthn Exceptions for BlockAuth

Custom exceptions for all passkey-related errors.
Each exception includes an error code for easy identification.
"""

from .constants import PasskeyErrorCodes


class PasskeyError(Exception):
    """Base exception for all passkey errors"""

    error_code = 'PASSKEY_000'
    default_message = 'An error occurred during passkey operation'

    def __init__(self, message: str = None, details: dict = None):
        self.message = message or self.default_message
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        """Convert exception to dictionary for API responses"""
        return {
            'error_code': self.error_code,
            'message': self.message,
            'details': self.details,
        }


class PasskeyNotEnabledError(PasskeyError):
    """Raised when passkey module is not enabled"""
    error_code = PasskeyErrorCodes.NOT_ENABLED
    default_message = 'Passkey module is not enabled. Set PASSKEY_ENABLED=True in BLOCK_AUTH_SETTINGS.'


class ChallengeExpiredError(PasskeyError):
    """Raised when challenge has expired"""
    error_code = PasskeyErrorCodes.CHALLENGE_EXPIRED
    default_message = 'Challenge has expired. Please request a new challenge.'


class ChallengeAlreadyUsedError(PasskeyError):
    """Raised when challenge has already been used"""
    error_code = PasskeyErrorCodes.CHALLENGE_ALREADY_USED
    default_message = 'Challenge has already been used. Please request a new challenge.'


class InvalidOriginError(PasskeyError):
    """Raised when origin does not match allowed origins"""
    error_code = PasskeyErrorCodes.INVALID_ORIGIN
    default_message = 'Invalid origin. The request origin does not match allowed origins.'


class InvalidRpIdError(PasskeyError):
    """Raised when RP ID does not match configuration"""
    error_code = PasskeyErrorCodes.INVALID_RP_ID
    default_message = 'Invalid RP ID. The relying party ID does not match configuration.'


class CredentialNotFoundError(PasskeyError):
    """Raised when credential is not found"""
    error_code = PasskeyErrorCodes.CREDENTIAL_NOT_FOUND
    default_message = 'Credential not found.'


class CredentialRevokedError(PasskeyError):
    """Raised when credential has been revoked"""
    error_code = PasskeyErrorCodes.CREDENTIAL_REVOKED
    default_message = 'Credential has been revoked.'


class CounterRegressionError(PasskeyError):
    """
    Raised when signature counter has regressed.

    This indicates a potentially cloned authenticator, which is a
    security concern.
    """
    error_code = PasskeyErrorCodes.COUNTER_REGRESSION
    default_message = 'Signature counter regression detected. Possible cloned authenticator.'


class SignatureVerificationError(PasskeyError):
    """Raised when signature verification fails"""
    error_code = PasskeyErrorCodes.SIGNATURE_VERIFICATION_FAILED
    default_message = 'Signature verification failed.'


class MaxCredentialsReachedError(PasskeyError):
    """Raised when user has reached maximum number of credentials"""
    error_code = PasskeyErrorCodes.MAX_CREDENTIALS_REACHED
    default_message = 'Maximum number of credentials reached.'


class AttestationVerificationError(PasskeyError):
    """Raised when attestation verification fails"""
    error_code = PasskeyErrorCodes.ATTESTATION_VERIFICATION_FAILED
    default_message = 'Attestation verification failed.'


class RateLimitExceededError(PasskeyError):
    """Raised when rate limit is exceeded"""
    error_code = PasskeyErrorCodes.RATE_LIMIT_EXCEEDED
    default_message = 'Rate limit exceeded. Please try again later.'


class InvalidCredentialDataError(PasskeyError):
    """Raised when credential data is invalid or malformed"""
    error_code = PasskeyErrorCodes.INVALID_CREDENTIAL_DATA
    default_message = 'Invalid credential data.'


class UserNotFoundError(PasskeyError):
    """Raised when user is not found"""
    error_code = PasskeyErrorCodes.USER_NOT_FOUND
    default_message = 'User not found.'


class CredentialAlreadyExistsError(PasskeyError):
    """Raised when credential already exists"""
    error_code = PasskeyErrorCodes.CREDENTIAL_ALREADY_EXISTS
    default_message = 'Credential already exists.'


class ConfigurationError(PasskeyError):
    """Raised when configuration is invalid"""
    error_code = 'PASSKEY_CONFIG'
    default_message = 'Invalid passkey configuration.'
