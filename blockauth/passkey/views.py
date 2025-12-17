"""
Passkey/WebAuthn Views for BlockAuth

DRF API views for passkey registration and authentication.
Provides passwordless authentication using WebAuthn/FIDO2 standard.
Supports Face ID, Touch ID, Windows Hello, and hardware security keys.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_spectacular.utils import extend_schema

from blockauth.jwt.token_manager import jwt_manager
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.rate_limiter import RequestThrottle
from blockauth.utils.generics import sanitize_log_context

from .services.passkey_service import PasskeyService
from .exceptions import PasskeyError, PasskeyNotEnabledError, MaxCredentialsReachedError, CredentialNotFoundError
from . import is_enabled


# Passkey rate limiting subjects
class PasskeySubject:
    REGISTER_OPTIONS = "passkey_register_options"
    REGISTER_VERIFY = "passkey_register_verify"
    AUTH_OPTIONS = "passkey_auth_options"
    AUTH_VERIFY = "passkey_auth_verify"
    CREDENTIALS = "passkey_credentials"


# Generic error messages to prevent information leakage
GENERIC_AUTH_ERROR = {"error_code": "AUTH_FAILED", "message": "Authentication failed."}
GENERIC_PASSKEY_ERROR = {"error_code": "PASSKEY_ERROR", "message": "An error occurred. Please try again."}

# Import documentation from separate docs module
from .docs import (
    passkey_registration_options_docs,
    passkey_registration_verify_docs,
    passkey_authentication_options_docs,
    passkey_authentication_verify_docs,
    passkey_credentials_list_docs,
    passkey_credential_detail_docs,
    passkey_credential_update_docs,
    passkey_credential_delete_docs,
)


def get_passkey_service():
    """Get passkey service instance"""
    if not is_enabled():
        raise PasskeyNotEnabledError()
    return PasskeyService()


class PasskeyRegistrationOptionsView(APIView):
    """
    Generate WebAuthn registration options.

    Requires authentication. Returns options that should be passed
    to navigator.credentials.create() on the frontend.
    """
    permission_classes = [IsAuthenticated]
    rate_limit_handler = RequestThrottle(rate=(10, 60))  # 10 requests per minute

    @extend_schema(**passkey_registration_options_docs)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.REGISTER_OPTIONS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            display_name = request.data.get('display_name')

            options = service.generate_registration_options(
                user_id=request.user.id,
                username=request.user.email or request.user.username,
                display_name=display_name,
            )

            blockauth_logger.info(
                "Passkey registration options generated",
                {"user_id": str(request.user.id)}
            )

            return Response(options)

        except MaxCredentialsReachedError as e:
            blockauth_logger.warning("Passkey max credentials reached", sanitize_log_context({"user_id": str(request.user.id)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except PasskeyError as e:
            blockauth_logger.error("Passkey registration options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey registration options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyRegistrationVerifyView(APIView):
    """
    Verify WebAuthn registration response.

    Requires authentication. Verifies the credential created by the
    authenticator and stores it for future authentication.
    """
    permission_classes = [IsAuthenticated]
    rate_limit_handler = RequestThrottle(rate=(5, 60))  # 5 requests per minute

    @extend_schema(**passkey_registration_verify_docs)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.REGISTER_VERIFY):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            credential_name = request.data.get('name', '')

            credential = service.verify_registration(
                credential_data=request.data,
                user_id=request.user.id,
                credential_name=credential_name,
            )

            blockauth_logger.success(
                "Passkey registered successfully",
                {"user_id": str(request.user.id), "credential_id": credential.id}
            )

            return Response({
                'id': credential.id,
                'credential_id': credential.credential_id,
                'name': credential.name,
                'created_at': credential.created_at.isoformat() if credential.created_at else None,
                'authenticator_attachment': credential.authenticator_attachment,
                'transports': credential.transports,
                'backup_eligible': credential.backup_eligible,
            }, status=status.HTTP_201_CREATED)

        except PasskeyError as e:
            blockauth_logger.error(
                "Passkey registration verification failed",
                sanitize_log_context({"error": str(e), "user_id": str(request.user.id)})
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey registration error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyAuthenticationOptionsView(APIView):
    """
    Generate WebAuthn authentication options.

    Public endpoint. Returns options that should be passed to
    navigator.credentials.get() on the frontend.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    rate_limit_handler = RequestThrottle(rate=(20, 60))  # 20 requests per minute (public endpoint)

    @extend_schema(**passkey_authentication_options_docs)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.AUTH_OPTIONS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            username = request.data.get('username')
            user_id = None

            # If username provided, look up user
            if username:
                User = get_block_auth_user_model()
                try:
                    user = User.objects.get(email=username)
                    user_id = user.id
                except User.DoesNotExist:
                    # Don't reveal if user exists - still return options
                    pass

            options = service.generate_authentication_options(
                user_id=user_id,
                username=username,
            )

            blockauth_logger.info(
                "Passkey authentication options generated",
                {"username": username or "discoverable"}
            )

            return Response(options)

        except PasskeyError as e:
            blockauth_logger.error("Passkey auth options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey auth options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyAuthenticationVerifyView(APIView):
    """
    Verify WebAuthn authentication response.

    Public endpoint. Verifies the signature from the authenticator
    and returns JWT tokens on success.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    rate_limit_handler = RequestThrottle(rate=(10, 60))  # 10 requests per minute

    @extend_schema(**passkey_authentication_verify_docs)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.AUTH_VERIFY):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()

            result = service.verify_authentication(
                credential_data=request.data,
            )

            # Get user and generate tokens
            User = get_block_auth_user_model()
            user = User.objects.get(id=result.user_id)

            # Generate JWT tokens
            tokens = jwt_manager.generate_tokens_for_user(user)

            # Get credential info for response
            credentials = service.get_credentials_for_user(result.user_id)
            credential_info = next(
                (c for c in credentials if c.credential_id == result.credential_id),
                None
            )

            blockauth_logger.success(
                "Passkey authentication successful",
                {"user_id": str(result.user_id)}
            )

            return Response({
                'access': tokens['access'],
                'refresh': tokens['refresh'],
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                },
                'credential': {
                    'id': credential_info.id if credential_info else None,
                    'name': credential_info.name if credential_info else None,
                    'last_used_at': credential_info.last_used_at.isoformat() if credential_info and credential_info.last_used_at else None,
                },
            })

        except CredentialNotFoundError as e:
            blockauth_logger.error("Passkey authentication failed", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except PasskeyError as e:
            blockauth_logger.error("Passkey authentication failed", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey authentication error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)


class PasskeyCredentialListView(APIView):
    """
    List user's passkey credentials.

    Requires authentication.
    """
    permission_classes = [IsAuthenticated]
    rate_limit_handler = RequestThrottle(rate=(30, 60))  # 30 requests per minute

    @extend_schema(**passkey_credentials_list_docs)
    def get(self, request):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            credentials = service.get_credentials_for_user(request.user.id)

            return Response({
                'count': len(credentials),
                'credentials': [
                    {
                        'id': c.id,
                        'credential_id': c.credential_id,
                        'name': c.name,
                        'created_at': c.created_at.isoformat() if c.created_at else None,
                        'last_used_at': c.last_used_at.isoformat() if c.last_used_at else None,
                        'authenticator_attachment': c.authenticator_attachment,
                        'transports': c.transports,
                        'backup_eligible': c.backup_eligible,
                        'backup_state': c.backup_state,
                        'is_active': c.is_active,
                    }
                    for c in credentials
                ]
            })

        except PasskeyError as e:
            blockauth_logger.error("Passkey credentials list error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey credentials list error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyCredentialDetailView(APIView):
    """
    Manage individual passkey credential.

    Requires authentication. Supports GET, PATCH (update name), and DELETE.
    """
    permission_classes = [IsAuthenticated]
    rate_limit_handler = RequestThrottle(rate=(30, 60))  # 30 requests per minute

    @extend_schema(**passkey_credential_detail_docs)
    def get(self, request, credential_id):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next(
                (c for c in credentials if c.id == str(credential_id)),
                None
            )

            if not credential:
                raise CredentialNotFoundError()

            return Response({
                'id': credential.id,
                'credential_id': credential.credential_id,
                'name': credential.name,
                'created_at': credential.created_at.isoformat() if credential.created_at else None,
                'last_used_at': credential.last_used_at.isoformat() if credential.last_used_at else None,
                'authenticator_attachment': credential.authenticator_attachment,
                'transports': credential.transports,
                'backup_eligible': credential.backup_eligible,
                'backup_state': credential.backup_state,
                'is_active': credential.is_active,
            })

        except CredentialNotFoundError as e:
            blockauth_logger.warning("Passkey credential not found", sanitize_log_context({"credential_id": str(credential_id)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential detail error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(**passkey_credential_update_docs)
    def patch(self, request, credential_id):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()
            name = request.data.get('name')

            if not name:
                return Response(
                    {"error_code": "VALIDATION_ERROR", "message": "Name is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify ownership
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next(
                (c for c in credentials if c.id == str(credential_id)),
                None
            )

            if not credential:
                raise CredentialNotFoundError()

            # Update name
            service.update_credential_name(credential.credential_id, name)

            # Get updated credential
            credentials = service.get_credentials_for_user(request.user.id)
            updated = next(
                (c for c in credentials if c.id == str(credential_id)),
                None
            )

            blockauth_logger.info(
                "Passkey credential updated",
                {"user_id": str(request.user.id), "credential_id": str(credential_id)}
            )

            return Response({
                'id': updated.id,
                'credential_id': updated.credential_id,
                'name': updated.name,
                'created_at': updated.created_at.isoformat() if updated.created_at else None,
                'last_used_at': updated.last_used_at.isoformat() if updated.last_used_at else None,
                'authenticator_attachment': updated.authenticator_attachment,
                'transports': updated.transports,
                'backup_eligible': updated.backup_eligible,
                'backup_state': updated.backup_state,
                'is_active': updated.is_active,
            })

        except CredentialNotFoundError as e:
            blockauth_logger.warning("Passkey credential not found for update", sanitize_log_context({"credential_id": str(credential_id)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential update error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(**passkey_credential_delete_docs)
    def delete(self, request, credential_id):
        if not self.rate_limit_handler.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            service = get_passkey_service()

            # Verify ownership
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next(
                (c for c in credentials if c.id == str(credential_id)),
                None
            )

            if not credential:
                raise CredentialNotFoundError()

            # Delete credential
            service.delete_credential(credential.credential_id)

            blockauth_logger.info(
                "Passkey credential deleted",
                {"user_id": str(request.user.id), "credential_id": str(credential_id)}
            )

            return Response(status=status.HTTP_204_NO_CONTENT)

        except CredentialNotFoundError as e:
            blockauth_logger.warning("Passkey credential not found for delete", sanitize_log_context({"credential_id": str(credential_id)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential delete error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
