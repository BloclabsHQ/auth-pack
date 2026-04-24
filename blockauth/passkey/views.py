"""
Passkey/WebAuthn Views for BlockAuth

DRF API views for passkey registration and authentication.
Provides passwordless authentication using WebAuthn/FIDO2 standard.
Supports Face ID, Touch ID, Windows Hello, and hardware security keys.
"""

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.jwt.token_manager import jwt_manager
from blockauth.notification import NotificationEvent, emit_passkey_event
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.rate_limiter import EnhancedThrottle

from . import is_enabled
from .config import get_passkey_config
from .exceptions import CredentialNotFoundError, MaxCredentialsReachedError, PasskeyError, PasskeyNotEnabledError
from .services.passkey_service import PasskeyService


def _request_origin(request) -> str:
    """
    Extract the request Origin for per-request RP_ID resolution.

    Uses only the ``Origin`` header. Browsers send it on every same-origin and
    cross-origin POST (including every WebAuthn endpoint here) and servers
    cannot forge it across a CORS boundary. We deliberately do NOT fall back
    to ``Referer``: it is not CORS-controlled and can be set to any value by
    non-browser clients, which would feed untrusted input into the resolver.

    Returns ``""`` when the Origin header is missing; ``resolve_rp_id`` treats
    that as "use the static RP_ID fallback".
    """
    return request.META.get("HTTP_ORIGIN", "") or ""


def _resolve_rp_id(request):
    """
    Resolve the RP_ID for the current request.

    Returns ``None`` only when the passkey feature is disabled. All other
    errors (``ConfigurationError`` from a bad resolver or malformed
    ``RP_ID_BY_ORIGIN`` map, etc.) propagate so misconfiguration surfaces
    loudly instead of silently falling back to the static ``RP_ID``.
    """
    try:
        config = get_passkey_config()
    except PasskeyNotEnabledError:
        return None
    return config.resolve_rp_id(_request_origin(request))


# Passkey rate limiting subjects
class PasskeySubject:
    REGISTER_OPTIONS = "passkey_register_options"
    REGISTER_VERIFY = "passkey_register_verify"
    AUTH_OPTIONS = "passkey_auth_options"
    AUTH_VERIFY = "passkey_auth_verify"
    CREDENTIALS = "passkey_credentials"


# Throttle configurations
class PasskeyThrottles:
    """Centralized passkey throttle configurations."""

    # Challenge generation: 10/min, 50/day
    REGISTER_OPTIONS = EnhancedThrottle(rate=(10, 60), daily_limit=50)
    # Registration: 5/min, 10/day (creates credentials)
    REGISTER_VERIFY = EnhancedThrottle(rate=(5, 60), daily_limit=10, max_failures=3, cooldown_minutes=30)
    # Auth options: 20/min, 100/day (public endpoint)
    AUTH_OPTIONS = EnhancedThrottle(rate=(20, 60), daily_limit=100)
    # Auth verify: 10/min, cooldown after 5 failures
    AUTH_VERIFY = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)
    # Credential management: 30/min
    CREDENTIALS = EnhancedThrottle(rate=(30, 60))


# Generic error messages to prevent information leakage
GENERIC_AUTH_ERROR = {"error_code": "AUTH_FAILED", "message": "Authentication failed."}
GENERIC_PASSKEY_ERROR = {"error_code": "PASSKEY_ERROR", "message": "An error occurred. Please try again."}

# Import documentation from separate docs module
from .docs import (
    passkey_authentication_options_docs,
    passkey_authentication_verify_docs,
    passkey_credential_delete_docs,
    passkey_credential_detail_docs,
    passkey_credential_update_docs,
    passkey_credentials_list_docs,
    passkey_registration_options_docs,
    passkey_registration_verify_docs,
)


def get_passkey_service():
    """Get passkey service instance"""
    if not is_enabled():
        raise PasskeyNotEnabledError()
    return PasskeyService()


class PasskeyBaseView(APIView):
    """Base class for passkey views with shared utilities."""

    @staticmethod
    def rate_limit_handler(request, subject):
        """Return rate limit exceeded response."""
        return Response(
            {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )


class PasskeyRegistrationOptionsView(PasskeyBaseView):
    """
    Generate WebAuthn registration options.

    Requires authentication. Returns options that should be passed
    to navigator.credentials.create() on the frontend.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**passkey_registration_options_docs)
    def post(self, request):
        throttle = PasskeyThrottles.REGISTER_OPTIONS
        if not throttle.allow_request(request, PasskeySubject.REGISTER_OPTIONS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            display_name = request.data.get("display_name")

            # Build human-readable username (user.name in WebAuthn spec)
            # Priority: email > wallet address (truncated) > user ID prefix
            user = request.user
            username = (
                user.email
                or (f"{user.wallet_address[:10]}..." if getattr(user, "wallet_address", None) else None)
                or f"User {str(user.id)[:8]}"
            )

            # Auto-resolve display_name from profile if client didn't provide one
            if not display_name:
                full_name = " ".join(
                    filter(
                        None,
                        [
                            getattr(user, "first_name", None),
                            getattr(user, "last_name", None),
                        ],
                    )
                )
                display_name = full_name or None

            options = service.generate_registration_options(
                user_id=user.id,
                username=username,
                display_name=display_name,
                rp_id=_resolve_rp_id(request),
            )

            blockauth_logger.info("Passkey registration options generated", {"user_id": str(request.user.id)})

            return Response(options)

        except MaxCredentialsReachedError:
            blockauth_logger.warning(
                "Passkey max credentials reached", sanitize_log_context({"user_id": str(request.user.id)})
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except PasskeyError as e:
            blockauth_logger.error("Passkey registration options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey registration options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyRegistrationVerifyView(PasskeyBaseView):
    """
    Verify WebAuthn registration response.

    Requires authentication. Verifies the credential created by the
    authenticator and stores it for future authentication.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**passkey_registration_verify_docs)
    def post(self, request):
        throttle = PasskeyThrottles.REGISTER_VERIFY
        if not throttle.allow_request(request, PasskeySubject.REGISTER_VERIFY):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            credential_name = request.data.get("name", "")

            credential = service.verify_registration(
                credential_data=request.data,
                user_id=request.user.id,
                credential_name=credential_name,
                expected_rp_id=_resolve_rp_id(request),
            )

            # Record success and emit event
            throttle.record_success(request, PasskeySubject.REGISTER_VERIFY)
            emit_passkey_event(
                NotificationEvent.PASSKEY_REGISTERED,
                {
                    "user_id": str(request.user.id),
                    "credential_id": str(credential.id),
                },
            )

            blockauth_logger.success(
                "Passkey registered successfully", {"user_id": str(request.user.id), "credential_id": credential.id}
            )

            return Response(
                {
                    "id": credential.id,
                    "credential_id": credential.credential_id,
                    "name": credential.name,
                    "created_at": credential.created_at.isoformat() if credential.created_at else None,
                    "authenticator_attachment": credential.authenticator_attachment,
                    "transports": credential.transports,
                    "backup_eligible": credential.backup_eligible,
                },
                status=status.HTTP_201_CREATED,
            )

        except PasskeyError as e:
            throttle.record_failure(request, PasskeySubject.REGISTER_VERIFY)
            blockauth_logger.error(
                "Passkey registration verification failed",
                sanitize_log_context({"error": str(e), "user_id": str(request.user.id)}),
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            throttle.record_failure(request, PasskeySubject.REGISTER_VERIFY)
            blockauth_logger.error("Passkey registration error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyAuthenticationOptionsView(PasskeyBaseView):
    """
    Generate WebAuthn authentication options.

    Public endpoint. Returns options that should be passed to
    navigator.credentials.get() on the frontend.
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(**passkey_authentication_options_docs)
    def post(self, request):
        throttle = PasskeyThrottles.AUTH_OPTIONS
        if not throttle.allow_request(request, PasskeySubject.AUTH_OPTIONS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            username = request.data.get("username")
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
                rp_id=_resolve_rp_id(request),
            )

            blockauth_logger.info("Passkey authentication options generated", {"username": username or "discoverable"})

            return Response(options)

        except PasskeyError as e:
            blockauth_logger.error("Passkey auth options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey auth options error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyAuthenticationVerifyView(PasskeyBaseView):
    """
    Verify WebAuthn authentication response.

    Public endpoint. Verifies the signature from the authenticator
    and returns JWT tokens on success.
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(**passkey_authentication_verify_docs)
    def post(self, request):
        throttle = PasskeyThrottles.AUTH_VERIFY
        if not throttle.allow_request(request, PasskeySubject.AUTH_VERIFY):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()

            result = service.verify_authentication(
                credential_data=request.data,
                expected_rp_id=_resolve_rp_id(request),
            )

            # Get user and generate tokens
            User = get_block_auth_user_model()
            user = User.objects.get(id=result.user_id)

            # Generate JWT tokens
            tokens = jwt_manager.generate_tokens_for_user(user)

            # Record success and emit event
            throttle.record_success(request, PasskeySubject.AUTH_VERIFY)
            emit_passkey_event(
                NotificationEvent.PASSKEY_AUTHENTICATED,
                {
                    "user_id": str(result.user_id),
                    "credential_id": result.credential_id[:20] if result.credential_id else None,
                },
            )

            # Get credential info for response
            credentials = service.get_credentials_for_user(result.user_id)
            credential_info = next((c for c in credentials if c.credential_id == result.credential_id), None)

            blockauth_logger.success("Passkey authentication successful", {"user_id": str(result.user_id)})

            return Response(
                {
                    "access": tokens["access"],
                    "refresh": tokens["refresh"],
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                    },
                    "credential": {
                        "id": credential_info.id if credential_info else None,
                        "name": credential_info.name if credential_info else None,
                        "last_used_at": (
                            credential_info.last_used_at.isoformat()
                            if credential_info and credential_info.last_used_at
                            else None
                        ),
                    },
                }
            )

        except CredentialNotFoundError as e:
            throttle.record_failure(request, PasskeySubject.AUTH_VERIFY)
            blockauth_logger.error("Passkey authentication failed", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except PasskeyError as e:
            throttle.record_failure(request, PasskeySubject.AUTH_VERIFY)
            blockauth_logger.error("Passkey authentication failed", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            throttle.record_failure(request, PasskeySubject.AUTH_VERIFY)
            blockauth_logger.error("Passkey authentication error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_400_BAD_REQUEST)


class PasskeyCredentialListView(PasskeyBaseView):
    """
    List user's passkey credentials.

    Requires authentication.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**passkey_credentials_list_docs)
    def get(self, request):
        throttle = PasskeyThrottles.CREDENTIALS
        if not throttle.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            credentials = service.get_credentials_for_user(request.user.id)

            return Response(
                {
                    "count": len(credentials),
                    "credentials": [
                        {
                            "id": c.id,
                            "credential_id": c.credential_id,
                            "name": c.name,
                            "created_at": c.created_at.isoformat() if c.created_at else None,
                            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
                            "authenticator_attachment": c.authenticator_attachment,
                            "transports": c.transports,
                            "backup_eligible": c.backup_eligible,
                            "backup_state": c.backup_state,
                            "is_active": c.is_active,
                        }
                        for c in credentials
                    ],
                }
            )

        except PasskeyError as e:
            blockauth_logger.error("Passkey credentials list error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            blockauth_logger.error("Passkey credentials list error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasskeyCredentialDetailView(PasskeyBaseView):
    """
    Manage individual passkey credential.

    Requires authentication. Supports GET, PATCH (update name), and DELETE.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**passkey_credential_detail_docs)
    def get(self, request, credential_id):
        throttle = PasskeyThrottles.CREDENTIALS
        if not throttle.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next((c for c in credentials if c.id == str(credential_id)), None)

            if not credential:
                raise CredentialNotFoundError()

            return Response(
                {
                    "id": credential.id,
                    "credential_id": credential.credential_id,
                    "name": credential.name,
                    "created_at": credential.created_at.isoformat() if credential.created_at else None,
                    "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
                    "authenticator_attachment": credential.authenticator_attachment,
                    "transports": credential.transports,
                    "backup_eligible": credential.backup_eligible,
                    "backup_state": credential.backup_state,
                    "is_active": credential.is_active,
                }
            )

        except CredentialNotFoundError as e:
            blockauth_logger.warning(
                "Passkey credential not found", sanitize_log_context({"credential_id": str(credential_id)})
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential detail error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(**passkey_credential_update_docs)
    def patch(self, request, credential_id):
        throttle = PasskeyThrottles.CREDENTIALS
        if not throttle.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()
            name = request.data.get("name")

            if not name:
                return Response(
                    {"error_code": "VALIDATION_ERROR", "message": "Name is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Verify ownership
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next((c for c in credentials if c.id == str(credential_id)), None)

            if not credential:
                raise CredentialNotFoundError()

            # Update name
            service.update_credential_name(credential.credential_id, name)

            # Get updated credential
            credentials = service.get_credentials_for_user(request.user.id)
            updated = next((c for c in credentials if c.id == str(credential_id)), None)

            blockauth_logger.info(
                "Passkey credential updated", {"user_id": str(request.user.id), "credential_id": str(credential_id)}
            )

            return Response(
                {
                    "id": updated.id,
                    "credential_id": updated.credential_id,
                    "name": updated.name,
                    "created_at": updated.created_at.isoformat() if updated.created_at else None,
                    "last_used_at": updated.last_used_at.isoformat() if updated.last_used_at else None,
                    "authenticator_attachment": updated.authenticator_attachment,
                    "transports": updated.transports,
                    "backup_eligible": updated.backup_eligible,
                    "backup_state": updated.backup_state,
                    "is_active": updated.is_active,
                }
            )

        except CredentialNotFoundError as e:
            blockauth_logger.warning(
                "Passkey credential not found for update", sanitize_log_context({"credential_id": str(credential_id)})
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential update error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(**passkey_credential_delete_docs)
    def delete(self, request, credential_id):
        throttle = PasskeyThrottles.CREDENTIALS
        if not throttle.allow_request(request, PasskeySubject.CREDENTIALS):
            return Response(
                {"error_code": "RATE_LIMIT", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            service = get_passkey_service()

            # Verify ownership
            credentials = service.get_credentials_for_user(request.user.id)
            credential = next((c for c in credentials if c.id == str(credential_id)), None)

            if not credential:
                raise CredentialNotFoundError()

            # Delete credential
            service.delete_credential(credential.credential_id)

            blockauth_logger.info(
                "Passkey credential deleted", {"user_id": str(request.user.id), "credential_id": str(credential_id)}
            )

            return Response(status=status.HTTP_204_NO_CONTENT)

        except CredentialNotFoundError as e:
            blockauth_logger.warning(
                "Passkey credential not found for delete", sanitize_log_context({"credential_id": str(credential_id)})
            )
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_404_NOT_FOUND)
        except PasskeyError as e:
            blockauth_logger.error("Passkey credential delete error", sanitize_log_context({"error": str(e)}))
            return Response(GENERIC_PASSKEY_ERROR, status=status.HTTP_400_BAD_REQUEST)
