"""
TOTP 2FA API Views

DRF views for TOTP 2FA operations.

Security: All endpoints implement rate limiting per SECURITY_STANDARDS.md
- Django @ratelimit decorators for primary rate limiting
- EnhancedThrottle for additional controls (daily limits, failure tracking, cooldowns)
"""
import logging
from typing import Any, Optional

from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema

from blockauth.utils.rate_limiter import EnhancedThrottle, get_client_ip

# Import documentation from separate docs module
from .docs import (
    totp_setup_docs,
    totp_confirm_docs,
    totp_verify_docs,
    totp_status_docs,
    totp_disable_docs,
    totp_regenerate_backup_codes_docs,
)

from .config import get_totp_config
from .constants import TOTPStatus
from .exceptions import (
    TOTPAccountLockedError,
    TOTPAlreadyEnabledError,
    TOTPCodeReusedError,
    TOTPError,
    TOTPInvalidBackupCodeError,
    TOTPInvalidCodeError,
    TOTPNotEnabledError,
    TOTPTooManyAttemptsError,
    TOTPVerificationError,
)
from .serializers import (
    BackupCodesResponseSerializer,
    TOTPConfirmRequestSerializer,
    TOTPDisableRequestSerializer,
    TOTPErrorSerializer,
    TOTPSetupRequestSerializer,
    TOTPSetupResponseSerializer,
    TOTPStatusResponseSerializer,
    TOTPVerifyRequestSerializer,
    TOTPVerifyResponseSerializer,
)
from .services import TOTPService
from .storage import DjangoTOTP2FAStore

logger = logging.getLogger(__name__)


# =============================================================================
# TOTP Rate Limiting Configuration (per SECURITY_STANDARDS.md)
# =============================================================================

class TOTPSubject:
    """Rate limiting subjects for TOTP operations."""
    SETUP = "totp_setup"
    CONFIRM = "totp_confirm"
    VERIFY = "totp_verify"
    DISABLE = "totp_disable"
    REGENERATE_BACKUP = "totp_regenerate_backup"
    STATUS = "totp_status"


class TOTPThrottles:
    """
    Centralized TOTP throttle configurations.

    Security Standards Compliance:
    - Setup: 3/hour (sensitive operation, creates secrets)
    - Confirm: 5/minute (verification during setup)
    - Verify: 5/minute (login verification - critical security)
    - Disable: 3/hour (sensitive security operation)
    - Regenerate backup: 3/hour (sensitive operation)
    - Status: 30/minute (read-only, less restrictive)
    """
    # Setup: 3/hour, max 5 failures triggers 30-min cooldown
    SETUP = EnhancedThrottle(rate=(3, 3600), daily_limit=10, max_failures=5, cooldown_minutes=30)
    # Confirm: 5/minute during setup flow
    CONFIRM = EnhancedThrottle(rate=(5, 60), max_failures=5, cooldown_minutes=15)
    # Verify: 5/minute - CRITICAL for login security
    VERIFY = EnhancedThrottle(rate=(5, 60), max_failures=5, cooldown_minutes=15)
    # Disable: 3/hour (sensitive operation)
    DISABLE = EnhancedThrottle(rate=(3, 3600), max_failures=3, cooldown_minutes=30)
    # Regenerate backup codes: 3/hour
    REGENERATE_BACKUP = EnhancedThrottle(rate=(3, 3600), daily_limit=5, max_failures=3, cooldown_minutes=30)
    # Status: 30/minute (read-only)
    STATUS = EnhancedThrottle(rate=(30, 60))


def get_totp_service(encryption_service: Optional[Any] = None) -> TOTPService:
    """
    Get configured TOTP service instance.

    The encryption service is automatically loaded from Django settings
    (TOTP_ENCRYPTION_KEY) if not provided explicitly.

    Args:
        encryption_service: Optional encryption service implementing ISecretEncryption.
                           If None, uses the configured encryption from settings.

    Returns:
        Configured TOTPService instance

    Note:
        TOTP_ENCRYPTION_KEY must be configured in BLOCK_AUTH_SETTINGS for
        TOTP to work. Without encryption, secrets cannot be stored securely.
    """
    from .services.encryption import get_encryption_service

    store = DjangoTOTP2FAStore()
    config = get_totp_config()

    # Use provided encryption service or load from settings
    if encryption_service is None:
        encryption_service = get_encryption_service()

    return TOTPService(store=store, config=config, encryption_service=encryption_service)


@method_decorator(ratelimit(key='user', rate='3/h', method='POST', block=True), name='post')
class TOTPSetupView(APIView):
    """
    Set up TOTP 2FA for the current user.

    POST /auth/totp/setup/

    Initiates TOTP setup and returns:
    - Secret for manual entry
    - Provisioning URI for QR code
    - Backup codes for recovery

    User must confirm setup with a valid TOTP code.

    Rate Limit: 3/hour (sensitive operation - per SECURITY_STANDARDS.md mfa_setup)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_setup_docs)
    def post(self, request: Request) -> Response:
        """Handle TOTP setup request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance)
        throttle = TOTPThrottles.SETUP
        if not throttle.allow_request(request, TOTPSubject.SETUP):
            logger.warning(
                "TOTP setup rate limit exceeded for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many setup attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = TOTPSetupRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            service = get_totp_service()

            # Use email as account name, or username as fallback
            account_name = getattr(request.user, 'email', None) or str(request.user)

            result = service.setup_totp(
                user_id=str(request.user.id),
                account_name=account_name,
                issuer=serializer.validated_data.get('issuer')
            )

            response_serializer = TOTPSetupResponseSerializer(data={
                'secret': result.secret,
                'provisioning_uri': result.provisioning_uri,
                'backup_codes': result.backup_codes,
            })
            response_serializer.is_valid(raise_exception=True)

            # Record success
            throttle.record_success(request, TOTPSubject.SETUP)

            logger.info(
                "TOTP setup initiated for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )

            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except TOTPAlreadyEnabledError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_409_CONFLICT
            )
        except TOTPError as e:
            throttle.record_failure(request, TOTPSubject.SETUP)
            logger.error("TOTP setup error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='user', rate='5/m', method='POST', block=True), name='post')
class TOTPConfirmView(APIView):
    """
    Confirm TOTP setup with a valid code.

    POST /auth/totp/confirm/

    Body: { "code": "123456" }

    Verifies the code and enables TOTP if valid.

    Rate Limit: 5/minute (verification attempts - per SECURITY_STANDARDS.md)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_confirm_docs)
    def post(self, request: Request) -> Response:
        """Handle TOTP confirmation request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance)
        throttle = TOTPThrottles.CONFIRM
        if not throttle.allow_request(request, TOTPSubject.CONFIRM):
            logger.warning(
                "TOTP confirm rate limit exceeded for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many confirmation attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = TOTPConfirmRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            service = get_totp_service()

            service.confirm_setup(
                user_id=str(request.user.id),
                code=serializer.validated_data['code']
            )

            # Record success
            throttle.record_success(request, TOTPSubject.CONFIRM)

            logger.info(
                "TOTP enabled for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )

            return Response({'message': 'TOTP 2FA enabled successfully'})

        except TOTPNotEnabledError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_404_NOT_FOUND
            )
        except TOTPInvalidCodeError as e:
            throttle.record_failure(request, TOTPSubject.CONFIRM)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )
        except TOTPError as e:
            throttle.record_failure(request, TOTPSubject.CONFIRM)
            logger.error("TOTP confirm error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='user', rate='5/m', method='POST', block=True), name='post')
class TOTPVerifyView(APIView):
    """
    Verify a TOTP code or backup code.

    POST /auth/totp/verify/

    Body: { "code": "123456" }

    Used during login to complete 2FA verification.
    Accepts both 6-digit TOTP codes and backup codes.

    Rate Limit: 5/minute (CRITICAL - login security - per SECURITY_STANDARDS.md)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_verify_docs)
    def post(self, request: Request) -> Response:
        """Handle TOTP verification request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance - CRITICAL)
        throttle = TOTPThrottles.VERIFY
        if not throttle.allow_request(request, TOTPSubject.VERIFY):
            logger.warning(
                "TOTP verify rate limit exceeded for user %s from IP %s",
                request.user.id,
                get_client_ip(request),
                extra={'user_id': str(request.user.id), 'ip': get_client_ip(request)}
            )
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many verification attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = TOTPVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            service = get_totp_service()

            result = service.verify(
                user_id=str(request.user.id),
                code=serializer.validated_data['code'],
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            response_serializer = TOTPVerifyResponseSerializer(data={
                'success': result.success,
                'verification_type': result.verification_type,
                'backup_codes_remaining': result.backup_codes_remaining,
            })
            response_serializer.is_valid(raise_exception=True)

            # Record success
            throttle.record_success(request, TOTPSubject.VERIFY)

            return Response(response_serializer.data)

        except TOTPAccountLockedError as e:
            throttle.record_failure(request, TOTPSubject.VERIFY)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_423_LOCKED
            )
        except TOTPTooManyAttemptsError as e:
            throttle.record_failure(request, TOTPSubject.VERIFY)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except (TOTPCodeReusedError, TOTPVerificationError, TOTPInvalidCodeError,
                TOTPInvalidBackupCodeError) as e:
            throttle.record_failure(request, TOTPSubject.VERIFY)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_401_UNAUTHORIZED
            )
        except TOTPNotEnabledError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_404_NOT_FOUND
            )
        except TOTPError as e:
            throttle.record_failure(request, TOTPSubject.VERIFY)
            logger.error("TOTP verify error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='user', rate='30/m', method='GET', block=True), name='get')
class TOTPStatusView(APIView):
    """
    Get TOTP status for the current user.

    GET /auth/totp/status/

    Returns current TOTP status, including:
    - Whether TOTP is enabled
    - Status (disabled, pending_confirmation, enabled)
    - Number of backup codes remaining

    Rate Limit: 30/minute (read-only - per SECURITY_STANDARDS.md api_read)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_status_docs)
    def get(self, request: Request) -> Response:
        """Handle TOTP status request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance)
        throttle = TOTPThrottles.STATUS
        if not throttle.allow_request(request, TOTPSubject.STATUS):
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        service = get_totp_service()
        store = DjangoTOTP2FAStore()

        totp_data = store.get_by_user_id(str(request.user.id))

        if totp_data is None:
            return Response(TOTPStatusResponseSerializer({
                'enabled': False,
                'status': TOTPStatus.DISABLED.value,
                'backup_codes_remaining': 0,
                'enabled_at': None,
            }).data)

        return Response(TOTPStatusResponseSerializer({
            'enabled': totp_data.status == TOTPStatus.ENABLED.value,
            'status': totp_data.status,
            'backup_codes_remaining': totp_data.backup_codes_remaining,
            'enabled_at': totp_data.enabled_at,
        }).data)


@method_decorator(ratelimit(key='user', rate='3/h', method='POST', block=True), name='post')
class TOTPDisableView(APIView):
    """
    Disable TOTP 2FA for the current user.

    POST /auth/totp/disable/

    Body: { "code": "123456" } or { "password": "user-password" }

    Requires verification before disabling for security.

    Rate Limit: 3/hour (sensitive security operation - per SECURITY_STANDARDS.md)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_disable_docs)
    def post(self, request: Request) -> Response:
        """Handle TOTP disable request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance)
        throttle = TOTPThrottles.DISABLE
        if not throttle.allow_request(request, TOTPSubject.DISABLE):
            logger.warning(
                "TOTP disable rate limit exceeded for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many disable attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = TOTPDisableRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = get_totp_service()

        # Verify user identity before disabling
        code = serializer.validated_data.get('code')
        password = serializer.validated_data.get('password')

        if code:
            try:
                # Verify TOTP code
                service.verify(
                    user_id=str(request.user.id),
                    code=code,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            except TOTPError as e:
                throttle.record_failure(request, TOTPSubject.DISABLE)
                return Response(
                    TOTPErrorSerializer(e.to_dict()).data,
                    status=status.HTTP_401_UNAUTHORIZED
                )
        elif password:
            # Verify password
            if not request.user.check_password(password):
                throttle.record_failure(request, TOTPSubject.DISABLE)
                return Response(
                    {'error': 'invalid_password', 'message': 'Invalid password'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Disable TOTP
        service.disable(str(request.user.id))

        # Record success
        throttle.record_success(request, TOTPSubject.DISABLE)

        logger.info(
            "TOTP disabled for user %s",
            request.user.id,
            extra={'user_id': str(request.user.id)}
        )

        return Response({'message': 'TOTP 2FA disabled successfully'})


@method_decorator(ratelimit(key='user', rate='3/h', method='POST', block=True), name='post')
class TOTPRegenerateBackupCodesView(APIView):
    """
    Regenerate backup codes.

    POST /auth/totp/backup-codes/regenerate/

    Body: { "code": "123456" }

    Requires TOTP verification before regenerating codes.
    Old backup codes are invalidated.

    Rate Limit: 3/hour (sensitive operation - per SECURITY_STANDARDS.md mfa_setup)
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(**totp_regenerate_backup_codes_docs)
    def post(self, request: Request) -> Response:
        """Handle TOTP backup codes regeneration request."""
        # Rate limiting check (SECURITY_STANDARDS.md compliance)
        throttle = TOTPThrottles.REGENERATE_BACKUP
        if not throttle.allow_request(request, TOTPSubject.REGENERATE_BACKUP):
            logger.warning(
                "TOTP backup codes regenerate rate limit exceeded for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )
            return Response(
                {"error": "rate_limit_exceeded", "message": "Too many regeneration attempts. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = TOTPVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = get_totp_service()

        try:
            # Verify TOTP code first
            service.verify(
                user_id=str(request.user.id),
                code=serializer.validated_data['code'],
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Regenerate backup codes
            backup_codes = service.regenerate_backup_codes(str(request.user.id))

            response_serializer = BackupCodesResponseSerializer(data={
                'backup_codes': backup_codes,
                'count': len(backup_codes),
            })
            response_serializer.is_valid(raise_exception=True)

            # Record success
            throttle.record_success(request, TOTPSubject.REGENERATE_BACKUP)

            logger.info(
                "Backup codes regenerated for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )

            return Response(response_serializer.data)

        except TOTPError as e:
            throttle.record_failure(request, TOTPSubject.REGENERATE_BACKUP)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )
