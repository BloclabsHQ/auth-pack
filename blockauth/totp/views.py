"""
TOTP 2FA API Views

DRF views for TOTP 2FA operations.
"""
import logging
from typing import Optional

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

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


def get_client_ip(request) -> Optional[str]:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def get_totp_service(encryption_service=None) -> TOTPService:
    """Get configured TOTP service instance."""
    store = DjangoTOTP2FAStore()
    config = get_totp_config()
    return TOTPService(store=store, config=config, encryption_service=encryption_service)


class TOTPSetupView(APIView):
    """
    Set up TOTP 2FA for the current user.

    POST /auth/totp/setup/

    Initiates TOTP setup and returns:
    - Secret for manual entry
    - Provisioning URI for QR code
    - Backup codes for recovery

    User must confirm setup with a valid TOTP code.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
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
            logger.error("TOTP setup error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


class TOTPConfirmView(APIView):
    """
    Confirm TOTP setup with a valid code.

    POST /auth/totp/confirm/

    Body: { "code": "123456" }

    Verifies the code and enables TOTP if valid.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TOTPConfirmRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            service = get_totp_service()

            service.confirm_setup(
                user_id=str(request.user.id),
                code=serializer.validated_data['code']
            )

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
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )
        except TOTPError as e:
            logger.error("TOTP confirm error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


class TOTPVerifyView(APIView):
    """
    Verify a TOTP code or backup code.

    POST /auth/totp/verify/

    Body: { "code": "123456" }

    Used during login to complete 2FA verification.
    Accepts both 6-digit TOTP codes and backup codes.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
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

            return Response(response_serializer.data)

        except TOTPAccountLockedError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_423_LOCKED
            )
        except TOTPTooManyAttemptsError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except (TOTPCodeReusedError, TOTPVerificationError, TOTPInvalidCodeError,
                TOTPInvalidBackupCodeError) as e:
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
            logger.error("TOTP verify error: %s", e)
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )


class TOTPStatusView(APIView):
    """
    Get TOTP status for the current user.

    GET /auth/totp/status/

    Returns current TOTP status, including:
    - Whether TOTP is enabled
    - Status (disabled, pending_confirmation, enabled)
    - Number of backup codes remaining
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
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


class TOTPDisableView(APIView):
    """
    Disable TOTP 2FA for the current user.

    POST /auth/totp/disable/

    Body: { "code": "123456" } or { "password": "user-password" }

    Requires verification before disabling for security.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
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
                return Response(
                    TOTPErrorSerializer(e.to_dict()).data,
                    status=status.HTTP_401_UNAUTHORIZED
                )
        elif password:
            # Verify password
            if not request.user.check_password(password):
                return Response(
                    {'error': 'invalid_password', 'message': 'Invalid password'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # Disable TOTP
        service.disable(str(request.user.id))

        logger.info(
            "TOTP disabled for user %s",
            request.user.id,
            extra={'user_id': str(request.user.id)}
        )

        return Response({'message': 'TOTP 2FA disabled successfully'})


class TOTPRegenerateBackupCodesView(APIView):
    """
    Regenerate backup codes.

    POST /auth/totp/backup-codes/regenerate/

    Body: { "code": "123456" }

    Requires TOTP verification before regenerating codes.
    Old backup codes are invalidated.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
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

            logger.info(
                "Backup codes regenerated for user %s",
                request.user.id,
                extra={'user_id': str(request.user.id)}
            )

            return Response(response_serializer.data)

        except TOTPError as e:
            return Response(
                TOTPErrorSerializer(e.to_dict()).data,
                status=status.HTTP_400_BAD_REQUEST
            )
