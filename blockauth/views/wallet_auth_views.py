import logging

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.wallet_auth_docs import wallet_email_add_docs, wallet_login_docs
from blockauth.models.otp import OTPSubject
from blockauth.notification import send_otp
from blockauth.enums import AuthenticationType
from blockauth.serializers.wallet_serializers import WalletEmailAddSerializer, WalletLinkSerializer, WalletLoginSerializer
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.custom_exception import ValidationErrorWithCode, WalletConflictError
from blockauth.utils.generics import model_to_json, sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.rate_limiter import EnhancedThrottle

logger = logging.getLogger(__name__)
_User = get_block_auth_user_model()


class WalletAuthLoginView(APIView):
    """
    API endpoint for Ethereum wallet login.
    Accepts wallet address, message, and signature, and returns access/refresh tokens.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    serializer_class = WalletLoginSerializer
    login_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    @extend_schema(**wallet_login_docs)
    def post(self, request):
        if not self.login_throttle.allow_request(request, "wallet_login"):
            reason = self.login_throttle.get_block_reason()
            msg = (
                "Too many failed login attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Wallet login attempt", sanitize_log_context(request.data))

        try:
            # Validate input data
            serializer.is_valid(raise_exception=True)

            # Perform authentication (all business logic is in the serializer)
            auth_result = serializer.authenticate_user()

            # Log success
            if auth_result["created"]:
                blockauth_logger.success(
                    "Wallet login: new user created",
                    sanitize_log_context(request.data, {"user": auth_result["user"].id}),
                )
            else:
                blockauth_logger.success(
                    "Wallet login successful", sanitize_log_context(request.data, {"user": auth_result["user"].id})
                )

            self.login_throttle.record_success(request, "wallet_login")

            # Return response
            return Response(
                data={"access": auth_result["access_token"], "refresh": auth_result["refresh_token"]},
                status=status.HTTP_200_OK,
            )

        except ValidationError as e:
            self.login_throttle.record_failure(request, "wallet_login")
            blockauth_logger.warning(
                "Wallet login validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            self.login_throttle.record_failure(request, "wallet_login")
            blockauth_logger.error("Wallet login failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet login request failed: {e}", exc_info=True)
            raise APIException()


class WalletEmailAddView(APIView):
    """
    API endpoint for wallet users to add an email address and automatically send verification.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = WalletEmailAddSerializer

    @extend_schema(**wallet_email_add_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        blockauth_logger.info("Wallet email add attempt", sanitize_log_context(request.data))

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Update user's email
            user = request.user
            user.email = data["email"]
            user.is_verified = False  # Reset verification status
            user.save()

            # Automatically send verification
            otp_data = {"identifier": data["email"], "method": "email", "verification_type": data["verification_type"]}
            send_otp(otp_data, OTPSubject.WALLET_EMAIL_VERIFICATION)

            blockauth_logger.success(
                "Wallet email added and verification sent", sanitize_log_context(request.data, {"user": user.id})
            )

            return Response(
                {"message": f'Email added successfully. {data["verification_type"]} sent via email.'},
                status=status.HTTP_200_OK,
            )

        except ValidationError as e:
            blockauth_logger.warning(
                "Wallet email add validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Wallet email add failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet email add request failed: {e}", exc_info=True)
            raise APIException()


class WalletLinkView(APIView):
    """
    API endpoint for authenticated users to link a MetaMask (or compatible) wallet.

    The user must already hold a valid JWT. They sign a structured JSON message
    with their wallet and submit address + message + signature. Full replay
    protection (nonce + timestamp) is enforced by WalletAuthenticator.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = WalletLinkSerializer
    link_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    def post(self, request):
        if not self.link_throttle.allow_request(request, "wallet_link"):
            reason = self.link_throttle.get_block_reason()
            msg = (
                "Too many failed attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data, context={"request": request})
        blockauth_logger.info("Wallet link attempt", sanitize_log_context(request.data))

        try:
            serializer.is_valid(raise_exception=True)

            user = request.user
            wallet_address = serializer.validated_data["wallet_address"]

            user.wallet_address = wallet_address
            user.add_authentication_type(AuthenticationType.WALLET)
            user.save()

            user_data = model_to_json(user, remove_fields=("password",))
            post_wallet_link_trigger = get_config("POST_WALLET_LINK_TRIGGER")()
            post_wallet_link_trigger.trigger(context={"user": user_data, "wallet_address": wallet_address})

            self.link_throttle.record_success(request, "wallet_link")
            blockauth_logger.success(
                "Wallet linked successfully",
                sanitize_log_context(request.data, {"user": user.id}),
            )

            return Response(
                data={"message": "Wallet linked successfully.", "wallet_address": wallet_address},
                status=status.HTTP_200_OK,
            )

        except WalletConflictError:
            self.link_throttle.record_failure(request, "wallet_link")
            raise

        except ValidationError as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.warning(
                "Wallet link validation failed",
                sanitize_log_context(request.data, {"errors": e.detail}),
            )
            raise ValidationErrorWithCode(detail=e.detail)

        except Exception as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.error("Wallet link failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet link request failed: {e}", exc_info=True)
            raise APIException()
