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
from blockauth.serializers.wallet_serializers import WalletEmailAddSerializer, WalletLoginSerializer
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.custom_exception import ValidationErrorWithCode
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger

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

    @extend_schema(**wallet_login_docs)
    def post(self, request):
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

            # Return response
            return Response(
                data={"access": auth_result["access_token"], "refresh": auth_result["refresh_token"]},
                status=status.HTTP_200_OK,
            )

        except ValidationError as e:
            blockauth_logger.warning(
                "Wallet login validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
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
