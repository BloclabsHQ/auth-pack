import logging

from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.validators import EmailValidator

from blockauth.serializers.wallet_serializers import WalletLoginSerializer, WalletEmailAddSerializer
from blockauth.utils.custom_exception import ValidationErrorWithCode
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.models.otp import OTPSubject
from blockauth.notification import send_otp

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

    @extend_schema(
        summary='Wallet Login',
        description='Authenticate using an Ethereum wallet signature.',
        tags=['Wallet Auth'],
        request=WalletLoginSerializer,
        responses={
            200: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "access": {"type": "string", "description": "JWT access token"},
                        "refresh": {"type": "string", "description": "JWT refresh token"}
                    },
                    "example": {
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
                    }
                },
                description="Successful wallet login"
            ),
            400: OpenApiResponse(
                description="Validation error",
                examples=[
                    OpenApiExample(
                        "Invalid signature",
                        value={"detail": "Invalid signature. Signature verification failed."},
                        status_codes=[400],
                    )
                ]
            ),
            500: OpenApiResponse(
                description="Internal server error",
                examples=[
                    OpenApiExample(
                        "Internal error",
                        value={"detail": "Internal server error"},
                        status_codes=[500],
                    )
                ]
            ),
        },
        examples=[
            OpenApiExample(
                "Wallet Login Example",
                value={
                    "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                    "message": "ABC",
                    "signature": "0x1234567890abcdef1234567890abcdef1234567890abcd..."
                },
                request_only=True,
            )
        ]
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Wallet login attempt", sanitize_log_context(request.data))
        
        try:
            # Validate input data
            serializer.is_valid(raise_exception=True)
            
            # Perform authentication (all business logic is in the serializer)
            auth_result = serializer.authenticate_user()
            
            # Log success
            if auth_result['created']:
                blockauth_logger.success(
                    "Wallet login: new user created", 
                    sanitize_log_context(request.data, {"user": auth_result['user'].id})
                )
            else:
                blockauth_logger.success(
                    "Wallet login successful", 
                    sanitize_log_context(request.data, {"user": auth_result['user'].id})
                )
            
            # Return response
            return Response(
                data={
                    "access": auth_result['access_token'], 
                    "refresh": auth_result['refresh_token']
                }, 
                status=status.HTTP_200_OK
            )
            
        except ValidationError as e:
            blockauth_logger.warning(
                "Wallet login validation failed", 
                sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error(
                "Wallet login failed", 
                sanitize_log_context(request.data, {"error": str(e)})
            )
            logger.error(f"Wallet login request failed: {e}", exc_info=True)
            raise APIException()


class WalletEmailAddView(APIView):
    """
    API endpoint for wallet users to add an email address and automatically send verification.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = WalletEmailAddSerializer

    @extend_schema(
        summary='Add Email for Wallet User',
        description='Add an email address to a wallet-authenticated user and automatically send verification.',
        tags=['Wallet Auth'],
        request=WalletEmailAddSerializer,
        responses={
            200: OpenApiResponse(
                description="Email added and verification sent successfully",
                examples=[
                    OpenApiExample(
                        "Success",
                        value={"message": "Email added successfully. Verification sent via email."},
                        status_codes=[200],
                    )
                ]
            ),
            400: OpenApiResponse(
                description="Validation error",
                examples=[
                    OpenApiExample(
                        "Email already in use",
                        value={"detail": "This email is already in use by another account."},
                        status_codes=[400],
                    )
                ]
            ),
        },
        examples=[
            OpenApiExample(
                "Add Email with OTP",
                value={
                    "email": "user@example.com",
                    "verification_type": "otp"
                },
                request_only=True,
            ),
            OpenApiExample(
                "Add Email with Link",
                value={
                    "email": "user@example.com",
                    "verification_type": "link"
                },
                request_only=True,
            )
        ]
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        blockauth_logger.info("Wallet email add attempt", sanitize_log_context(request.data))
        
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            
            # Check WALLET_EMAIL_REQUIRED setting for wallet users
            if get_config('WALLET_EMAIL_REQUIRED'):
                if not request.user.is_verified:
                    raise ValidationError(
                        detail={"non_field_error": "Email verification required. Please verify your email address first."}, 
                        code=4006
                    )
            
            # Update user's email
            user = request.user
            user.email = data['email']
            user.is_verified = False  # Reset verification status
            user.save()
            
            # Automatically send verification
            otp_data = {
                'identifier': data['email'],
                'method': 'email',
                'verification_type': data['verification_type']
            }
            send_otp(otp_data, OTPSubject.WALLET_EMAIL_VERIFICATION)
            
            blockauth_logger.success(
                "Wallet email added and verification sent", 
                sanitize_log_context(request.data, {"user": user.id})
            )
            
            return Response(
                {'message': f'Email added successfully. {data["verification_type"]} sent via email.'}, 
                status=status.HTTP_200_OK
            )
            
        except ValidationError as e:
            blockauth_logger.warning(
                "Wallet email add validation failed", 
                sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error(
                "Wallet email add failed", 
                sanitize_log_context(request.data, {"error": str(e)})
            )
            logger.error(f"Wallet email add request failed: {e}", exc_info=True)
            raise APIException() 