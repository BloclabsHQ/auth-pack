import logging
from django.utils import timezone
from blockauth.utils.docs import extend_schema
try:
    from blockauth.docs.auth_docs import (
        signup_docs,
        signup_resend_otp_docs,
        signup_confirm_docs,
        basic_login_docs,
        passwordless_login_docs,
        passwordless_confirm_docs,
        refresh_token_docs,
        password_reset_docs,
        password_reset_confirm_docs,
        password_change_docs,
        email_change_docs,
        email_change_confirm_docs
    )
except Exception:  # docs extra not installed
    signup_docs = {}
    signup_resend_otp_docs = {}
    signup_confirm_docs = {}
    basic_login_docs = {}
    passwordless_login_docs = {}
    passwordless_confirm_docs = {}
    refresh_token_docs = {}
    password_reset_docs = {}
    password_reset_confirm_docs = {}
    password_change_docs = {}
    email_change_docs = {}
    email_change_confirm_docs = {}
from rest_framework import status
from rest_framework.exceptions import APIException, AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.models.otp import OTP, OTPSubject
from blockauth.models.user import AuthenticationType
from blockauth.notification import send_otp, NotificationEvent

from blockauth.serializers.user_account_serializers import PasswordChangeSerializer, \
    EmailChangeConfirmationSerializer, \
    PasswordResetConfirmationEmailSerializer, EmailChangeRequestSerializer, \
    SignUpRequestSerializer, SignUpResendOTPSerializer, RefreshTokenSerializer, \
    PasswordlessLoginSerializer, BasicLoginSerializer, PasswordlessLoginConfirmationSerializer, \
    SignUpConfirmationSerializer, PasswordResetRequestSerializer
from blockauth.utils.config import get_config, get_block_auth_user_model
from blockauth.utils.custom_exception import ValidationErrorWithCode
from blockauth.utils.generics import model_to_json, sanitize_log_context
from blockauth.utils.rate_limiter import RequestThrottle
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS
from blockauth.utils.logger import blockauth_logger

logger = logging.getLogger(__name__)
_User = get_block_auth_user_model()


class SignUpView(APIView):
    """
    Sign up with identifier (email/phone number) and password. Internally it will send an otp to the user's contact.
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpRequestSerializer
    authentication_classes = []

    @extend_schema(**signup_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("User signup attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            pre_signup_trigger = get_config('PRE_SIGNUP_TRIGGER')()
            pre_signup_trigger.trigger(context=data)

            if data.get('email'):
                user = _User.objects.create(email=data['email'])
            else:
                user = _User.objects.create(phone_number=data['phone_number'])
            user.set_password(data['password'])
            user.add_authentication_type(AuthenticationType.EMAIL)
            user.save()

            send_otp(data=data, subject=OTPSubject.SIGNUP)
            blockauth_logger.success(f"User signup {data['verification_type']} sent", sanitize_log_context(request.data, {"user": user.id}))
            return Response({'message': f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("User signup validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("User signup failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpResendOTPView(APIView):
    """
    Send OTP/verification link for signup or wallet email verification
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpResendOTPSerializer
    rate_limit_handler = RequestThrottle()
    authentication_classes = []

    @extend_schema(**signup_resend_otp_docs)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.SIGNUP):
            wait_time = int(self.rate_limit_handler.wait())
            blockauth_logger.warning("Signup OTP resend rate limit hit", sanitize_log_context(request.data, {"wait_time": wait_time}))
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            
            # Determine if this is a wallet email verification or regular signup
            # by checking if a user with the given email exists and has a wallet address
            identifier = data.get('identifier')
            user = _User.objects.filter(email=identifier).first()
            is_wallet_verification = user and user.wallet_address
            
            if is_wallet_verification:
                # Check rate limit for wallet email verification
                if not self.rate_limit_handler.allow_request(request, OTPSubject.WALLET_EMAIL_VERIFICATION):
                    wait_time = int(self.rate_limit_handler.wait())
                    blockauth_logger.warning(
                        "Wallet email OTP resend rate limit hit", 
                        sanitize_log_context(request.data, {"wait_time": wait_time})
                    )
                    return Response(
                        data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                        status=status.HTTP_429_TOO_MANY_REQUESTS
                    )
                
                # Send verification for wallet email verification
                send_otp(data, OTPSubject.WALLET_EMAIL_VERIFICATION)
                blockauth_logger.success(f"Wallet email verification {data['verification_type']} sent", sanitize_log_context(request.data))
            else:
                # Send verification for regular signup
                send_otp(data, OTPSubject.SIGNUP)
                blockauth_logger.success(f"Signup {data['verification_type']} sent", sanitize_log_context(request.data))
                
            return Response({'message': f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Verification send validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Verification send failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpConfirmView(APIView):
    """
    Verify OTP to confirm signup or wallet email verification
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpConfirmationSerializer
    authentication_classes = []

    @extend_schema(**signup_confirm_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        blockauth_logger.info("Verification confirmation attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            
            # Determine if this is a wallet email verification or regular signup
            # by checking which OTP subject exists in the database
            identifier = data["identifier"]
            code = data["code"]
            
            # Check if wallet email verification OTP exists
            wallet_otp_exists = OTP.objects.filter(
                identifier=identifier,
                code=code,
                subject=OTPSubject.WALLET_EMAIL_VERIFICATION,
                is_used=False
            ).exists()
            
            # Check if signup OTP exists
            signup_otp_exists = OTP.objects.filter(
                identifier=identifier,
                code=code,
                subject=OTPSubject.SIGNUP,
                is_used=False
            ).exists()
            
            if wallet_otp_exists:
                # Wallet email verification
                OTP.validate_otp(
                    identifier=identifier, 
                    code=code, 
                    subject=OTPSubject.WALLET_EMAIL_VERIFICATION
                )
                
                # Find the user by email and update verification status
                user = _User.objects.get(email=identifier)
                user.is_verified = True
                user.save()
                
                blockauth_logger.success(
                    "Wallet email verified", 
                    sanitize_log_context(request.data, {"user": user.id})
                )
                return Response(
                    {'message': 'Email verified successfully.'}, 
                    status=status.HTTP_200_OK
                )
            elif signup_otp_exists:
                # Regular signup confirmation
                OTP.validate_otp(
                    identifier=identifier, 
                    code=code, 
                    subject=OTPSubject.SIGNUP
                )

                email, phone_number = data.get('email'), data.get('phone_number')
                if email:
                    user = _User.objects.get(email=email)
                else:
                    user = _User.objects.get(phone_number=phone_number)
                user.is_verified = True
                user.save()

                user_data = model_to_json(user, remove_fields=('password',))

                post_signup_trigger = get_config('POST_SIGNUP_TRIGGER')()
                post_signup_trigger.trigger(context=user_data)
                blockauth_logger.success("User signup confirmed", sanitize_log_context(request.data, {"user": user.id}))
                return Response(data={'message': 'Sign up success'}, status=status.HTTP_200_OK)
            else:
                # No valid OTP found for either subject
                raise ValidationError(detail={"code": "invalid otp"}, code=4010)
                
        except ValidationError as e:
            blockauth_logger.warning("Verification confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Verification confirmation failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class BasicAuthLoginView(APIView):
    """
    Login via identifier(email/phone number) & password and get access token & refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = BasicLoginSerializer
    authentication_classes = []

    @extend_schema(**basic_login_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Basic login attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            user = data['user']
            user.last_login = timezone.now()
            user.add_authentication_type('EMAIL')
            user.save()

            user_data = model_to_json(user, remove_fields=('password',))

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context=user_data)
            blockauth_logger.success("Basic login successful", sanitize_log_context(request.data, {"user": user.id}))

            access_token, refresh_token = generate_auth_token(
                token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
            )
            return Response(
                {"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK
            )
        except AuthenticationFailed as e:
            blockauth_logger.warning("Basic login authentication failed", sanitize_log_context(request.data, {"errors": str(e)}))
            raise ValidationErrorWithCode(detail={'non_field_error': str(e)}, code=4003)
        except ValidationError as e:
            blockauth_logger.warning("Basic login validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Basic login failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginSerializer
    authentication_classes = []

    @extend_schema(**passwordless_login_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Passwordless login attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data=data, subject=OTPSubject.PASSWORDLESS_LOGIN)
            blockauth_logger.success(f"Passwordless login {data['verification_type']} sent", sanitize_log_context(request.data))
            return Response({"message": f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Passwordless login validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Passwordless login failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginConfirmView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginConfirmationSerializer
    authentication_classes = []

    @extend_schema(**passwordless_confirm_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Passwordless login confirmation attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            OTP.validate_otp(
                identifier=data['identifier'], code=data['code'], subject=OTPSubject.PASSWORDLESS_LOGIN
            )
            blockauth_logger.success("Passwordless login confirmed", sanitize_log_context(request.data))
            user = _User.objects.filter(
                email=data['email'] if data.get('email') else None,
                phone_number=data['phone_number'] if data.get('phone_number') else None
            ).first()
            if not user:
                if data.get('email'):
                    user = _User.objects.create(email=data['email'])
                else:
                    user = _User.objects.create(phone_number=data['phone_number'])
                user.add_authentication_type(AuthenticationType.EMAIL)
                user.save()

            user.last_login = timezone.now()
            user.save()
            user_data = model_to_json(user, remove_fields=('password',))

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context=user_data)
            blockauth_logger.success("Passwordless login successful", sanitize_log_context(request.data, {"user": user.id}))

            access_token, refresh_token = generate_auth_token(
                token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
            )
            return Response(
                {"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK
            )
        except ValidationError as e:
            blockauth_logger.warning("Passwordless login confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Passwordless login confirmation failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class AuthRefreshTokenView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenSerializer
    authentication_classes = []

    @extend_schema(**refresh_token_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Token refresh attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            token_class = AUTH_TOKEN_CLASS()
            access_token, refresh_token = generate_auth_token(
                token_class=token_class, user_id=str(data.get('user_id'))
            )
            blockauth_logger.success("Token refresh successful", sanitize_log_context(request.data, {"user": data.get('user_id')}))
            return Response(
                {"access": access_token, "refresh": refresh_token},
                status=status.HTTP_200_OK
            )
        except ValidationError as e:
            blockauth_logger.warning("Token refresh validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Token refresh failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetRequestSerializer
    authentication_classes = []

    @extend_schema(**password_reset_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Password reset request", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data=data, subject=OTPSubject.PASSWORD_RESET)
            blockauth_logger.success(f"Password reset {data['verification_type']} sent", sanitize_log_context(request.data))
            return Response({"message": f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Password reset validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Password reset failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetConfirmView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetConfirmationEmailSerializer
    authentication_classes = []

    @extend_schema(**password_reset_confirm_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Password reset confirmation attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            OTP.validate_otp(
                identifier=data['identifier'], code=data['code'], subject=OTPSubject.PASSWORD_RESET
            )
            blockauth_logger.success("Password reset confirmed", sanitize_log_context(request.data))

            user = _User.objects.filter(
                email=data['email'] if data.get('email') else None,
                phone_number=data['phone_number'] if data.get('phone_number') else None
            ).first()
            if not user:
                raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4002)

            user.set_password(data['new_password'])
            user.save()

            # Optionally send notification here via DEFAULT_NOTIFICATION_CLASS if configured
            blockauth_logger.success("Password reset confirmed", sanitize_log_context(request.data, {"user": user.id}))
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Password reset confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Password reset confirmation failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer

    @extend_schema(**password_change_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        blockauth_logger.info("Password change attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            blockauth_logger.success("Password change successful", sanitize_log_context(request.data, {"user": user.id}))
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Password change validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Password change failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeRequestSerializer

    @extend_schema(**email_change_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        blockauth_logger.info("Email change request", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data=data, subject=OTPSubject.EMAIL_CHANGE)
            blockauth_logger.success(f"Email change {data['verification_type']} sent", sanitize_log_context(request.data, {"user": request.user.id}))
            return Response({"message": f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Email change request validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Email change request failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeConfirmView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeConfirmationSerializer

    @extend_schema(**email_change_confirm_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        blockauth_logger.info("Email change confirmation attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            OTP.validate_otp(
                identifier=data['identifier'], code=data['code'], subject=OTPSubject.EMAIL_CHANGE
            )
            user = request.user
            user.email = data['email']
            user.save()
            blockauth_logger.success("Email change confirmed", sanitize_log_context(request.data, {"user": user.id}))
            return Response({'message': 'Email changed successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning("Email change confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail}))
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Email change confirmation failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()