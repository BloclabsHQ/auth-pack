import logging

from django.contrib.auth import get_user_model
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import APIException, AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.models.otp import OTP, OTPSubject
from blockauth.notification import send_otp, NotificationEvent
from blockauth.schemas.account_settings import password_change_schema, email_change_schema, email_change_confirm_schema
from blockauth.schemas.login import basic_login_schema, passwordless_login_schema, passwordless_login_confirm_schema, \
    refresh_token_schema
from blockauth.schemas.password_reset import password_reset_schema, password_reset_confirm_schema
from blockauth.schemas.signup import signup_schema, signup_resend_otp_schema, signup_confirm_schema
from blockauth.serializers.user_account_serializers import PasswordChangeSerializer, \
    EmailChangeConfirmationSerializer, \
    PasswordResetConfirmationEmailSerializer, EmailChangeRequestSerializer, \
    SignUpRequestSerializer, SignUpResendOTPSerializer, RefreshTokenSerializer, \
    PasswordlessLoginSerializer, BasicLoginSerializer, PasswordlessLoginConfirmationSerializer, \
    SignUpConfirmationSerializer, PasswordResetRequestSerializer
from blockauth.utils.config import get_config
from blockauth.utils.custom_exception import ValidationErrorWithCode
from blockauth.utils.generics import model_to_json
from blockauth.utils.rate_limiter import RequestThrottle
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

logger = logging.getLogger(__name__)
_User = get_user_model()


class SignUpView(APIView):
    """
    Sign up with identifier (email/phone number) and password. Internally it will send an otp to the user's contact.
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpRequestSerializer

    @extend_schema(summary='Signup', tags=['Signup'], **signup_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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
            user.save()

            send_otp(data=data, subject=OTPSubject.SIGNUP)
            return Response({'message': f'{data['verification_type']} sent via {data['method']}.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpResendOTPView(APIView):
    """
    Resend otp for signup.
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpResendOTPSerializer
    rate_limit_handler = RequestThrottle()

    @extend_schema(summary='Resend OTP to Signup', tags=['Signup'], **signup_resend_otp_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.SIGNUP):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data, OTPSubject.SIGNUP)
            return Response({'message': f'{data['verification_type']} sent via {data['method']}.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpConfirmView(APIView):
    """
    Verify otp to signup
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpConfirmationSerializer

    @extend_schema(summary='Confirm Signup', tags=['Signup'], **signup_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            OTP.validate_otp(identifier=data["identifier"], code=data["code"], subject=OTPSubject.SIGNUP)

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
            return Response(data={'message': 'Sign up success'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class BasicAuthLoginView(APIView):
    """
    Login via identifier(email/phone number) & password and get access token & refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = BasicLoginSerializer

    @extend_schema(summary='Basic Login', tags=['Login'], **basic_login_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            user = data['user']
            user.last_login = timezone.now()
            user.save()

            user_data = model_to_json(user, remove_fields=('password',))

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context={'user': user_data})

            access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=user.id.hex)
            return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginView(APIView):
    """
    Send an otp/Login Link for passwordless login with email/phone number.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginSerializer
    rate_limit_handler = RequestThrottle()

    @extend_schema(summary='Passwordless Login', tags=['Login'], **passwordless_login_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.LOGIN):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data, OTPSubject.LOGIN)
            return Response({'message': f'{data['verification_type']} sent via {data['method']}.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginConfirmView(APIView):
    """
    Verify otp for login & get access token & refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginConfirmationSerializer

    @extend_schema(summary='Confirm Passwordless Login', tags=['Login'], **passwordless_login_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            OTP.validate_otp(identifier=data["identifier"], code=data["code"], subject=OTPSubject.LOGIN)

            email, phone_number = data.get('email'), data.get('phone_number')
            if email:
                user, created = _User.objects.get_or_create(email=email, defaults={'is_verified': True})
            else:
                user, created = _User.objects.get_or_create(phone_number=phone_number, defaults={'is_verified': True})
            user.last_login = timezone.now()
            user.is_verified = True
            user.save()

            user_data = model_to_json(user, remove_fields=('password',))

            if created:
                post_sign_up_trigger = get_config('POST_SIGNUP_TRIGGER')()
                post_sign_up_trigger.trigger(context={'user': user_data})

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context={'user': user_data})

            access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=user.id.hex)
            return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class AuthRefreshTokenView(APIView):
    """
    Get new access token using the refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenSerializer

    @extend_schema(summary='Regenerate Access Token', tags=['Login'], **refresh_token_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            raise ValidationErrorWithCode(detail=serializer.errors)

        refresh_token = serializer.validated_data.get('refresh')

        token = AUTH_TOKEN_CLASS()
        payload = token.decode_token(refresh_token)

        try:
            if payload['type'] != 'refresh':
                raise AuthenticationFailed("Invalid token.")

            user_id = payload["user_id"]
            access_token, refresh_token = generate_auth_token(token_class=token, user_id=user_id)
            return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetView(APIView):
    """
    Request password reset & get otp.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetRequestSerializer
    rate_limit_handler = RequestThrottle()

    @extend_schema(summary='Reset Password', tags=['Password Reset'], **password_reset_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.PASSWORD_RESET):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            send_otp(data, OTPSubject.PASSWORD_RESET)
            return Response({'message': f'{data['verification_type']} sent via {data['method']}.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetConfirmationEmailSerializer

    @extend_schema(summary='Confirm Password Reset', tags=['Password Reset'], **password_reset_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            OTP.validate_otp(
                identifier=data["identifier"],
                code=data["code"],
                subject=OTPSubject.PASSWORD_RESET,
            )

            email, phone_number, method = data.get('email'), data.get('phone_number'), None
            if email:
                user = _User.objects.get(email=email)
                context = {'identifier': email}
                method = 'email'
            else:
                user = _User.objects.get(phone_number=phone_number)
                context = {'identifier': phone_number}
                method = 'sms'

            user.set_password(data['new_password'])
            user.save()

            # send notification to user
            communication_class = get_config('DEFAULT_NOTIFICATION_CLASS')()
            communication_class.notify(method=method, event=NotificationEvent.SUCCESS_PASSWORD_RESET, context=context)
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordChangeView(APIView):
    """
    Change password as a logged-in user
    Login required
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer
    rate_limit_handler = RequestThrottle()

    @extend_schema(summary='Change Password', tags=['Account Settings'], **password_change_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, 'password_change'):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data, context={'request': request})

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            user = request.user

            user.set_password(data['new_password'])
            user.save()

            # send notification to user
            if user.email:
                context = {'identifier': user.email}
                method = 'email'
            else:
                context = {'method': 'sms', 'identifier': user.phone_number}
                method = 'sms'

            communication_class = get_config('DEFAULT_NOTIFICATION_CLASS')()
            communication_class.notify(method=method, event=NotificationEvent.SUCCESS_PASSWORD_CHANGE, context=context)
            return Response({'message': 'Password has been changed successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeView(APIView):
    """
    Request for email change with new email & current password confirmation & get otp.
    Login required
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeRequestSerializer
    rate_limit_handler = RequestThrottle()

    @extend_schema(summary='Change Account Email', tags=['Account Settings'], **email_change_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.EMAIL_CHANGE):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data, context={'request': request})

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            code = OTP.generate_otp(get_config('OTP_LENGTH'))
            otp_instance = OTP.objects.create(identifier=data['new_email'], code=code, subject=OTPSubject.EMAIL_CHANGE)
            context = model_to_json(otp_instance)
            context['method'] = 'email'
            context['verification_type'] = data['verification_type']

            send_otp(context, OTPSubject.EMAIL_CHANGE)
            return Response({'message': f'{data['verification_type']} has been sent to the email.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeConfirmView(APIView):
    """
    Confirm email change via code confirmation & notify to old email
    Login required
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeConfirmationSerializer

    @extend_schema(summary='Confirm Account Email Change', tags=['Account Settings'], **email_change_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            OTP.validate_otp(
                identifier=data["identifier"],
                code=data["code"],
                subject=OTPSubject.EMAIL_CHANGE,
            )

            user = request.user
            old_email = user.email
            user.email = data['identifier']
            user.save()

            # send notification to user
            communication_class = get_config('DEFAULT_NOTIFICATION_CLASS')()
            communication_class.notify(method='email', event=NotificationEvent.SUCCESS_EMAIL_CHANGE, context={'identifier': old_email})
            return Response({'message': 'Email has been changed successfully.'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()