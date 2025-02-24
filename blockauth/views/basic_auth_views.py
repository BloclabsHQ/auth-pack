import logging
from datetime import timedelta

import jwt
from django.contrib.auth import authenticate, get_user_model
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import ValidationError, APIException, AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from blockauth.communication import CommunicationPurpose
from blockauth.models.otp import OTP, OTPSubject
from blockauth.schemas.account_settings import password_change_schema, email_change_schema, email_change_confirm_schema
from blockauth.schemas.login import basic_login_schema, passwordless_login_schema, passwordless_login_confirm_schema, \
    refresh_token_schema
from blockauth.schemas.password_reset import password_reset_schema, password_reset_confirm_schema
from blockauth.schemas.signup import signup_schema, signup_resend_otp_schema, signup_confirm_schema
from blockauth.serializers.otp_serializers import OTPRequestEmailSerializer, OTPVerifyEmailSerializer
from blockauth.serializers.user_account_serializers import PasswordChangeSerializer, \
    EmailChangeConfirmationEmailSerializer, \
    PasswordResetConfirmationEmailSerializer, EmailChangeOTPRequestSerializer, \
    SignUpRequestSerializer, SignUpResendOTPSerializer, RefreshTokenSerializer, \
    PasswordlessLoginSerializer, BasicLoginSerializer, PasswordlessLoginConfirmationSerializer
from blockauth.utils.config import get_config
from blockauth.utils.generics import model_to_json
from blockauth.utils.rate_limiter import OTPRequestThrottle
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

logger = logging.getLogger(__name__)
_User = get_user_model()

class SignUpView(APIView):
    """
    ### Sign up with email and password. Internally it will send an OTP to the user's email.
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpRequestSerializer
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()

    @extend_schema(summary='Signup', tags=['Signup'], **signup_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            pre_signup_trigger = get_config('PRE_SIGNUP_TRIGGER')()
            pre_signup_trigger.trigger(context={'data': data})

            otp_code = OTP.generate_otp(get_config('OTP_LENGTH'))
            otp_instance = OTP.objects.create(identifier=data['email'], otp_code=otp_code, subject=OTPSubject.SIGNUP)

            # send OTP to user via email/sms etc
            context = model_to_json(otp_instance)
            self.communication_class.communicate(purpose=CommunicationPurpose.OTP_REQUEST, context=context)

            user = _User.objects.create(email=data['email'])
            user.set_password(data['password'])
            user.save()
            return Response({'message': 'OTP request sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpResendOTPView(APIView):
    """
    ### Resend OTP for signup.
    """
    permission_classes = (AllowAny,)
    serializer_class = SignUpResendOTPSerializer
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()
    rate_limit_handler = OTPRequestThrottle()

    @extend_schema(summary='Resend OTP for Signup', tags=['Signup'], **signup_resend_otp_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.SIGNUP):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"OTP rate limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            otp_code = OTP.generate_otp(get_config('OTP_LENGTH'))
            otp_instance = OTP.objects.create(identifier=data['email'], otp_code=otp_code, subject=OTPSubject.SIGNUP)

            # send OTP to user via developer's communication class
            context = model_to_json(otp_instance)
            self.communication_class.communicate(purpose=CommunicationPurpose.OTP_REQUEST, context=context)
            return Response({'message': 'OTP request sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class SignUpConfirmView(APIView):
    """
    ### Verify OTP to signup
    """
    permission_classes = (AllowAny,)
    serializer_class = OTPVerifyEmailSerializer

    @extend_schema(summary='Confirm Signup', tags=['Signup'], **signup_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        OTP.validate_otp(identifier=data['email'], otp_code=data['otp_code'], subject=OTPSubject.SIGNUP)

        try:
            user = _User.objects.get(email=data['email'])
            user.is_verified = True
            user.save()

            user_data = model_to_json(user)

            post_signup_trigger = get_config('POST_SIGNUP_TRIGGER')()
            post_signup_trigger.trigger(context={'user': user_data})
            return Response(data={'message': 'Sign up succesful'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class BasicAuthLoginView(APIView):
    """
    ### Login via username & password and get access token & refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = BasicLoginSerializer

    @extend_schema(summary='Basic Login', tags=['Login'], **basic_login_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
        user = authenticate(email=email, password=password)
        if user is None:
            raise ValidationError({"detail": "username or password incorrect"})

        if not user.is_verified:
            raise ValidationError({"detail": "Account is not verified. Complete signup process or login via passwordless method"})

        try:
            user.last_login = timezone.now()
            user.save()

            user_data = model_to_json(user)

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context={'user': user_data})

            access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=user.id.hex)
            return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginView(APIView):
    """
    ### Send an OTP/Login Link for passwordless login with email/phone number.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginSerializer
    rate_limit_handler = OTPRequestThrottle()
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()

    # todo: adjust schema
    @extend_schema(summary='Passwordless Login', tags=['Login'], **passwordless_login_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.LOGIN):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        method, login_id, verification_type = data['method'], data['login_id'], data['verification_type']

        try:
            otp_code = OTP.generate_otp(get_config('OTP_LENGTH'))
            OTP.objects.create(identifier=login_id, otp_code=otp_code, subject=OTPSubject.LOGIN)
            context = {**data, 'otp_code': otp_code}
            context.pop('preferred_login_url')

            if verification_type == 'link':
                context['login_url'] = f'{data['preferred_login_url']}?code={otp_code}&login_id={login_id}'

            self.communication_class.communicate(purpose=CommunicationPurpose.PASSWORDLESS_LOGIN, context=context)
            return Response({'message': f'{verification_type} sent via {method}.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginConfirmView(APIView):
    """
    ### Verify otp code for login & get access token & refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginConfirmationSerializer

    # todo: adjust schema
    @extend_schema(summary='Confirm Passwordless Login', tags=['Login'], **passwordless_login_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        OTP.validate_otp(identifier=data['login_id'], otp_code=data['code'], subject=OTPSubject.LOGIN)
        try:
            email, phone_number = data.get('email'), data.get('phone_number')
            if email:
                user, created = _User.objects.get_or_create(email=email, defaults={'is_verified': True})
            else:
                user, created = _User.objects.get_or_create(phone_number=phone_number, defaults={'is_verified': True})
            user.last_login = timezone.now()
            user.save()

            user_data = model_to_json(user, remove_fields=('password',))

            if created:
                post_sign_up_trigger = get_config('POST_SIGNUP_TRIGGER')()
                post_sign_up_trigger.trigger(context={'user': user_data})

            post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
            post_login_trigger.trigger(context={'user': user_data})

            access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=user.id.hex)
            return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class AuthRefreshTokenView(APIView):
    """
    ### Get new access token using the refresh token.
    """
    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenSerializer

    @extend_schema(summary='Regenerate Access Token', tags=['Login'], **refresh_token_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
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
    ### Request password reset & get OTP.
    """
    permission_classes = (AllowAny,)
    serializer_class = OTPRequestEmailSerializer
    rate_limit_handler = OTPRequestThrottle()
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()

    @extend_schema(summary='Reset Password', tags=['Password Reset'], **password_reset_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.PASSWORD_RESET):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"OTP rate limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            otp_code = OTP.generate_otp(get_config('OTP_LENGTH'))
            otp_instance = OTP.objects.create(
                identifier=data['email'], otp_code=otp_code, subject=OTPSubject.PASSWORD_RESET
            )

            context = model_to_json(otp_instance)
            self.communication_class.communicate(purpose=CommunicationPurpose.OTP_REQUEST, context=context)
            return Response({'message': 'OTP request sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetConfirmView(APIView):
    """
    ### Confirm password reset via OTP.
    """
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetConfirmationEmailSerializer

    @extend_schema(summary='Confirm Password Reset', tags=['Password Reset'], **password_reset_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        OTP.validate_otp(identifier=data['email'], otp_code=data['otp_code'], subject=OTPSubject.PASSWORD_RESET)
        try:
            user = _User.objects.get(email=data['email'])
            user.set_password(data['new_password'])
            user.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordChangeView(APIView):
    """
    ### Change password as a logged-in user
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()

    @extend_schema(summary='Change Password', tags=['Account Settings'], **password_change_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = request.user

        try:
            user.set_password(data['new_password'])
            user.save()

            # send email/sms notification to user
            self.communication_class.communicate(purpose=CommunicationPurpose.PASSWORD_CHANGE, context={})
            return Response({'message': 'Password has been changed successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeView(APIView):
    """
    ### Request for email change with current password confirmation & get OTP.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeOTPRequestSerializer
    rate_limit_handler = OTPRequestThrottle()
    communication_class = get_config('DEFAULT_COMMUNICATION_CLASS')()

    @extend_schema(summary='Change Account Email', tags=['Account Settings'], **email_change_schema)
    def post(self, request):
        if not self.rate_limit_handler.allow_request(request, OTPSubject.EMAIL_CHANGE):
            wait_time = int(self.rate_limit_handler.wait())
            return Response(
                data={"detail": f"OTP rate limit exceeded. Please try again after {wait_time} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            otp_code = OTP.generate_otp(get_config('OTP_LENGTH'))
            otp_instance = OTP.objects.create(
                identifier=data['email'], otp_code=otp_code, subject=OTPSubject.EMAIL_CHANGE
            )
            context = model_to_json(otp_instance)
            self.communication_class.communicate(context=context, purpose=CommunicationPurpose.OTP_REQUEST)
            return Response({'message': 'OTP request sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeConfirmView(APIView):
    """
    ### Confirm email change via OTP
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeConfirmationEmailSerializer

    @extend_schema(summary='Confirm Account Email Change', tags=['Account Settings'], **email_change_confirm_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        OTP.validate_otp(identifier=data['email'], otp_code=data['otp_code'], subject=OTPSubject.EMAIL_CHANGE)
        try:
            user = request.user
            user.email = data['new_email']
            user.save()
            return Response({'message': 'Email has been changed successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()