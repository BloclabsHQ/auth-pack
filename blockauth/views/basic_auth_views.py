import logging

from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import APIException, AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.auth_docs import (
    basic_login_docs,
    email_change_confirm_docs,
    email_change_docs,
    password_change_docs,
    password_reset_confirm_docs,
    password_reset_docs,
    passwordless_confirm_docs,
    passwordless_login_docs,
    refresh_token_docs,
    signup_confirm_docs,
    signup_docs,
    signup_resend_otp_docs,
)
from blockauth.enums import AuthenticationType
from blockauth.models.otp import OTP, OTPSubject
from blockauth.notification import NotificationEvent, send_otp
from blockauth.serializers.user_account_serializers import (
    BasicLoginResponseSerializer,
    BasicLoginSerializer,
    EmailChangeConfirmationSerializer,
    EmailChangeRequestSerializer,
    PasswordChangeSerializer,
    PasswordlessLoginConfirmationSerializer,
    PasswordlessLoginResponseSerializer,
    PasswordlessLoginSerializer,
    PasswordResetConfirmationEmailSerializer,
    PasswordResetRequestSerializer,
    RefreshTokenSerializer,
    SignUpConfirmationSerializer,
    SignUpRequestSerializer,
    SignUpResendOTPSerializer,
)
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.custom_exception import ValidationErrorWithCode
from blockauth.utils.generics import model_to_json, sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.rate_limiter import EnhancedThrottle, OTPThrottle, RequestThrottle
from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token

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

            pre_signup_trigger = get_config("PRE_SIGNUP_TRIGGER")()
            pre_signup_trigger.trigger(context=data)

            if data.get("email"):
                user = _User.objects.create(email=data["email"])
            else:
                user = _User.objects.create(phone_number=data["phone_number"])
            user.set_password(data["password"])
            user.add_authentication_type(AuthenticationType.EMAIL)
            user.save()

            send_otp(data=data, subject=OTPSubject.SIGNUP)
            blockauth_logger.success(
                f"User signup {data['verification_type']} sent", sanitize_log_context(request.data, {"user": user.id})
            )
            return Response(
                {"message": f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK
            )
        except ValidationError as e:
            blockauth_logger.warning(
                "User signup validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("User signup failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException() from e


class SignUpResendOTPView(APIView):
    """
    Send OTP/verification link for signup or wallet email verification.

    Enhanced with OTP-specific throttling for better security.
    """

    permission_classes = (AllowAny,)
    serializer_class = SignUpResendOTPSerializer
    rate_limit_handler = OTPThrottle(rate=(5, 60), daily_limit=20)  # 5 OTPs per minute, 20 per day
    authentication_classes = []

    @extend_schema(**signup_resend_otp_docs)
    def post(self, request):
        try:
            if not self.rate_limit_handler.allow_request(request, OTPSubject.SIGNUP):
                error_message = self.rate_limit_handler.get_error_message()
                blockauth_logger.warning(
                    "Signup OTP resend rate limit hit",
                    sanitize_log_context(request.data, {"error_message": error_message}),
                )
                return Response(data={"detail": error_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

            serializer = self.serializer_class(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Serializer stores _should_send and _user — only send OTP when appropriate,
            # but always return the same response to prevent user enumeration (OWASP).
            if data.get("_should_send"):
                user = data["_user"]
                is_wallet_verification = user.wallet_address is not None

                if is_wallet_verification:
                    if not self.rate_limit_handler.allow_request(request, OTPSubject.WALLET_EMAIL_VERIFICATION):
                        error_message = self.rate_limit_handler.get_error_message()
                        blockauth_logger.warning(
                            "Wallet email OTP resend rate limit hit",
                            sanitize_log_context(request.data, {"error_message": error_message}),
                        )
                        return Response(data={"detail": error_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)
                    send_otp(data, OTPSubject.WALLET_EMAIL_VERIFICATION)
                    blockauth_logger.success(
                        f"Wallet email verification {data['verification_type']} sent",
                        sanitize_log_context(request.data),
                    )
                else:
                    send_otp(data, OTPSubject.SIGNUP)
                    blockauth_logger.success(
                        f"Signup {data['verification_type']} sent", sanitize_log_context(request.data)
                    )

            # Always return identical response regardless of account state
            return Response(
                {
                    "message": f'If your account requires verification, a {data["verification_type"]} will be sent via {data["method"]}.'
                },
                status=status.HTTP_200_OK,
            )
        except ValidationError as e:
            blockauth_logger.warning(
                "Verification send validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
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
        serializer = self.serializer_class(data=request.data, context={"request": request})
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
                identifier=identifier, code=code, subject=OTPSubject.WALLET_EMAIL_VERIFICATION, is_used=False
            ).exists()

            # Check if signup OTP exists
            signup_otp_exists = OTP.objects.filter(
                identifier=identifier, code=code, subject=OTPSubject.SIGNUP, is_used=False
            ).exists()

            if wallet_otp_exists:
                # Wallet email verification
                OTP.validate_otp(identifier=identifier, code=code, subject=OTPSubject.WALLET_EMAIL_VERIFICATION)

                # Find the user by email and update verification status
                user = _User.objects.get(email=identifier)
                user.is_verified = True
                user.save()

                blockauth_logger.success("Wallet email verified", sanitize_log_context(request.data, {"user": user.id}))
                return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
            elif signup_otp_exists:
                # Regular signup confirmation
                OTP.validate_otp(identifier=identifier, code=code, subject=OTPSubject.SIGNUP)

                email, phone_number = data.get("email"), data.get("phone_number")
                if email:
                    user = _User.objects.get(email=email)
                else:
                    user = _User.objects.get(phone_number=phone_number)
                user.is_verified = True
                user.save()

                user_data = model_to_json(user, remove_fields=("password",))

                # Call POST_SIGNUP_TRIGGER with user data
                post_signup_trigger = get_config("POST_SIGNUP_TRIGGER")()
                post_signup_trigger.trigger(context={"user": user, "provider_data": data})
                blockauth_logger.success("User signup confirmed", sanitize_log_context(request.data, {"user": user.id}))
                return Response(data={"message": "Sign up success"}, status=status.HTTP_200_OK)
            else:
                # No valid OTP found for either subject
                raise ValidationError(
                    detail={"code": "Invalid or expired verification code. Please request a new one."}, code=4010
                )

        except ValidationError as e:
            blockauth_logger.warning(
                "Verification confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error(
                "Verification confirmation failed", sanitize_log_context(request.data, {"error": str(e)})
            )
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class BasicAuthLoginView(APIView):
    """``POST /login/basic/`` -- email/phone + password login.

    Returns ``{access, refresh, user}``. The ``user`` payload carries
    ``id``, ``email``, ``is_verified``, and ``wallet_address`` so clients
    hydrate without a follow-up ``GET /me/`` round-trip (issue #97).
    ``wallet_address`` is null for email-first accounts until they run
    the ``wallet/link/`` flow.
    """

    permission_classes = (AllowAny,)
    serializer_class = BasicLoginSerializer
    authentication_classes = []
    login_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    @extend_schema(**basic_login_docs)
    def post(self, request):
        # Check progressive lockout before processing
        if not self.login_throttle.allow_request(request, "basic_login"):
            reason = self.login_throttle.get_block_reason()
            msg = (
                "Too many failed login attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Basic login attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            user = data["user"]
            user.last_login = timezone.now()
            user.add_authentication_type("EMAIL")
            user.save()

            user_data = model_to_json(user, remove_fields=("password",))

            post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
            post_login_trigger.trigger(context={"user": user_data})

            # Use enhanced token generation with custom claims support
            try:
                from blockauth.utils.token import generate_auth_token_with_custom_claims

                access_token, refresh_token = generate_auth_token_with_custom_claims(
                    token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
                )
            except ImportError:
                # Fall back to original implementation
                access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))
            self.login_throttle.record_success(request, "basic_login")
            blockauth_logger.success("Basic login successful", sanitize_log_context(request.data, {"user": user.id}))
            # Issue #97: return user payload so clients can hydrate profile
            # state without a second ``GET /me/`` round-trip. Same shape as
            # wallet-login. ``wallet_address`` is null for email-first users
            # until they run the ``wallet/link/`` flow.
            response_serializer = BasicLoginResponseSerializer(
                {
                    "access": access_token,
                    "refresh": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "is_verified": user.is_verified,
                        "wallet_address": user.wallet_address,
                    },
                }
            )
            return Response(data=response_serializer.data, status=status.HTTP_200_OK)
        except (ValidationError, ValidationErrorWithCode) as e:
            self.login_throttle.record_failure(request, "basic_login")
            blockauth_logger.warning(
                "Basic login validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            self.login_throttle.record_failure(request, "basic_login")
            blockauth_logger.error("Basic login failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginView(APIView):
    """
    Send an otp/Login Link for passwordless login with email/phone number.

    Enhanced with OTP-specific throttling for better security:
    - Prevents multiple active OTPs per identifier
    - Daily limits per identifier
    - Enhanced logging and monitoring
    """

    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginSerializer
    rate_limit_handler = OTPThrottle(rate=(5, 60), daily_limit=20)  # 5 OTPs per minute, 20 per day
    authentication_classes = []

    @extend_schema(**passwordless_login_docs)
    def post(self, request):
        try:
            if not self.rate_limit_handler.allow_request(request, OTPSubject.LOGIN):
                error_message = self.rate_limit_handler.get_error_message()
                blockauth_logger.warning(
                    "Passwordless login rate limit hit",
                    sanitize_log_context(request.data, {"error_message": error_message}),
                )
                return Response(data={"detail": error_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            send_otp(data, OTPSubject.LOGIN)
            blockauth_logger.success(
                f"Passwordless login {data['verification_type']} sent", sanitize_log_context(request.data)
            )
            return Response(
                {"message": f"{data['verification_type']} sent via {data['method']}."}, status=status.HTTP_200_OK
            )
        except ValidationError as e:
            blockauth_logger.warning(
                "Passwordless login validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Passwordless login failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordlessLoginConfirmView(APIView):
    """``POST /login/passwordless/confirm/`` -- verify OTP and issue tokens.

    Mirrors :class:`BasicAuthLoginView`'s response shape:
    ``{access, refresh, user}``. Auto-creates an account if the identifier
    is new (issue #97 -- clients hydrate profile state in a single
    round-trip regardless of the create-vs-existing branch).
    """

    permission_classes = (AllowAny,)
    serializer_class = PasswordlessLoginConfirmationSerializer
    authentication_classes = []
    login_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    @extend_schema(**passwordless_confirm_docs)
    def post(self, request):
        if not self.login_throttle.allow_request(request, "passwordless_login"):
            reason = self.login_throttle.get_block_reason()
            msg = (
                "Too many failed login attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Passwordless login confirmation attempt", sanitize_log_context(request.data))
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            OTP.validate_otp(identifier=data["identifier"], code=data["code"], subject=OTPSubject.LOGIN)

            email, phone_number = data.get("email"), data.get("phone_number")
            if email:
                user, created = _User.objects.get_or_create(email=email, defaults={"is_verified": True})
            else:
                user, created = _User.objects.get_or_create(phone_number=phone_number, defaults={"is_verified": True})
            user.last_login = timezone.now()
            user.is_verified = True
            user.add_authentication_type(AuthenticationType.PASSWORDLESS)
            user.save()

            user_data = model_to_json(user, remove_fields=("password",))

            if created:
                post_sign_up_trigger = get_config("POST_SIGNUP_TRIGGER")()
                post_sign_up_trigger.trigger(context={"user": user_data})
                blockauth_logger.success(
                    "Passwordless login: new user created", sanitize_log_context(request.data, {"user": user.id})
                )

            post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
            post_login_trigger.trigger(context={"user": user_data})

            # Use enhanced token generation with custom claims support
            try:
                from blockauth.utils.token import generate_auth_token_with_custom_claims

                access_token, refresh_token = generate_auth_token_with_custom_claims(
                    token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
                )
            except ImportError:
                # Fall back to original implementation
                access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))
            self.login_throttle.record_success(request, "passwordless_login")
            blockauth_logger.success(
                "Passwordless login confirmed", sanitize_log_context(request.data, {"user": user.id})
            )
            # Issue #97: mirror basic-login / wallet-login by returning the
            # authenticated user so clients can hydrate profile state in one
            # round-trip. ``wallet_address`` is null for email / SMS users
            # that haven't linked a wallet yet.
            response_serializer = PasswordlessLoginResponseSerializer(
                {
                    "access": access_token,
                    "refresh": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "is_verified": user.is_verified,
                        "wallet_address": user.wallet_address,
                    },
                }
            )
            return Response(data=response_serializer.data, status=status.HTTP_200_OK)
        except ValidationError as e:
            self.login_throttle.record_failure(request, "passwordless_login")
            blockauth_logger.warning(
                "Passwordless login confirmation validation failed",
                sanitize_log_context(request.data, {"errors": e.detail}),
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            self.login_throttle.record_failure(request, "passwordless_login")
            blockauth_logger.error(
                "Passwordless login confirmation failed", sanitize_log_context(request.data, {"error": str(e)})
            )
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class AuthRefreshTokenView(APIView):
    """
    Get new access token using the refresh token.
    """

    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenSerializer
    authentication_classes = []

    @extend_schema(**refresh_token_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Refresh token attempt", sanitize_log_context(request.data))
        if not serializer.is_valid():
            blockauth_logger.warning(
                "Refresh token validation failed", sanitize_log_context(request.data, {"errors": serializer.errors})
            )
            raise ValidationErrorWithCode(detail=serializer.errors)
        refresh_token_value = serializer.validated_data.get("refresh_token")
        token = AUTH_TOKEN_CLASS()
        payload = token.decode_token(refresh_token_value)
        try:
            if payload["type"] != "refresh":
                blockauth_logger.error(
                    "Invalid refresh token type", sanitize_log_context(request.data, {"payload": payload})
                )
                raise AuthenticationFailed("Invalid token.")

            # --- Refresh token rotation: reject blacklisted tokens ----------
            from blockauth.utils.token_blacklist import is_blacklisted

            old_jti = payload.get("jti")
            if is_blacklisted(old_jti):
                blockauth_logger.warning(
                    "Blacklisted refresh token reuse attempted",
                    sanitize_log_context(request.data, {"jti": old_jti}),
                )
                raise AuthenticationFailed("Invalid token.")

            user_id = payload["user_id"]

            # Get user to retrieve is_verified status
            user_model = get_block_auth_user_model()
            user = user_model.objects.get(id=user_id)

            # Use enhanced token generation with custom claims support
            try:
                from blockauth.utils.token import generate_auth_token_with_custom_claims

                access_token, new_refresh_token = generate_auth_token_with_custom_claims(
                    token_class=token, user_id=user_id
                )
            except ImportError:
                # Fall back to original implementation
                access_token, new_refresh_token = generate_auth_token(token_class=token, user_id=user_id)

            # --- Blacklist the old refresh token so it can't be reused ------
            if get_config("ROTATE_REFRESH_TOKENS") and old_jti:
                import time

                from blockauth.utils.token_blacklist import blacklist_token

                exp = payload.get("exp", 0)
                remaining_ttl = max(int(exp) - int(time.time()), 0)
                blacklist_token(old_jti, remaining_ttl)

            blockauth_logger.success(
                "Refresh token successful", sanitize_log_context(request.data, {"user_id": user_id})
            )
            return Response(data={"access": access_token, "refresh": new_refresh_token}, status=status.HTTP_200_OK)
        except AuthenticationFailed:
            raise
        except Exception as e:
            blockauth_logger.error("Refresh token failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetView(APIView):
    """
    Request password reset & get otp.
    """

    permission_classes = (AllowAny,)
    serializer_class = PasswordResetRequestSerializer
    rate_limit_handler = RequestThrottle()
    authentication_classes = []

    @extend_schema(**password_reset_docs)
    def post(self, request):
        try:
            if not self.rate_limit_handler.allow_request(request, OTPSubject.PASSWORD_RESET):
                wait_time = int(self.rate_limit_handler.wait())
                blockauth_logger.warning(
                    "Password reset rate limit hit", sanitize_log_context(request.data, {"wait_time": wait_time})
                )
                return Response(
                    data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Serializer stores _should_send — only send OTP when user exists,
            # but always return the same response to prevent user enumeration (OWASP).
            if data.get("_should_send"):
                send_otp(data, OTPSubject.PASSWORD_RESET)
                blockauth_logger.success(
                    f"Password reset {data['verification_type']} sent", sanitize_log_context(request.data)
                )

            # Always return identical response regardless of account existence
            return Response(
                {"message": f'If an account exists, a {data["verification_type"]} will be sent via {data["method"]}.'},
                status=status.HTTP_200_OK,
            )
        except ValidationError as e:
            blockauth_logger.warning(
                "Password reset validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Password reset failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset
    """

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
                identifier=data["identifier"],
                code=data["code"],
                subject=OTPSubject.PASSWORD_RESET,
            )

            email, phone_number, method = data.get("email"), data.get("phone_number"), None
            if email:
                user = _User.objects.get(email=email)
                context = {"identifier": email}
                method = "email"
            else:
                user = _User.objects.get(phone_number=phone_number)
                context = {"identifier": phone_number}
                method = "sms"

            # Reset user password
            user.set_password(data["new_password"])
            user.save()

            # Trigger POST_PASSWORD_RESET_TRIGGER if configured
            try:
                post_password_reset_trigger = get_config("POST_PASSWORD_RESET_TRIGGER")()
                trigger_context = {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "trigger_type": "password_reset",
                    "timestamp": timezone.now().isoformat(),
                }
                post_password_reset_trigger.trigger(context=trigger_context)
            except Exception as e:
                # Trigger not configured or failed - log but don't break password reset
                blockauth_logger.warning("POST_PASSWORD_RESET_TRIGGER failed", {"user_id": user.id, "error": str(e)})

            # send notification to user
            communication_class = get_config("DEFAULT_NOTIFICATION_CLASS")()
            communication_class.notify(method=method, event=NotificationEvent.SUCCESS_PASSWORD_RESET, context=context)
            blockauth_logger.success("Password reset confirmed", {"user": user.id, **request.data})
            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning(
                "Password reset confirmation validation failed",
                sanitize_log_context(request.data, {"errors": e.detail}),
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error(
                "Password reset confirmation failed", sanitize_log_context(request.data, {"error": str(e)})
            )
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

    @extend_schema(**password_change_docs)
    def post(self, request):
        try:
            if not self.rate_limit_handler.allow_request(request, "password_change"):
                wait_time = int(self.rate_limit_handler.wait())
                blockauth_logger.warning(
                    "Password change rate limit hit", sanitize_log_context(request.data, {"wait_time": wait_time})
                )
                return Response(
                    data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            serializer = self.serializer_class(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            user = request.user

            # Change user password
            user.set_password(data["new_password"])
            user.save()

            # Trigger POST_PASSWORD_CHANGE_TRIGGER if configured
            try:
                post_password_change_trigger = get_config("POST_PASSWORD_CHANGE_TRIGGER")()
                trigger_context = {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "trigger_type": "password_change",
                    "timestamp": timezone.now().isoformat(),
                }
                post_password_change_trigger.trigger(context=trigger_context)
            except Exception as e:
                # Trigger not configured or failed - log but don't break password change
                blockauth_logger.warning("POST_PASSWORD_CHANGE_TRIGGER failed", {"user_id": user.id, "error": str(e)})

            # send notification to user
            if user.email:
                context = {"identifier": user.email}
                method = "email"
            else:
                context = {"method": "sms", "identifier": user.phone_number}
                method = "sms"

            communication_class = get_config("DEFAULT_NOTIFICATION_CLASS")()
            communication_class.notify(method=method, event=NotificationEvent.SUCCESS_PASSWORD_CHANGE, context=context)
            blockauth_logger.success("Password change successful", {"user": user.id, **request.data})
            return Response({"message": "Password has been changed successfully."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning(
                "Password change validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Password change failed", sanitize_log_context(request.data, {"error": str(e)}))
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

    @extend_schema(**email_change_docs)
    def post(self, request):
        try:
            if not self.rate_limit_handler.allow_request(request, OTPSubject.EMAIL_CHANGE):
                wait_time = int(self.rate_limit_handler.wait())
                blockauth_logger.warning(
                    "Email change rate limit hit", sanitize_log_context(request.data, {"wait_time": wait_time})
                )
                return Response(
                    data={"detail": f"Request limit exceeded. Please try again after {wait_time} seconds."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            serializer = self.serializer_class(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Create proper data structure for send_otp function
            otp_data = {
                "identifier": data["new_email"],
                "method": "email",
                "verification_type": data["verification_type"],
            }

            send_otp(otp_data, OTPSubject.EMAIL_CHANGE)
            blockauth_logger.success(
                f"Email change {data['verification_type']} sent", sanitize_log_context(request.data)
            )
            return Response(
                {"message": f"{data['verification_type']} has been sent to the email."}, status=status.HTTP_200_OK
            )
        except ValidationError as e:
            blockauth_logger.warning(
                "Email change validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Email change failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()


class EmailChangeConfirmView(APIView):
    """
    Confirm email change via code confirmation & notify to old email
    Login required
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeConfirmationSerializer

    @extend_schema(**email_change_confirm_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        blockauth_logger.info("Email change confirmation attempt", sanitize_log_context(request.data))
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
            user.email = data["identifier"]
            user.save()

            # send notification to user
            communication_class = get_config("DEFAULT_NOTIFICATION_CLASS")()
            communication_class.notify(
                method="email", event=NotificationEvent.SUCCESS_EMAIL_CHANGE, context={"identifier": old_email}
            )
            blockauth_logger.success("Email change confirmed", sanitize_log_context(request.data, {"user": user.id}))
            return Response({"message": "Email has been changed successfully."}, status=status.HTTP_200_OK)
        except ValidationError as e:
            blockauth_logger.warning(
                "Email change confirmation validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error(
                "Email change confirmation failed", sanitize_log_context(request.data, {"error": str(e)})
            )
            logger.error(f"Request failed: {e}", exc_info=True)
            raise APIException()
