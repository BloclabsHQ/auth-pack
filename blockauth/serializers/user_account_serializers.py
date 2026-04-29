import logging

from django.core.validators import EmailValidator
from django.utils.text import format_lazy
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from blockauth.models.otp import OTP, OTPSubject
from blockauth.serializers.otp_serializers import OTPRequestSerializer, OTPVerifySerializer
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import get_password_help_text
from blockauth.utils.validators import BlockAuthPasswordValidator, is_valid_phone_number

_User = get_block_auth_user_model()
logger = logging.getLogger(__name__)

# Single instance of password validator to avoid duplicate error messages
_password_validator = BlockAuthPasswordValidator()

"""account basic auth related serializers"""


class SignUpRequestSerializer(OTPRequestSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[_password_validator.validate],
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        identifier = data.get("identifier")
        if data.get("email") and _User.objects.filter(email=identifier).exists():
            logger.info("Signup attempted with existing email.")
            raise ValidationError(
                detail={"identifier": "Unable to complete registration with the provided information."},
                code=4002,
            )

        if data.get("phone_number") and _User.objects.filter(phone_number=identifier).exists():
            logger.info("Signup attempted with existing phone number.")
            raise ValidationError(
                detail={"identifier": "Unable to complete registration with the provided information."},
                code=4002,
            )
        return data


class SignUpResendOTPSerializer(OTPRequestSerializer):
    """Validates format and checks account state.
    Results stored internally — view returns identical response
    regardless of outcome to prevent user enumeration (OWASP)."""

    def validate(self, data):
        super().validate(data)

        identifier = data.get("identifier")
        query_params = {"email": identifier} if data.get("email") else {"phone_number": identifier}
        user = _User.objects.filter(**query_params).first()

        # Store validation results for the view — never expose to the client
        data["_user"] = user
        data["_otp_payload"] = None
        data["_should_send"] = False

        if user and not user.is_verified:
            data["_should_send"] = True
        elif user:
            logger.info("OTP resend requested for already verified account.")
        else:
            # Ghost-free signup flow: no user row exists yet.
            # Check for a pending SIGNUP OTP so we can resend with the same payload.
            pending_otp = OTP.objects.filter(identifier=identifier, subject=OTPSubject.SIGNUP, is_used=False).first()
            if pending_otp:
                data["_otp_payload"] = pending_otp.payload
                data["_should_send"] = True
            else:
                logger.info("OTP resend requested for non-existent account.")

        return data


class SignUpConfirmationSerializer(OTPVerifySerializer):
    def validate(self, data):
        super().validate(data)
        return data


"""basic login related serializers"""


class BasicLoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="Email or Phone number")
    password = serializers.CharField(
        write_only=True,
        required=True,
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        identifier = data.get("identifier")
        # validate email or phone number format
        try:
            EmailValidator()(identifier)
            data["email"] = identifier
        except Exception:
            if not is_valid_phone_number(identifier):
                raise ValidationError(
                    detail={
                        "identifier": "Invalid email or phone number format. Please provide a valid email or phone number."
                    },
                    code=4001,
                )
            data["phone_number"] = identifier

        # validate credentials — use same message for all failures to prevent enumeration
        query_params = {"email": identifier} if data.get("email") else {"phone_number": identifier}
        user = _User.objects.filter(**query_params).first()

        if not user or not user.check_password(data["password"]):
            raise ValidationError(
                detail={"non_field_errors": "Invalid credentials. Please check your email/phone and password."},
                code=4005,
            )

        if not user.is_verified:
            raise ValidationError(
                detail={
                    "non_field_errors": "Account is not verified. Complete the signup process or log in via passwordless method."
                },
                code=4006,
            )

        data["user"] = user
        return data


"""passwordless login related serializers"""


class PasswordlessLoginSerializer(OTPRequestSerializer):
    pass


class PasswordlessLoginConfirmationSerializer(OTPVerifySerializer):
    pass


"""account password related serializers"""


class PasswordResetRequestSerializer(OTPRequestSerializer):
    """Validates format and checks account existence.
    Results stored internally — view returns identical response
    regardless of outcome to prevent user enumeration (OWASP)."""

    def validate(self, data):
        super().validate(data)

        identifier = data.get("identifier")
        query_params = {"email": identifier} if data.get("email") else {"phone_number": identifier}
        user = _User.objects.filter(**query_params).first()

        # Store validation result for the view — never expose to the client
        data["_user"] = user
        data["_should_send"] = user is not None

        if not user:
            logger.info("Password reset requested for non-existent account.")

        return data


class PasswordResetConfirmationEmailSerializer(OTPVerifySerializer):
    new_password = serializers.CharField(
        write_only=True, validators=[_password_validator.validate], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(write_only=True, help_text=format_lazy(get_password_help_text()))

    def validate(self, data):
        super().validate(data)
        if data["new_password"] != data["confirm_password"]:
            raise ValidationError(
                detail={"new_password": "Passwords do not match. Please make sure both passwords are identical."},
                code=4007,
            )
        return data


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, help_text=format_lazy(get_password_help_text()))
    new_password = serializers.CharField(
        write_only=True, validators=[_password_validator.validate], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(write_only=True, help_text=format_lazy(get_password_help_text()))

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise ValidationError(
                detail={"new_password": "Passwords do not match. Please make sure both passwords are identical."},
                code=4007,
            )

        if self.context["request"].user.password and not self.context["request"].user.check_password(
            data["old_password"]
        ):
            raise ValidationError(
                detail={"old_password": "Current password is incorrect. Please try again."}, code=4005
            )
        return data


"""account email related serializers"""


class EmailChangeRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField(help_text="New email to replace the current email")
    current_password = serializers.CharField(write_only=True, help_text=format_lazy(get_password_help_text()))
    verification_type = serializers.ChoiceField(choices=["otp", "link"], help_text="OTP or Link", default="otp")

    def validate(self, data):
        current_password = data.get("current_password")

        if not self.context["request"].user.password:
            raise ValidationError(
                detail={
                    "current_password": "This is a passwordless account. Please set a password first via password reset."
                },
                code=4008,
            )

        if not self.context["request"].user.check_password(current_password):
            raise ValidationError(detail={"current_password": "Incorrect password. Please try again."}, code=4005)

        if _User.objects.filter(email=data["new_email"]).exists():
            logger.info("Email change attempted with an unavailable email address.")
            raise ValidationError(
                detail={"new_email": "Unable to change to this email address."},
                code=4002,
            )

        if data["verification_type"] == "link":
            get_config("CLIENT_APP_URL")  # internally raise 500 if not configured
        return data


class EmailChangeConfirmationSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="New email to replace the current email")
    code = serializers.CharField(help_text="Verification code received")

    def validate(self, data):
        identifier = data.get("identifier")
        try:
            EmailValidator()(identifier)
        except Exception:
            raise ValidationError(
                detail={"identifier": "Invalid email address format. Please provide a valid email address."}, code=4001
            )
        return data


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(help_text="Refresh token to get new access token", required=True)


"""shared login response serializers (issue #97)

These serializers describe the ``{access, refresh, user}`` response shape
used by basic-login, passwordless-login, and wallet-login. Keeping them in
one place means the OpenAPI spec stays consistent across all three endpoints
and clients can share a single generated type.

``email`` and ``wallet_address`` are both nullable because:

* wallet-first accounts are created with no email on first SIWE login,
* basic / passwordless accounts have no wallet until the user runs the
  ``wallet/link/`` flow.
"""


class WalletItemSerializer(serializers.Serializer):
    """One row in the ``user.wallets`` array.

    ``label`` is nullable because a wallet has no label until the user sets
    one; ``chain_id`` is required (defaults to mainnet = 1 at the builder
    layer); ``primary`` is always present so clients can pick a default
    wallet when multiple rows land. Issue #537: before this row existed,
    wallets were serialised as bare address strings, which made the response
    shape harder to evolve.
    """

    address = serializers.CharField(help_text="Ethereum address, 0x-prefixed, lowercase")
    chain_id = serializers.IntegerField(help_text="EIP-155 chain id (1 = Ethereum mainnet)")
    linked_at = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="ISO-8601 timestamp the wallet was linked to this account",
    )
    label = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="User-set wallet label; null until set in dashboard",
    )
    primary = serializers.BooleanField(help_text="True for the account's default wallet")


class LoginUserSerializer(serializers.Serializer):
    """User payload embedded in every login response.

    Shared by ``BasicLoginResponseSerializer``,
    ``PasswordlessLoginResponseSerializer``, and
    ``WalletLoginResponseSerializer`` so the three endpoints stay in lock-step.
    Do not add anything here that isn't safe to surface to the client --
    this object goes into the success response of an unauthenticated call.

    ``is_active``, ``date_joined``, and ``wallets`` are always present so
    clients can consume the login response without a follow-up ``GET /me/``
    round-trip. ``first_name`` / ``last_name`` are
    ``required=False`` (Zod's ``.optional()`` rejects ``null``) — callers
    must omit the keys entirely when the underlying value is unset, which
    ``build_user_payload`` already does.
    """

    id = serializers.UUIDField(help_text="User UUID")
    email = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="Email address (null for wallet-first accounts)",
    )
    is_verified = serializers.BooleanField(help_text="Whether the account is verified")
    is_active = serializers.BooleanField(
        help_text="Whether the account is active (defaults to True for AbstractBaseUser-derived models)",
    )
    date_joined = serializers.CharField(
        allow_null=True,
        required=False,
        help_text=(
            "ISO-8601 timestamp of account creation. Null when the downstream "
            "user model does not define ``date_joined`` (BlockUser abstract base)."
        ),
    )
    wallet_address = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="Ethereum wallet address (null for accounts without a linked wallet)",
    )
    wallets = serializers.ListField(
        child=WalletItemSerializer(),
        help_text=(
            "Linked wallets as ``WalletItem`` objects. Single-element array "
            "derived from ``wallet_address`` until the user model supports "
            "multiples; empty when no wallet is linked. Issue #537: previously "
            "serialised as ``string[]``, which was harder for clients to evolve."
        ),
    )
    # first_name / last_name are optional because the abstract BlockUser
    # model does not define them; concrete downstream user models may.
    # build_user_payload omits the keys entirely when the underlying value
    # is null — required=False keeps the serializer from synthesizing a
    # null entry, matching optional-field client contracts.
    first_name = serializers.CharField(
        required=False,
        help_text="Given name (omitted entirely when unset)",
    )
    last_name = serializers.CharField(
        required=False,
        help_text="Family name (omitted entirely when unset)",
    )


class BasicLoginResponseSerializer(serializers.Serializer):
    """Response body for ``POST /login/basic/`` (issue #97).

    The ``user`` field gives clients parity with wallet-login so they can
    hydrate profile state without a follow-up ``GET /me/`` round-trip.
    """

    access = serializers.CharField(help_text="JWT access token")
    refresh = serializers.CharField(help_text="JWT refresh token")
    user = LoginUserSerializer(help_text="Authenticated user profile")


class PasswordlessLoginResponseSerializer(serializers.Serializer):
    """Response body for ``POST /login/passwordless/confirm/`` (issue #97).

    Same shape as :class:`BasicLoginResponseSerializer`; kept as a distinct
    class so drf-spectacular can tag the schema separately per endpoint and
    so future divergence (e.g. passwordless-only flags) is cheap.
    """

    access = serializers.CharField(help_text="JWT access token")
    refresh = serializers.CharField(help_text="JWT refresh token")
    user = LoginUserSerializer(help_text="Authenticated user profile")


class AuthStateResponseSerializer(serializers.Serializer):
    """Response body for endpoints that mutate auth state and must hand
    the client the full post-mutation auth tuple in one round trip.

    Used by ``/token/refresh/``, ``/password/reset/confirm/``, and
    ``/password/change/`` so clients never need a follow-up ``/me/`` or
    ``/login/basic/`` to reconcile state after a mutation.
    """

    access = serializers.CharField(help_text="JWT access token (freshly issued)")
    refresh = serializers.CharField(help_text="JWT refresh token (rotated where applicable)")
    user = LoginUserSerializer(help_text="Current user profile")


class SignUpConfirmResponseSerializer(serializers.Serializer):
    """Response body for successful ``POST /signup/confirm/``.

    Signup confirmation now issues JWTs so the client is signed in
    immediately instead of following up with ``POST /login/basic/`` using
    the just-set password. Same shape as the login responses so the OpenAPI
    surface stays consistent and clients can share a single post-auth code
    path.
    """

    access = serializers.CharField(help_text="JWT access token")
    refresh = serializers.CharField(help_text="JWT refresh token")
    user = LoginUserSerializer(help_text="Newly verified user profile")
