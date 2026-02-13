from django.core.validators import EmailValidator
from django.utils.text import format_lazy
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from blockauth.serializers.otp_serializers import OTPRequestSerializer, OTPVerifySerializer
import logging
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.config import get_config
from blockauth.utils.generics import get_password_help_text
from blockauth.utils.validators import is_valid_phone_number, FabricBlocPasswordValidator

_User = get_block_auth_user_model()
logger = logging.getLogger(__name__)

# Single instance of password validator to avoid duplicate error messages
_password_validator = FabricBlocPasswordValidator()

"""account basic auth related serializers"""

class SignUpRequestSerializer(OTPRequestSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[_password_validator.validate],
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        if data.get('email') and _User.objects.filter(email=identifier).exists():
            logger.info("Signup attempted with existing email.")
            raise ValidationError(
                detail={'identifier': 'Unable to complete registration with the provided information.'},
                code=4002,
            )

        if data.get('phone_number') and _User.objects.filter(phone_number=identifier).exists():
            logger.info("Signup attempted with existing phone number.")
            raise ValidationError(
                detail={'identifier': 'Unable to complete registration with the provided information.'},
                code=4002,
            )
        return data

class SignUpResendOTPSerializer(OTPRequestSerializer):
    """Validates format and checks account state.
    Results stored internally — view returns identical response
    regardless of outcome to prevent user enumeration (OWASP)."""

    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()

        # Store validation results for the view — never expose to the client
        data['_user'] = user
        data['_should_send'] = False

        if not user:
            logger.info("OTP resend requested for non-existent account.")
        elif user.is_verified:
            logger.info("OTP resend requested for already verified account.")
        else:
            data['_should_send'] = True

        return data

class SignUpConfirmationSerializer(OTPVerifySerializer):
    def validate(self, data):
        super().validate(data)
        return data



"""basic login related serializers"""

class BasicLoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="Email or Phone number")
    password = serializers.CharField(
        write_only=True, required=True,
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        # validate email or phone number format
        try:
            EmailValidator()(identifier)
            data['email'] = identifier
        except Exception:
            if not is_valid_phone_number(identifier):
                raise ValidationError(detail={'identifier': 'Invalid email or phone number format. Please provide a valid email or phone number.'}, code=4001)
            data['phone_number'] = identifier

        # validate credentials — use same message for all failures to prevent enumeration
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()

        if not user or not user.check_password(data['password']):
            raise ValidationError(
                detail={'non_field_errors': 'Invalid credentials. Please check your email/phone and password.'},
                code=4005,
            )

        if not user.is_verified:
            raise ValidationError(
                detail={'non_field_errors': 'Account is not verified. Complete the signup process or log in via passwordless method.'},
                code=4006,
            )

        data['user'] = user
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

        identifier = data.get('identifier')
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()

        # Store validation result for the view — never expose to the client
        data['_user'] = user
        data['_should_send'] = user is not None

        if not user:
            logger.info("Password reset requested for non-existent account.")

        return data


class PasswordResetConfirmationEmailSerializer(OTPVerifySerializer):
    new_password = serializers.CharField(
        write_only=True, validators=[_password_validator.validate], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(
        write_only=True, help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        super().validate(data)
        if data['new_password'] != data['confirm_password']:
            raise ValidationError(detail={'new_password': 'Passwords do not match. Please make sure both passwords are identical.'}, code=4007)
        return data

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True, help_text=format_lazy(get_password_help_text())
    )
    new_password = serializers.CharField(
        write_only=True, validators=[_password_validator.validate], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(
        write_only=True, help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError(detail={'new_password': 'Passwords do not match. Please make sure both passwords are identical.'}, code=4007)

        if self.context['request'].user.password and not self.context['request'].user.check_password(data['old_password']):
            raise ValidationError(detail={'old_password': 'Current password is incorrect. Please try again.'}, code=4005)
        return data



"""account email related serializers"""
class EmailChangeRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField(help_text='New email to replace the current email')
    current_password = serializers.CharField(
        write_only=True, help_text=format_lazy(get_password_help_text())
    )
    verification_type = serializers.ChoiceField(choices=["otp", "link"], help_text="OTP or Link", default='otp')

    def validate(self, data):
        current_password = data.get('current_password')

        if not self.context['request'].user.password:
            raise ValidationError(
                detail={'current_password': 'This is a passwordless account. Please set a password first via password reset.'},
                code=4008,
            )

        if not self.context['request'].user.check_password(current_password):
            raise ValidationError(detail={'current_password': 'Incorrect password. Please try again.'}, code=4005)

        if _User.objects.filter(email=data['new_email']).exists():
            logger.info("Email change attempted with an unavailable email address.")
            raise ValidationError(
                detail={'new_email': 'Unable to change to this email address.'},
                code=4002,
            )


        if data['verification_type'] == 'link':
            get_config('CLIENT_APP_URL')   # internally raise 500 if not configured
        return data


class EmailChangeConfirmationSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="New email to replace the current email")
    code = serializers.CharField(help_text="Verification code received")

    def validate(self, data):
        identifier = data.get('identifier')
        try:
            EmailValidator()(identifier)
        except Exception:
            raise ValidationError(detail={'identifier': 'Invalid email address format. Please provide a valid email address.'}, code=4001)
        return data

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(help_text="Refresh token to get new access token", required=True)