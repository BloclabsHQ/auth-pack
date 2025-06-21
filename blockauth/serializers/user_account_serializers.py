from django.core.validators import EmailValidator
from django.utils.text import format_lazy
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from blockauth.serializers.otp_serializers import OTPRequestSerializer, OTPVerifySerializer
import logging
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.config import get_config
from blockauth.utils.generics import get_password_help_text
from blockauth.utils.validators import is_valid_phone_number

_User = get_block_auth_user_model()
logger = logging.getLogger(__name__)

"""account basic auth related serializers"""

class SignUpRequestSerializer(OTPRequestSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password],
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        if data.get('email') and _User.objects.filter(email=identifier).exists():
            logger.info(f"Email: {identifier} already registered.")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4002)

        if data.get('phone_number') and _User.objects.filter(phone_number=identifier).exists():
            logger.info(f"Phone number: {identifier} already registered.")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4002)
        return data

class SignUpResendOTPSerializer(OTPRequestSerializer):
    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()

        if data.get('email') and not user:
            logger.info(f"Email: {identifier} does not exists")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4003)

        if data.get('phone_number') and not user:
            logger.info(f"Phone number: {identifier} does not exists")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4003)

        if user and user.is_verified:
            logger.info(f"User with identifier {identifier} is already verified")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4004)
        return data

class SignUpConfirmationSerializer(OTPVerifySerializer):
    pass



"""basic login related serializers"""

class BasicLoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="Email or Phone number")
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password],
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
                raise ValidationError(detail={'identifier': 'invalid email or phone number.'}, code=4001)
            data['phone_number'] = identifier

        # validate user or password existence
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()
        if not user:
            raise ValidationError(detail={'identifier': 'incorrect identifier.'}, code=4005)

        if not user.check_password(data['password']):
            raise ValidationError(detail={'password': 'incorrect password.'}, code=4005)

        if not user.is_verified:
            raise ValidationError(
                detail={"non_field_error": "account is not verified. Complete signup process or login via passwordless method"},
                code=4006
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
    def validate(self, data):
        super().validate(data)

        identifier = data.get('identifier')
        query_params = {'email': identifier} if data.get('email') else {'phone_number': identifier}
        user = _User.objects.filter(**query_params).first()

        if data.get('email') and not user:
            logger.info(f"Email: {identifier} does not exists")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4003)

        if data.get('phone_number') and not user:
            logger.info(f"Phone number: {identifier} does not exists")
            raise ValidationError(detail={'non_field_error': 'request can not be processed.'}, code=4003)
        return data


class PasswordResetConfirmationEmailSerializer(OTPVerifySerializer):
    new_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        super().validate(data)
        if data['new_password'] != data['confirm_password']:
            raise ValidationError(detail={'new_password': 'passwords do not match.'}, code=4007)
        return data

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )
    new_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError(detail={'new_password': 'passwords do not match.'}, code=4007)

        if self.context['request'].user.password and not self.context['request'].user.check_password(data['old_password']):
            raise ValidationError(detail={'old_password': 'old password is incorrect.'}, code=4005)
        return data



"""account email related serializers"""
class EmailChangeRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField(help_text='New email to replace the current email')
    current_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )
    verification_type = serializers.ChoiceField(choices=["otp", "link"], help_text="OTP or Link", default='otp')

    def validate(self, data):
        current_password = data.get('current_password')

        if not self.context['request'].user.password:
            raise ValidationError(
                detail={'non_field_error': 'passwordless account. please change or reset password.'},
                code=4008
            )

        if not self.context['request'].user.check_password(current_password):
            raise ValidationError(detail={'current_password': 'incorrect password.'}, code=4005)

        if _User.objects.filter(email=data['new_email']).exists():
            logger.info(f"Email {data['new_email']} already in use")
            raise ValidationError(detail={'current_password': 'request can not be processed.'}, code=4002)


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
            raise ValidationError(detail={'identifier': 'enter a valid email address.'}, code=4001)
        return data

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(help_text="Refresh token to get new access token", required=True)