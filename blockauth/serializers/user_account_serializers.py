from django.contrib.auth import get_user_model
from django.utils.text import format_lazy
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from blockauth.serializers.otp_serializers import OTPVerifyEmailSerializer, OTPRequestEmailSerializer
import logging

from blockauth.utils.generics import get_password_help_text

_User = get_user_model()
logger = logging.getLogger(__name__)

"""account basic auth related serializers"""

class SignUpRequestSerializer(OTPRequestEmailSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password],
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        email = data.get('email')
        if _User.objects.filter(email=email).exists():
            logger.info(f"Email {email} already in use")
            raise ValidationError({'email': 'Request cannot be processed'})
        return data

class SignUpResendOTPSerializer(OTPRequestEmailSerializer):
    def validate(self, data):
        email = data.get('email')
        user = _User.objects.filter(email=email).first()
        if not user:
            logger.info(f"User with email:{email} does not exist")
            raise ValidationError({'email': 'Request cannot be processed'})

        if user.is_verified:
            logger.info(f"User with email:{email} is already verified")
            raise ValidationError({'email': 'Request cannot be processed'})
        return data

class BasicLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password],
        help_text=format_lazy(get_password_help_text()),
    )

    def validate(self, data):
        super().validate(data)

        email = data.get('email')
        user = _User.objects.filter(email=email).first()
        if user and not user.password:
            raise ValidationError({
                'detail': 'Passwordless account. Please login via passwordless method, social account or reset password.'
            })

        return data

"""account password related serializers"""

class PasswordResetConfirmationEmailSerializer(OTPVerifyEmailSerializer):
    new_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )
    confirm_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError({'detail': 'Passwords do not match.'})
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
            raise ValidationError({'detail': 'Passwords do not match.'})

        if self.context['request'].user.password and not self.context['request'].user.check_password(data['old_password']):
            raise ValidationError({'detail': 'Old password is incorrect'})
        return data


"""account email related serializers"""

class EmailChangeOTPRequestSerializer(OTPRequestEmailSerializer):
    current_password = serializers.CharField(
        write_only=True, validators=[validate_password], help_text=format_lazy(get_password_help_text())
    )

    def validate(self, data):
        current_password = data.get('current_password')

        if not self.context['request'].user.password:
            raise ValidationError({'detail': 'Passwordless account. Please change or reset password.'})

        if not self.context['request'].user.check_password(current_password):
            raise ValidationError({'current_password': 'Incorrect password'})
        return data

class EmailChangeConfirmationEmailSerializer(OTPVerifyEmailSerializer):
    new_email = serializers.EmailField(help_text='New email to replace the current email')

    def validate(self, data):
        new_email = data.get('new_email')
        if _User.objects.filter(email=new_email).exists():
            logger.info(f"Email {new_email} already in use")
            raise ValidationError({'new_email': 'Can''t use this email'})
        return data


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(help_text="Refresh token to get new access token", required=True)