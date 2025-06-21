from rest_framework import serializers
from django.core.validators import EmailValidator
from rest_framework.exceptions import ValidationError
from blockauth.utils.config import get_config, get_block_auth_user_model
from blockauth.utils.validators import is_valid_phone_number

_User = get_block_auth_user_model()

class OTPRequestSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=["email", "sms"], help_text="Method to send message", default="email")
    verification_type = serializers.ChoiceField(choices=["otp", "link"], help_text="OTP or Link", default='otp')
    identifier = serializers.CharField(max_length=100, help_text="Email or Phone number")

    def validate(self, data):
        method = data.get('method')
        identifier = data.get('identifier')
        verification_type = data.get('verification_type')

        # validate email or phone number format
        if method == 'email':
            try:
                EmailValidator()(identifier)
                data['email'] = identifier
            except Exception:
                raise ValidationError(detail={'identifier': "enter a valid email address."}, code=4001)
        elif method == "sms":
            if not is_valid_phone_number(identifier):
                raise ValidationError(detail={'identifier': "enter a valid phone number."}, code=4001)
            data['phone_number'] = identifier

        if verification_type == 'link':
            get_config('CLIENT_APP_URL')   # internally raise 500 if not configured
        return data


class OTPVerifySerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=100, help_text="Email or Phone number")
    code = serializers.CharField(help_text="Verification code received")

    def validate(self, data):
        identifier = data.get('identifier')
        # validate email or phone number format
        try:
            EmailValidator()(identifier)
            data['email'] = identifier
        except Exception:
            if not is_valid_phone_number(identifier):
                raise ValidationError(detail={'identifier': "invalid email or phone number."}, code=4001)
            data['phone_number'] = identifier
        return data