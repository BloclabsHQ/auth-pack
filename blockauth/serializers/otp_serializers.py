from django.contrib.auth import get_user_model
from rest_framework import serializers

from blockauth.utils.config import get_config

_User = get_user_model()


class OTPRequestEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=100, help_text="Email to send OTP")


class OTPVerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=100, help_text="Email to send OTP")
    otp_code = serializers.CharField(max_length=get_config("OTP_LENGTH"), help_text="OTP received")