import random
import string

from django.db import models
from django.utils import timezone
from rest_framework.serializers import ValidationError

from blockauth.utils.config import get_config


class OTPSubject(models.TextChoices):
    LOGIN = 'login', 'Login'
    SIGNUP = 'sign_up', 'Signup'
    PASSWORD_RESET = 'password_reset', 'Password Reset'
    EMAIL_CHANGE = 'email_change', 'Email Change'


class OTP(models.Model):
    identifier = models.CharField(max_length=100, help_text="Email to send OTP")
    code = models.CharField(max_length=12)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    subject = models.CharField(max_length=30, choices=OTPSubject.choices)

    @classmethod
    def validate_otp(cls, identifier: str, subject: str, code: str) -> None:
        otp_instance = cls.objects.filter(
            identifier=identifier,
            subject=subject,
        ).values('code', 'created_at', 'is_used').order_by('-created_at').first()

        if not otp_instance or otp_instance['code'] != code:
            raise ValidationError(detail={"code": "invalid otp"}, code=4010)

        if timezone.now() > otp_instance['created_at'] + get_config('OTP_VALIDITY') or otp_instance['is_used']:
            raise ValidationError(detail={"code": "otp has expired."}, code=4011)
        cls.clear_otp(identifier, subject)

    @classmethod
    def clear_otp(cls, identifier: str, subject: str) -> None:
        cls.objects.filter(identifier=identifier, subject=subject).delete()

    @staticmethod
    def generate_otp(length):
        characters = string.digits + string.ascii_letters
        otp = ''.join(random.choice(characters) for _ in range(length))
        return otp

    class Meta:
        managed = True
        db_table = "otp"
        verbose_name = "OTP"
        indexes = [
            models.Index(fields=['identifier', 'subject']),
        ]