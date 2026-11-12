import hashlib
import hmac
import secrets
import string

from django.db import models
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from blockauth.utils.config import get_config
from blockauth.utils.token import _resolve_keys


class OTPSubject(models.TextChoices):
    LOGIN = "login", "Login"
    SIGNUP = "sign_up", "Signup"
    PASSWORD_RESET = "password_reset", "Password Reset"
    EMAIL_CHANGE = "email_change", "Email Change"
    WALLET_EMAIL_VERIFICATION = "wallet_email_verification", "Wallet Email Verification"


def otp_code_digest(code: str) -> str:
    """Return the HMAC-SHA256 hex digest for a delivered OTP code."""
    signing_key, _verification_key = _resolve_keys(get_config("ALGORITHM"))
    key = signing_key if isinstance(signing_key, bytes) else str(signing_key).encode("utf-8")
    return hmac.new(key, code.encode("utf-8"), hashlib.sha256).hexdigest()


class OTP(models.Model):
    identifier = models.CharField(max_length=100, db_index=True, help_text="Email or phone to send OTP")
    code = models.CharField(max_length=64)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    subject = models.CharField(max_length=30, choices=OTPSubject.choices)
    # Carries data that must survive until OTP confirmation. Used by the
    # ghost-free signup flow to defer user-row creation until inbox ownership
    # is proven.
    payload = models.JSONField(null=True, blank=True, default=None)

    @classmethod
    def validate_otp(cls, identifier: str, subject: str, code: str) -> dict | None:
        """Validate an OTP and return its payload (may be None).

        Raises ValidationError on invalid/expired code. Deletes the OTP on
        success so it cannot be replayed.
        """
        otp_instance = (
            cls.objects.filter(
                identifier=identifier,
                subject=subject,
            )
            .values("code", "created_at", "is_used", "payload")
            .order_by("-created_at")
            .first()
        )

        # Always run constant-time comparison even when no OTP exists,
        # so attackers can't distinguish "no OTP" from "wrong code" via timing.
        # Pad dummy to same length as the digest so compare_digest doesn't leak length.
        presented = otp_code_digest(code)
        stored_code = otp_instance["code"] if otp_instance else "\0" * len(presented)
        if len(stored_code) == len(presented):
            code_match = hmac.compare_digest(stored_code, presented)
        else:
            code_match = False

        if not otp_instance or not code_match:
            raise ValidationError(detail={"code": "invalid otp"}, code=4010)

        if timezone.now() > otp_instance["created_at"] + get_config("OTP_VALIDITY") or otp_instance["is_used"]:
            raise ValidationError(detail={"code": "otp has expired."}, code=4011)
        cls.clear_otp(identifier, subject)
        return otp_instance.get("payload")

    @classmethod
    def clear_otp(cls, identifier: str, subject: str) -> None:
        cls.objects.filter(identifier=identifier, subject=subject).delete()

    @staticmethod
    def generate_otp(length):
        """Generate cryptographically secure OTP using secrets module."""
        characters = string.digits + string.ascii_letters
        otp = "".join(secrets.choice(characters) for _ in range(length))
        return otp

    class Meta:
        managed = True
        db_table = "otp"
        verbose_name = "OTP"
        indexes = [
            models.Index(fields=["identifier", "subject"]),
        ]
