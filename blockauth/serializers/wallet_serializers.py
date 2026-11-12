from django.core.validators import EmailValidator
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from blockauth.services.wallet_login_service import WalletLoginError, get_wallet_login_service
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.custom_exception import WalletConflictError
from blockauth.utils.validators import normalize_email, user_identifier_lookup

_User = get_block_auth_user_model()

_LINK_SIGNATURE_CODES = {
    "invalid_signature",
    "signature_mismatch",
    "signature_recovery_failed",
    "malleable_signature",
    "signature_internal_error",
}


class WalletLinkSerializer(serializers.Serializer):
    """
    Validates a wallet link request from an already-authenticated user.

    Performs signature verification through the SIWE login service. The
    challenge must be the server-issued plaintext bound to this account.
    Raises WalletConflictError (409) if the address belongs to another
    user, ValidationError (400) if the user already has a wallet linked.
    """

    wallet_address = serializers.CharField(max_length=42, help_text="Ethereum wallet address (0x...)")
    message = serializers.CharField(help_text="Server-issued SIWE plaintext that was signed.")
    signature = serializers.CharField(max_length=132, help_text="Ethereum signature (0x-prefixed, 130 hex chars)")

    def validate_wallet_address(self, value):
        if not value.startswith("0x") or len(value) != 42:
            raise ValidationError("Invalid wallet address format. Must be a 42-character hex string starting with 0x.")
        return value.lower()

    def validate(self, data):
        wallet_address = data.get("wallet_address")
        message = data.get("message")
        signature = data.get("signature")
        request = self.context.get("request")

        # 1. Verify the server-issued challenge. Typed codes come from the service.
        service = get_wallet_login_service()
        try:
            service.verify_link(
                user_id=str(request.user.pk),
                wallet_address=wallet_address,
                message=message,
                signature=signature,
            )
        except WalletLoginError as exc:
            field = "signature" if exc.code in _LINK_SIGNATURE_CODES else "message"
            raise ValidationError(detail={field: exc.message}, code=exc.code) from exc

        # 2. User must not already have a wallet linked (cheap — attribute access, no DB)
        if request.user.wallet_address:
            raise ValidationError(
                detail={"wallet_address": "Your account already has a linked wallet. Unlink it first."},
                code="WALLET_ALREADY_LINKED",
            )

        # 3. Wallet must not belong to a different account (DB query — only runs if user is unlinked)
        if _User.objects.filter(wallet_address=wallet_address).exclude(pk=request.user.pk).exists():
            raise WalletConflictError()

        return data


class WalletEmailAddSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Email address to add and verify")
    verification_type = serializers.ChoiceField(
        choices=["otp", "link"], default="otp", help_text="Type of verification to send (OTP or link)"
    )

    def validate_email(self, value):
        """Validate email format"""
        try:
            EmailValidator()(value)
        except Exception:
            raise ValidationError("Invalid email address format. Please provide a valid email address.")
        return normalize_email(value)

    def validate(self, data):
        """Validate the email add request"""
        # Check if email is already in use by another user
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            lookup = user_identifier_lookup(data["email"], email=True)
            if _User.objects.filter(**lookup).exclude(wallet_address=request.user.wallet_address).exists():
                raise ValidationError(detail={"email": "Unable to use this email address."})

            # Check if user already has a verified email
            if request.user.email and request.user.is_verified:
                raise ValidationError(detail={"email": "This account already has a verified email address."})

        return data
