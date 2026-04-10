import logging

from django.core.validators import EmailValidator
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from blockauth.enums import AuthenticationType
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.custom_exception import WalletConflictError
from blockauth.utils.generics import model_to_json
from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token
from blockauth.utils.web3.wallet import WalletAuthenticator

_User = get_block_auth_user_model()
logger = logging.getLogger(__name__)


class WalletLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=42, help_text="Ethereum wallet address (0x...)")
    message = serializers.CharField(help_text="Message that was signed by the wallet user.")
    signature = serializers.CharField(
        help_text="Ethereum signature (0x-prefixed, 130 hex chars, e.g. 0x1234...)", max_length=132
    )

    def validate_wallet_address(self, value):
        if not value.startswith("0x") or len(value) != 42:
            raise ValidationError("Invalid wallet address format. Must be a 42-character hex string starting with 0x.")
        return value.lower()

    def validate(self, data):
        """
        Validate the wallet login data and perform signature verification.
        Handles user creation or retrieval based on wallet address.
        """
        wallet_address = data.get("wallet_address")
        message = data.get("message")
        signature = data.get("signature")

        # Verify the signature (includes replay protection via nonce + timestamp)
        try:
            authenticator = WalletAuthenticator()
            if not authenticator.verify_signature(wallet_address, message, signature):
                raise ValidationError(
                    detail={"signature": "Invalid signature. Signature verification failed."}, code="INVALID_SIGNATURE"
                )
        except ValueError as e:
            # Structured validation errors from replay/timestamp/nonce checks
            raise ValidationError(detail={"message": str(e)}, code=4009)
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            raise ValidationError(detail={"signature": "Signature verification failed."}, code="INVALID_SIGNATURE")

        # Check if user exists or create new one
        # First check if wallet is already associated with another user
        existing_user = _User.objects.filter(wallet_address=wallet_address).first()

        if existing_user:
            # Wallet exists, use existing user
            user = existing_user
            created = False
        else:
            # Wallet doesn't exist, create new user
            user = _User.objects.create(wallet_address=wallet_address, is_verified=False)
            created = True

        # Update last login and add authentication type
        user.last_login = timezone.now()
        user.add_authentication_type(AuthenticationType.WALLET)
        user.save()

        # Prepare user data and provider data
        user_data = model_to_json(user, remove_fields=("password",))
        provider_data = {"provider": "wallet", "wallet_address": user.wallet_address}

        # Generate tokens with custom claims support
        try:
            from blockauth.utils.token import generate_auth_token_with_custom_claims

            access_token, refresh_token = generate_auth_token_with_custom_claims(
                token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
            )
        except ImportError:
            # Fall back to original implementation
            access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))

        # Store all the data for the view to use
        data["user"] = user
        data["created"] = created
        data["user_data"] = user_data
        data["provider_data"] = provider_data
        data["access_token"] = access_token
        data["refresh_token"] = refresh_token

        return data

    def authenticate_user(self):
        """
        Complete authentication process including triggers and logging.
        Returns the authentication result.
        """
        if not hasattr(self, "validated_data"):
            raise ValidationError(
                detail={"non_field_errors": "Serializer must be validated before calling authenticate_user()."}
            )

        user = self.validated_data["user"]
        created = self.validated_data["created"]
        user_data = self.validated_data["user_data"]
        provider_data = self.validated_data["provider_data"]
        access_token = self.validated_data["access_token"]
        refresh_token = self.validated_data["refresh_token"]

        # Trigger post-signup if new user
        if created:
            post_signup_trigger = get_config("POST_SIGNUP_TRIGGER")()
            post_signup_trigger.trigger(context={"user": user_data, "provider_data": provider_data})

        # Trigger post-login
        post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
        post_login_trigger.trigger(context={"user": user_data, "provider_data": provider_data})

        return {
            "user": user,
            "created": created,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_data": user_data,
            "provider_data": provider_data,
        }


class WalletLinkSerializer(serializers.Serializer):
    """
    Validates a wallet link request from an already-authenticated user.

    Performs full signature verification (including replay protection) via
    WalletAuthenticator. Raises WalletConflictError (409) if the address
    belongs to another user, ValidationError (400) if the user already has
    a wallet linked.
    """

    wallet_address = serializers.CharField(max_length=42, help_text="Ethereum wallet address (0x...)")
    message = serializers.CharField(help_text="JSON-encoded message with nonce + timestamp that was signed.")
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

        # 1. Verify signature — replay protection, nonce, timestamp all handled here
        try:
            authenticator = WalletAuthenticator()
            if not authenticator.verify_signature(wallet_address, message, signature):
                raise ValidationError(
                    detail={"signature": "Invalid signature. Signature verification failed."},
                    code="INVALID_SIGNATURE",
                )
        except ValueError as e:
            raise ValidationError(detail={"message": str(e)}, code="INVALID_SIGNATURE")
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            raise ValidationError(
                detail={"signature": "Signature verification failed."},
                code="INVALID_SIGNATURE",
            )

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
        return value

    def validate(self, data):
        """Validate the email add request"""
        # Check if email is already in use by another user
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            if _User.objects.filter(email=data["email"]).exclude(wallet_address=request.user.wallet_address).exists():
                raise ValidationError(detail={"email": "Unable to use this email address."})

            # Check if user already has a verified email
            if request.user.email and request.user.is_verified:
                raise ValidationError(detail={"email": "This account already has a verified email address."})

        return data
