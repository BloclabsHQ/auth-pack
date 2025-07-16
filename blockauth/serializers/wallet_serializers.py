from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.utils import timezone
from django.core.validators import EmailValidator
from blockauth.models.user import AuthenticationType
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.web3.wallet import WalletAuthenticator
from blockauth.utils.generics import model_to_json
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS
import logging

_User = get_block_auth_user_model()
logger = logging.getLogger(__name__)


class WalletLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(
        max_length=42, 
        help_text="Ethereum wallet address (0x...)"
    )
    message = serializers.CharField(
        help_text="Message that was signed by the wallet user."
    )
    signature = serializers.CharField(
        help_text="Ethereum signature (0x-prefixed, 130 hex chars, e.g. 0x1234...)",
        max_length=132
    )

    def validate_wallet_address(self, value):
        """Validate Ethereum wallet address format"""
        if not value.startswith('0x') or len(value) != 42:
            raise ValidationError("Invalid wallet address format. Must be a valid Ethereum address.")
        return value.lower()

    def validate(self, data):
        """
        Validate the wallet login data and perform signature verification.
        Handles user creation or retrieval based on wallet address.
        """
        super().validate(data)
        
        wallet_address = data.get('wallet_address')
        message = data.get('message')
        signature = data.get('signature')

        # Verify the signature
        try:
            authenticator = WalletAuthenticator()
            if not authenticator.verify_signature(wallet_address, message, signature):
                raise ValidationError(
                    detail={'signature': 'Invalid signature. Signature verification failed.'}, 
                    code=4009
                )
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            raise ValidationError(
                detail={'signature': 'Signature verification failed.'}, 
                code=4009
            )

        # Check if user exists or create new one
        user, created = _User.objects.get_or_create(
            wallet_address=wallet_address,
            defaults={'is_verified': False}
        )
        
        if created:
            user.is_verified = False

        # Update last login and add authentication type
        user.last_login = timezone.now()
        user.add_authentication_type(AuthenticationType.WALLET)
        user.save()

        # Prepare user data and provider data
        user_data = model_to_json(user, remove_fields=('password',))
        provider_data = {'provider': 'wallet', 'wallet_address': user.wallet_address}

        # Generate tokens
        access_token, refresh_token = generate_auth_token(
            token_class=AUTH_TOKEN_CLASS(), 
            user_id=user.id.hex
        )

        # Store all the data for the view to use
        data['user'] = user
        data['created'] = created
        data['user_data'] = user_data
        data['provider_data'] = provider_data
        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        
        return data

    def authenticate_user(self):
        """
        Complete authentication process including triggers and logging.
        Returns the authentication result.
        """
        if not hasattr(self, 'validated_data'):
            raise ValidationError("Serializer must be validated first")
        
        user = self.validated_data['user']
        created = self.validated_data['created']
        user_data = self.validated_data['user_data']
        provider_data = self.validated_data['provider_data']
        access_token = self.validated_data['access_token']
        refresh_token = self.validated_data['refresh_token']

        # Trigger post-signup if new user
        if created:
            post_signup_trigger = get_config('POST_SIGNUP_TRIGGER')()
            post_signup_trigger.trigger(context={'user': user_data, 'provider_data': provider_data})

        # Trigger post-login
        post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
        post_login_trigger.trigger(context={'user': user_data, 'provider_data': provider_data})

        return {
            'user': user,
            'created': created,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_data': user_data,
            'provider_data': provider_data,
        }


class WalletEmailAddSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Email address to add and verify"
    )
    verification_type = serializers.ChoiceField(
        choices=["otp", "link"],
        default="otp",
        help_text="Type of verification to send (OTP or link)"
    )

    def validate_email(self, value):
        """Validate email format"""
        try:
            EmailValidator()(value)
        except Exception:
            raise ValidationError("Enter a valid email address.")
        return value

    def validate(self, data):
        """Validate the email add request"""
        super().validate(data)
        
        # Check if email is already in use by another user
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            if _User.objects.filter(email=data['email']).exclude(wallet_address=request.user.wallet_address).exists():
                raise ValidationError("This email is already in use by another account.")
            
            # Check if user already has a verified email
            if request.user.email and request.user.is_verified:
                raise ValidationError("User already has a verified email address.")
        
        return data 