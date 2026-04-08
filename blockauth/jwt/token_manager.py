import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List

import jwt
from rest_framework.exceptions import AuthenticationFailed

from blockauth.utils.config import get_block_auth_user_model, get_config

from .interfaces import CustomClaimsProvider

# Try to import Django timezone, fallback to datetime if not available
try:
    from django.utils import timezone

    def get_current_time():
        return timezone.now()

except ImportError:

    def get_current_time():
        return datetime.utcnow()


logger = logging.getLogger(__name__)


class JWTTokenManager:
    """Enhanced JWT manager with custom claims support.

    Supports both symmetric (HS256) and asymmetric (RS256/ES256) algorithms.
    Key resolution is automatic based on the configured ALGORITHM.
    """

    def __init__(self):
        from blockauth.utils.token import _resolve_keys

        self.algorithm = get_config("ALGORITHM")
        self.signing_key, self.verification_key = _resolve_keys(self.algorithm)
        # Backward compatibility
        self.secret_key = self.signing_key
        self.expiry_hours = get_config("ACCESS_TOKEN_LIFETIME")
        self._claims_providers: List[CustomClaimsProvider] = []

    def register_claims_provider(self, provider: CustomClaimsProvider):
        """Register a custom claims provider"""
        if provider not in self._claims_providers:
            self._claims_providers.append(provider)
            logger.info(f"Registered custom claims provider: {provider.__class__.__name__}")

    def unregister_claims_provider(self, provider: CustomClaimsProvider):
        """Unregister a custom claims provider"""
        if provider in self._claims_providers:
            self._claims_providers.remove(provider)
            logger.info(f"Unregistered custom claims provider: {provider.__class__.__name__}")

    def generate_token(
        self, user_id: str, token_type: str, token_lifetime: timedelta, user_data: Dict[str, Any] = None
    ) -> str:
        """Generate JWT token with base and custom claims"""
        # User-provided data (applied first so base claims can't be overridden)
        extra_claims = dict(user_data) if user_data else {}

        # Base claims (always included — set AFTER extra_claims to prevent override)
        base_claims = {
            "user_id": user_id,
            "jti": str(uuid.uuid4()),
            "exp": get_current_time() + token_lifetime,
            "iat": get_current_time(),
            "type": token_type,
        }

        # Collect custom claims from all registered providers
        custom_claims = {}

        for provider in self._claims_providers:
            try:
                # Get user object for custom claims
                user_model = get_block_auth_user_model()
                user = user_model.objects.get(id=user_id)

                provider_claims = provider.get_custom_claims(user)

                if provider_claims:
                    custom_claims.update(provider_claims)
            except user_model.DoesNotExist:
                logger.warning("User %s not found, skipping claims provider %s", user_id, provider.__class__.__name__)
            except Exception as e:
                logger.error("Error getting custom claims from %s: %s", provider.__class__.__name__, e)

        # Merge all claims: extra_claims < custom_claims < base_claims (base always wins)
        all_claims = {**extra_claims, **custom_claims, **base_claims}

        return jwt.encode(all_claims, self.signing_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate JWT token"""
        try:
            claims = jwt.decode(token, self.verification_key, algorithms=[self.algorithm])

            # Validate custom claims with providers
            for provider in self._claims_providers:
                try:
                    if not provider.validate_custom_claims(claims):
                        logger.warning(f"Custom claims validation failed for {provider.__class__.__name__}")
                        raise jwt.InvalidTokenError("Custom claims validation failed")
                except Exception as e:
                    logger.error(f"Error validating custom claims with {provider.__class__.__name__}: {e}")
                    raise jwt.InvalidTokenError("Custom claims validation failed")

            return claims
        except jwt.ExpiredSignatureError:
            logger.error("Token has expired.")
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise AuthenticationFailed(f"Invalid token: {str(e)}")

    def get_custom_claims(self, token: str) -> Dict[str, Any]:
        """Extract only custom claims from a token"""
        try:
            claims = self.decode_token(token)
            # Remove base claims to get only custom claims
            base_claim_keys = {"user_id", "jti", "exp", "iat", "type"}
            custom_claims = {k: v for k, v in claims.items() if k not in base_claim_keys}
            return custom_claims
        except Exception as e:
            logger.error(f"Error extracting custom claims: {e}")
            return {}

    def generate_tokens_for_user(self, user) -> Dict[str, str]:
        """
        Generate access and refresh tokens for a user.

        Args:
            user: User object with id and email attributes

        Returns:
            Dict with 'access' and 'refresh' token strings
        """
        # Get token lifetimes from config
        access_lifetime = get_config("ACCESS_TOKEN_LIFETIME")
        refresh_lifetime = get_config("REFRESH_TOKEN_LIFETIME")

        # Prepare user data
        user_data = {
            "email": getattr(user, "email", None),
        }

        # Generate access token
        access_token = self.generate_token(
            user_id=str(user.id), token_type="access", token_lifetime=access_lifetime, user_data=user_data
        )

        # Generate refresh token
        refresh_token = self.generate_token(
            user_id=str(user.id), token_type="refresh", token_lifetime=refresh_lifetime, user_data=user_data
        )

        return {"access": access_token, "refresh": refresh_token}


# Global instance
jwt_manager = JWTTokenManager()
