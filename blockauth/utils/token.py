"""
JWT Token Management Module

This module provides JWT (JSON Web Token) functionality for authentication in the BlockAuth system.
It includes classes and functions for generating, encoding, and decoding JWT tokens used for
user authentication and session management.

Key Features:
- Abstract token interface for extensibility
- JWT token generation with configurable algorithms and secret keys
- Token validation with proper error handling
- Support for both access and refresh tokens
- Configurable token lifetimes
- Supports both symmetric (HS256) and asymmetric (RS256/ES256) algorithms

Configuration:
- ALGORITHM: JWT signing algorithm ('HS256', 'RS256', 'ES256', etc.)
- Symmetric (HS256): set JWT_SECRET_KEY (or falls back to SECRET_KEY)
- Asymmetric (RS256/ES256): set JWT_PRIVATE_KEY (signing) and JWT_PUBLIC_KEY (verification)
- ACCESS_TOKEN_LIFETIME: Lifetime for access tokens (defaults to 1 hour)
- REFRESH_TOKEN_LIFETIME: Lifetime for refresh tokens (defaults to 1 day)

Usage:
    from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

    # Generate tokens for a user
    access_token, refresh_token = generate_auth_token(
        token_class=AUTH_TOKEN_CLASS(),
        user_id=str(user.id)
    )

    # Decode a token
    token_instance = AUTH_TOKEN_CLASS()
    payload = token_instance.decode_token(token_string)
"""

import logging
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any, Union

import jwt
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from blockauth.utils.config import get_config

logger = logging.getLogger(__name__)

# Algorithms that use asymmetric keys (private key for signing, public key for verification)
_ASYMMETRIC_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


def _resolve_keys(algorithm: str, explicit_secret_key=None):
    """
    Resolve signing and verification keys based on algorithm type.

    Symmetric (HS256): signing_key = verification_key = JWT_SECRET_KEY
    Asymmetric (RS256/ES256): signing_key = JWT_PRIVATE_KEY, verification_key = JWT_PUBLIC_KEY

    Returns:
        tuple: (signing_key, verification_key)
    """
    if explicit_secret_key:
        return explicit_secret_key, explicit_secret_key

    if algorithm in _ASYMMETRIC_ALGORITHMS:
        private_key = get_config("JWT_PRIVATE_KEY")
        public_key = get_config("JWT_PUBLIC_KEY")
        if not private_key or not public_key:
            raise ValueError(
                f"Algorithm {algorithm} requires both JWT_PRIVATE_KEY and JWT_PUBLIC_KEY "
                f"in BLOCK_AUTH_SETTINGS."
            )
        return private_key, public_key

    # Symmetric algorithm — same key for both
    try:
        secret = get_config("JWT_SECRET_KEY")
    except AttributeError:
        secret = get_config("SECRET_KEY")
    return secret, secret


class AbstractToken:
    """
    Abstract base class for token operations.
    
    This class defines the interface that all token implementations must follow.
    It provides a contract for token generation and decoding operations.
    
    Methods:
        generate_token: Generate a new token with specified parameters
        decode_token: Decode and validate an existing token
    """
    
    def generate_token(self, user_id: str, token_type: str, token_lifetime: timedelta, user_data: Dict[str, Any] = None) -> str:
        """
        Generate a new token with the specified parameters.
        
        Args:
            user_id (str): The unique identifier of the user
            token_type (str): Type of token ('access' or 'refresh')
            token_lifetime (timedelta): How long the token should be valid
            
        Returns:
            str: The generated JWT token string
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError

    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate an existing token.
        
        Args:
            token (str): The JWT token string to decode
            
        Returns:
            Dict[str, Any]: The decoded token payload
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError


class Token(AbstractToken):
    """
    JWT Token implementation for authentication.

    Supports both symmetric (HS256) and asymmetric (RS256/ES256) algorithms.
    Key resolution is automatic based on the configured algorithm:
    - HS256: uses JWT_SECRET_KEY for both signing and verification
    - RS256/ES256: uses JWT_PRIVATE_KEY for signing, JWT_PUBLIC_KEY for verification

    Attributes:
        signing_key: Key used for token signing
        verification_key: Key used for token verification
        algorithm (str): The JWT algorithm (e.g., 'HS256', 'RS256')

    Backward compatible: existing HS256 configurations work without changes.
    """

    def __init__(self, secret_key: str = None, algorithm: str = None):
        """
        Initialize the Token instance.

        Args:
            secret_key (str, optional): Explicit key for both signing and verification
                (symmetric override). If provided, used directly regardless of algorithm.
            algorithm (str, optional): JWT signing algorithm.
                Defaults to ALGORITHM from configuration.
        """
        self.algorithm = algorithm or get_config("ALGORITHM")
        self.signing_key, self.verification_key = _resolve_keys(
            self.algorithm, explicit_secret_key=secret_key
        )
        # Backward compatibility — existing code may read self.secret_key
        self.secret_key = self.signing_key

    def generate_token(self, user_id: str, token_type: str, token_lifetime: timedelta, user_data: Dict[str, Any] = None) -> str:
        """
        Generate a new JWT token.

        Args:
            user_id (str): The unique identifier of the user
            token_type (str): Type of token ('access' or 'refresh')
            token_lifetime (timedelta): How long the token should be valid
            user_data (Dict[str, Any], optional): Additional user data to include in token

        Returns:
            str: The generated JWT token string
        """
        payload = {
            "user_id": user_id,
            "exp": timezone.now() + token_lifetime,
            "iat": timezone.now(),
            "type": token_type,
        }
        if user_data:
            payload.update(user_data)

        return jwt.encode(payload, self.signing_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.

        Uses the verification key (public key for RS256, shared secret for HS256).

        Args:
            token (str): The JWT token string to decode

        Returns:
            Dict[str, Any]: The decoded token payload

        Raises:
            AuthenticationFailed: If the token is invalid, expired, or has an invalid signature
        """
        try:
            payload = jwt.decode(token, self.verification_key, algorithms=[self.algorithm])
            return payload

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired.")
            raise AuthenticationFailed("Token has expired.")

        except jwt.InvalidSignatureError:
            logger.error("Invalid signature.")
            raise AuthenticationFailed("Invalid signature.")

        except jwt.InvalidTokenError:
            logger.error("Invalid token.")
            raise AuthenticationFailed("Invalid token.")


def generate_auth_token(token_class: AbstractToken, user_id: str, user_data: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    Generate both access and refresh tokens for a user.
    
    This function creates a pair of JWT tokens - an access token for API authentication
    and a refresh token for obtaining new access tokens. Both tokens are generated
    using the same user ID but with different lifetimes and types.
    
    Args:
        token_class (AbstractToken): Token class instance to use for generation
        user_id (str): The unique identifier of the user (typically str(user.id))
        user_data (Dict[str, Any], optional): Additional user data to include in tokens
        
    Returns:
        Tuple[str, str]: A tuple containing (access_token, refresh_token)
        
    Configuration:
        ACCESS_TOKEN_LIFETIME: Lifetime for access tokens (from Django settings)
        REFRESH_TOKEN_LIFETIME: Lifetime for refresh tokens (from Django settings)
        
    Example:
        from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS
        
        # Generate tokens for a user
        access_token, refresh_token = generate_auth_token(
            token_class=AUTH_TOKEN_CLASS(),
            user_id=str(user.id)
        )
        
        # Use tokens in API responses
        return {
            "access": access_token,
            "refresh": refresh_token
        }
    """
    # Generate access token with shorter lifetime
    access_token = token_class.generate_token(
        user_id=user_id,
        token_type="access",
        token_lifetime=get_config('ACCESS_TOKEN_LIFETIME'),
        user_data=user_data
    )

    # Generate refresh token with longer lifetime (minimal payload)
    refresh_token = token_class.generate_token(
        user_id=user_id,
        token_type="refresh",
        token_lifetime=get_config('REFRESH_TOKEN_LIFETIME')
    )
    
    return access_token, refresh_token


# Default token class instance for the application
AUTH_TOKEN_CLASS = Token

# Enhanced token generation function with custom claims support
def generate_auth_token_with_custom_claims(token_class: AbstractToken, user_id: str, user_data: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    Generate both access and refresh tokens for a user with custom claims support.
    
    This function creates a pair of JWT tokens - an access token for API authentication
    and a refresh token for obtaining new access tokens. Both tokens are generated
    using the same user ID but with different lifetimes and types.
    
    Args:
        token_class (AbstractToken): Token class instance to use for generation
        user_id (str): The unique identifier of the user (typically str(user.id))
        user_data (Dict[str, Any], optional): Additional user data to include in tokens
        
    Returns:
        Tuple[str, str]: A tuple containing (access_token, refresh_token)
        
    Configuration:
        ACCESS_TOKEN_LIFETIME: Lifetime for access tokens (from Django settings)
        REFRESH_TOKEN_LIFETIME: Lifetime for refresh tokens (from Django settings)
        
    Example:
        from blockauth.utils.token import generate_auth_token_with_custom_claims, AUTH_TOKEN_CLASS
        
        # Generate tokens for a user with custom claims
        access_token, refresh_token = generate_auth_token_with_custom_claims(
            token_class=AUTH_TOKEN_CLASS(),
            user_id=str(user.id)
        )
        
        # Use tokens in API responses
        return {
            "access": access_token,
            "refresh": refresh_token
        }
    """
    # Try to use enhanced JWT manager if available
    logger.info("🔍 Attempting to use enhanced JWT system...")
    
    try:
        logger.info("🔍 Importing JWT manager...")
        from blockauth.jwt.token_manager import jwt_manager
        logger.info("✅ Successfully imported JWT manager")
        
        logger.info("🔍 Importing user model...")
        from blockauth.utils.config import get_block_auth_user_model
        logger.info("✅ Successfully imported user model")
        
        # Get the user object from user_id
        user_model = get_block_auth_user_model()
        try:
            user = user_model.objects.get(id=user_id)
            logger.info(f"✅ Found user: {user.email}")
        except user_model.DoesNotExist:
            logger.warning(f"User with id {user_id} not found, using fallback implementation")
            return generate_auth_token(token_class, user_id, user_data)
        
        # Check if claims providers are registered
        logger.info(f"✅ JWT manager has {len(jwt_manager._claims_providers)} claims providers registered")
        for i, provider in enumerate(jwt_manager._claims_providers):
            logger.info(f"  Provider {i}: {provider.__class__.__name__}")
        
        # Generate access token with custom claims
        logger.info("✅ Generating access token with custom claims...")
        access_token = jwt_manager.generate_token(
            user_id=user_id,
            token_type="access",
            token_lifetime=get_config('ACCESS_TOKEN_LIFETIME'),
            user_data=user_data
        )

        # Generate refresh token with longer lifetime (minimal payload, no custom claims)
        logger.info("✅ Generating refresh token...")
        refresh_token = jwt_manager.generate_token(
            user_id=user_id,
            token_type="refresh",
            token_lifetime=get_config('REFRESH_TOKEN_LIFETIME')
        )
        
        logger.info("✅ Successfully generated tokens with custom claims")
        return access_token, refresh_token
        
    except ImportError as e:
        # Fall back to original implementation if enhanced system is not available
        logger.error(f"❌ ImportError in enhanced JWT system: {e}")
        logger.error(f"❌ ImportError type: {type(e)}")
        import traceback
        traceback.print_exc()
        logger.warning("⚠️ Falling back to original implementation due to ImportError")
        return generate_auth_token(token_class, user_id, user_data)
    except Exception as e:
        # Fall back to original implementation if there's any other error
        logger.error(f"❌ Exception in enhanced JWT system: {e}")
        logger.error(f"❌ Exception type: {type(e)}")
        import traceback
        traceback.print_exc()
        logger.warning("⚠️ Falling back to original implementation due to Exception")
        return generate_auth_token(token_class, user_id, user_data)