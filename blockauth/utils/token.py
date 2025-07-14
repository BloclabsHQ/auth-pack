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

Configuration:
- JWT_SECRET_KEY: Secret key for token signing (optional, falls back to Django SECRET_KEY)
- ALGORITHM: JWT signing algorithm (defaults to 'HS256')
- ACCESS_TOKEN_LIFETIME: Lifetime for access tokens (defaults to 1 hour)
- REFRESH_TOKEN_LIFETIME: Lifetime for refresh tokens (defaults to 1 day)

Usage:
    from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS
    
    # Generate tokens for a user
    access_token, refresh_token = generate_auth_token(
        token_class=AUTH_TOKEN_CLASS(), 
        user_id=user.id.hex
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


class AbstractToken:
    """
    Abstract base class for token operations.
    
    This class defines the interface that all token implementations must follow.
    It provides a contract for token generation and decoding operations.
    
    Methods:
        generate_token: Generate a new token with specified parameters
        decode_token: Decode and validate an existing token
    """
    
    def generate_token(self, user_id: str, token_type: str, token_lifetime: timedelta) -> str:
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
    
    This class provides JWT token generation and validation functionality using
    the PyJWT library. It supports configurable secret keys and algorithms,
    and includes proper error handling for various token validation scenarios.
    
    Attributes:
        secret_key (str): The secret key used for token signing
        algorithm (str): The JWT algorithm used for signing (e.g., 'HS256')
    
    Configuration:
        JWT_SECRET_KEY: Secret key for token signing (from Django settings)
        ALGORITHM: JWT signing algorithm (defaults to 'HS256')
    """
    
    def __init__(self, secret_key: str = None, algorithm: str = None):
        """
        Initialize the Token instance with secret key and algorithm.
        
        Args:
            secret_key (str, optional): Secret key for token signing. 
                Defaults to JWT_SECRET_KEY from configuration, falls back to SECRET_KEY.
            algorithm (str, optional): JWT signing algorithm. 
                Defaults to ALGORITHM from configuration.
        """
        # Use JWT_SECRET_KEY if provided, otherwise fall back to SECRET_KEY
        if secret_key:
            self.secret_key = secret_key
        else:
            try:
                self.secret_key = get_config('JWT_SECRET_KEY')
            except AttributeError:
                # Fall back to SECRET_KEY if JWT_SECRET_KEY is not configured
                self.secret_key = get_config('SECRET_KEY')
        self.algorithm = algorithm or get_config('ALGORITHM')

    def generate_token(self, user_id: str, token_type: str, token_lifetime: timedelta) -> str:
        """
        Generate a new JWT token with the specified parameters.
        
        Creates a JWT token containing user information, expiration time,
        issued time, and token type. The token is signed using the configured
        secret key and algorithm.
        
        Args:
            user_id (str): The unique identifier of the user (typically user.id.hex)
            token_type (str): Type of token ('access' or 'refresh')
            token_lifetime (timedelta): How long the token should be valid
            
        Returns:
            str: The generated JWT token string
            
        Example:
            token = Token()
            access_token = token.generate_token(
                user_id="user123",
                token_type="access",
                token_lifetime=timedelta(hours=1)
            )
        """
        # Create the token payload with standard JWT claims
        payload = {
            "user_id": user_id,                    # Custom claim: user identifier
            "exp": timezone.now() + token_lifetime, # Standard claim: expiration time
            "iat": timezone.now(),                 # Standard claim: issued at time
            "type": token_type                     # Custom claim: token type
        }
        
        # Encode the payload into a JWT token
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.
        
        Decodes the JWT token and validates its signature, expiration, and format.
        Handles various error conditions with appropriate logging and exceptions.
        
        Args:
            token (str): The JWT token string to decode
            
        Returns:
            Dict[str, Any]: The decoded token payload containing user_id, exp, iat, type
            
        Raises:
            AuthenticationFailed: If the token is invalid, expired, or has an invalid signature
            
        Example:
            token = Token()
            try:
                payload = token.decode_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
                user_id = payload['user_id']
                token_type = payload['type']
            except AuthenticationFailed as e:
                # Handle authentication error
                pass
        """
        try:
            # Decode and verify the token signature
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
            
        except jwt.ExpiredSignatureError:
            # Token has passed its expiration time
            logger.error("Token has expired.")
            raise AuthenticationFailed("Token has expired.")
            
        except jwt.InvalidTokenError:
            # Token is malformed or invalid
            logger.error("Invalid token.")
            raise AuthenticationFailed("Invalid token.")
            
        except jwt.InvalidSignatureError:
            # Token signature verification failed
            logger.error("Invalid signature.")
            raise AuthenticationFailed("Invalid signature.")


def generate_auth_token(token_class: AbstractToken, user_id: str) -> Tuple[str, str]:
    """
    Generate both access and refresh tokens for a user.
    
    This function creates a pair of JWT tokens - an access token for API authentication
    and a refresh token for obtaining new access tokens. Both tokens are generated
    using the same user ID but with different lifetimes and types.
    
    Args:
        token_class (AbstractToken): Token class instance to use for generation
        user_id (str): The unique identifier of the user (typically user.id.hex)
        
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
            user_id=user.id.hex
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
        token_lifetime=get_config('ACCESS_TOKEN_LIFETIME')
    )

    # Generate refresh token with longer lifetime
    refresh_token = token_class.generate_token(
        user_id=user_id,
        token_type="refresh",
        token_lifetime=get_config('REFRESH_TOKEN_LIFETIME')
    )
    
    return access_token, refresh_token


# Default token class instance for the application
AUTH_TOKEN_CLASS = Token