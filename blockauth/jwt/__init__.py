"""
JWT Token Management with Custom Claims Support

This module provides enhanced JWT functionality with support for custom claims
through a provider interface system.
"""

from .interfaces import CustomClaimsProvider
from .token_manager import JWTTokenManager, jwt_manager

__all__ = ['CustomClaimsProvider', 'JWTTokenManager', 'jwt_manager']
