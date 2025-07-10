from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from blockauth.utils.config import get_config


class WalletEmailVerificationPermission(BasePermission):
    """
    Permission class to check if wallet users have verified email when required.
    This permission should be used on non-auth endpoints to restrict access
    for wallet users who haven't verified their email.
    """
    
    def has_permission(self, request, view):
        # If wallet email verification is not required, allow all requests
        if not get_config('WALLET_EMAIL_REQUIRED'):
            return True
        
        # If user is not authenticated, let other permission classes handle it
        if not request.user.is_authenticated:
            return True
        
        # Check if user is a wallet user (has wallet_address)
        if not request.user.wallet_address:
            return True
        
        # For wallet users, check if they have a verified email
        if not request.user.email or not request.user.is_verified:
            raise PermissionDenied(
                "Email verification required. Please add and verify your email address to access this endpoint."
            )
        
        return True 