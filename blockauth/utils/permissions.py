from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from blockauth.utils.config import get_config


class EmailVerificationPermission(BasePermission):
    """
    Permission class to check if users have verified email when required.
    This permission should be used on non-auth endpoints to restrict access
    for users who haven't verified their email.

    The permission checks:
    1. If email verification is required (configurable)
    2. If the user has an email address
    3. If the user's email is verified (is_verified=True)

    Configuration:
        EMAIL_VERIFICATION_REQUIRED: Boolean flag to enable/disable this permission
    """

    def has_permission(self, request, view):
        # If email verification is not required, allow all requests
        try:
            if not get_config("EMAIL_VERIFICATION_REQUIRED"):
                return True
        except AttributeError:
            # If EMAIL_VERIFICATION_REQUIRED is not configured, default to False (not required)
            return True

        # If user is not authenticated, let other permission classes handle it
        if not request.user.is_authenticated:
            return True

        # Check if user has an email address
        if not request.user.email:
            raise PermissionDenied("Email address required. Please add an email address to access this endpoint.")

        # Check if user's email is verified
        if not request.user.is_verified:
            raise PermissionDenied(
                "Email verification required. Please verify your email address to access this endpoint."
            )

        return True
