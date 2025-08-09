"""
BlockAuth URL Configuration

This module defines the URL patterns for BlockAuth authentication endpoints.
URLs are dynamically generated based on enabled features in BLOCK_AUTH_SETTINGS.

Features:
- Feature-based URL generation using BLOCK_AUTH_SETTINGS['FEATURES']
- Social authentication endpoints (Google, Facebook, LinkedIn)
- Consistent trailing slash handling
- Type-safe URL names using constants

Usage:
    Include this module in your Django project's urls.py:
    path('auth/', include('blockauth.urls'))

Configuration:
    Control which endpoints are available by setting feature flags in settings.py:
    BLOCK_AUTH_SETTINGS = {
        'FEATURES': {
            'SIGNUP': True,
            'EMAIL_CHANGE': False,  # Disable email change endpoints
            # ... other features
        }
    }
"""

from importlib import import_module
from django.urls import path

from blockauth.utils.config import is_social_auth_configured
from blockauth.utils.feature_flags import is_feature_enabled
from blockauth.constants import Features, URLNames, SocialProviders


def _import_string(dotted_path: str):
    module_path, attr_name = dotted_path.rsplit('.', 1)
    module = import_module(module_path)
    return getattr(module, attr_name)


# Note: All endpoints include trailing slashes for consistency.
# Django's APPEND_SLASH=True setting will automatically redirect
# requests without trailing slashes to the correct URLs.

# URL pattern mappings organized by feature
# Each feature maps to a list of tuples: (url_path, view_class_path, url_name)
# This allows for dynamic URL generation based on enabled features and defers imports
URL_PATTERN_MAPPINGS = {
    # User registration endpoints
    Features.SIGNUP: [
        ('signup/', 'blockauth.views.basic_auth_views.SignUpView', URLNames.SIGNUP),
        ('signup/otp/resend/', 'blockauth.views.basic_auth_views.SignUpResendOTPView', URLNames.SIGNUP_OTP_RESEND),
        ('signup/confirm/', 'blockauth.views.basic_auth_views.SignUpConfirmView', URLNames.SIGNUP_CONFIRM),
    ],

    # Authentication endpoints
    Features.BASIC_LOGIN: [
        ('login/basic/', 'blockauth.views.basic_auth_views.BasicAuthLoginView', URLNames.BASIC_LOGIN),
    ],
    Features.PASSWORDLESS_LOGIN: [
        ('login/passwordless/', 'blockauth.views.basic_auth_views.PasswordlessLoginView', URLNames.PASSWORDLESS_LOGIN),
        ('login/passwordless/confirm/', 'blockauth.views.basic_auth_views.PasswordlessLoginConfirmView', URLNames.PASSWORDLESS_LOGIN_CONFIRM),
    ],
    Features.WALLET_LOGIN: [
        ('login/wallet/', 'blockauth.views.wallet_auth_views.WalletAuthLoginView', URLNames.WALLET_LOGIN),
    ],
    Features.TOKEN_REFRESH: [
        ('token/refresh/', 'blockauth.views.basic_auth_views.AuthRefreshTokenView', URLNames.TOKEN_REFRESH),
    ],

    # Password management endpoints
    Features.PASSWORD_RESET: [
        ('password/reset/', 'blockauth.views.basic_auth_views.PasswordResetView', URLNames.PASSWORD_RESET),
        ('password/reset/confirm/', 'blockauth.views.basic_auth_views.PasswordResetConfirmView', URLNames.PASSWORD_RESET_CONFIRM),
    ],
    Features.PASSWORD_CHANGE: [
        ('password/change/', 'blockauth.views.basic_auth_views.PasswordChangeView', URLNames.PASSWORD_CHANGE),
    ],

    # Email management endpoints
    Features.EMAIL_CHANGE: [
        ('email/change/', 'blockauth.views.basic_auth_views.EmailChangeView', URLNames.EMAIL_CHANGE),
        ('email/change/confirm/', 'blockauth.views.basic_auth_views.EmailChangeConfirmView', URLNames.EMAIL_CHANGE_CONFIRM),
    ],

    # Wallet management endpoints
    Features.WALLET_EMAIL_ADD: [
        ('wallet/email/add/', 'blockauth.views.wallet_auth_views.WalletEmailAddView', URLNames.WALLET_EMAIL_ADD),
    ],
}

# Social authentication URL pattern mappings (deferred imports)
SOCIAL_URL_PATTERN_MAPPINGS = {
    SocialProviders.GOOGLE: [
        ('google/', 'blockauth.views.google_auth_views.GoogleAuthLoginView', URLNames.GOOGLE_LOGIN),
        ('google/callback/', 'blockauth.views.google_auth_views.GoogleAuthCallbackView', URLNames.GOOGLE_CALLBACK),
    ],
    SocialProviders.FACEBOOK: [
        ('facebook/', 'blockauth.views.facebook_auth_views.FacebookAuthLoginView', URLNames.FACEBOOK_LOGIN),
        ('facebook/callback/', 'blockauth.views.facebook_auth_views.FacebookAuthCallbackView', URLNames.FACEBOOK_CALLBACK),
    ],
    SocialProviders.LINKEDIN: [
        ('linkedin/', 'blockauth.views.linkedin_auth_views.LinkedInAuthLoginView', URLNames.LINKEDIN_LOGIN),
        ('linkedin/callback/', 'blockauth.views.linkedin_auth_views.LinkedInAuthCallbackView', URLNames.LINKEDIN_CALLBACK),
    ],
}


def build_urlpatterns():
    """
    Build URL patterns based on enabled features.

    This function dynamically generates Django URL patterns by:
    1. Checking which features are enabled in BLOCK_AUTH_SETTINGS['FEATURES']
    2. Adding URL patterns only for enabled features
    3. Handling social authentication providers separately

    Returns:
        list: List of Django URL patterns (path objects)
    """
    urlpatterns = []

    # Build regular feature-based URLs
    for feature, patterns in URL_PATTERN_MAPPINGS.items():
        if is_feature_enabled(feature):
            for url_path, view_path, url_name in patterns:
                view_class = _import_string(view_path)
                urlpatterns.append(path(url_path, view_class.as_view(), name=url_name))

    # Build social authentication URLs
    if is_feature_enabled(Features.SOCIAL_AUTH):
        for provider, patterns in SOCIAL_URL_PATTERN_MAPPINGS.items():
            if is_social_auth_configured(provider):
                for url_path, view_path, url_name in patterns:
                    view_class = _import_string(view_path)
                    urlpatterns.append(path(url_path, view_class.as_view(), name=url_name))

    return urlpatterns


# Generate the final URL patterns list
urlpatterns = build_urlpatterns()

