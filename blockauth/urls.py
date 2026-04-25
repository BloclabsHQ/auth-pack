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

from django.urls import path

from blockauth.constants import Features, SocialProviders, URLNames
from blockauth.passkey.views import (
    PasskeyAuthenticationOptionsView,
    PasskeyAuthenticationVerifyView,
    PasskeyCredentialDetailView,
    PasskeyCredentialListView,
    PasskeyRegistrationOptionsView,
    PasskeyRegistrationVerifyView,
)
from blockauth.utils.config import is_social_auth_configured
from blockauth.utils.feature_flags import is_feature_enabled
from blockauth.views.basic_auth_views import (
    AuthRefreshTokenView,
    BasicAuthLoginView,
    EmailChangeConfirmView,
    EmailChangeView,
    PasswordChangeView,
    PasswordlessLoginConfirmView,
    PasswordlessLoginView,
    PasswordResetConfirmView,
    PasswordResetView,
    SignUpConfirmView,
    SignUpResendOTPView,
    SignUpView,
)
from blockauth.apple.views import (
    AppleNativeVerifyView,
    AppleServerToServerNotificationView,
    AppleWebAuthorizeView,
    AppleWebCallbackView,
)
from blockauth.views.facebook_auth_views import FacebookAuthCallbackView, FacebookAuthLoginView
from blockauth.views.google_auth_views import GoogleAuthCallbackView, GoogleAuthLoginView
from blockauth.views.google_native_views import GoogleNativeIdTokenVerifyView
from blockauth.views.linkedin_auth_views import LinkedInAuthCallbackView, LinkedInAuthLoginView
from blockauth.views.wallet_auth_views import (
    WalletAuthLoginView,
    WalletChallengeView,
    WalletEmailAddView,
    WalletLinkView,
    WalletUnlinkView,
)

# Note: All endpoints include trailing slashes for consistency.
# Django's APPEND_SLASH=True setting will automatically redirect
# requests without trailing slashes to the correct URLs.

# URL pattern mappings organized by feature
# Each feature maps to a list of tuples: (url_path, view_class, url_name)
# This allows for dynamic URL generation based on enabled features
URL_PATTERN_MAPPINGS = {
    # User registration endpoints
    Features.SIGNUP: [
        ("signup/", SignUpView, URLNames.SIGNUP),  # Request OTP for signup
        ("signup/otp/resend/", SignUpResendOTPView, URLNames.SIGNUP_OTP_RESEND),  # Resend OTP
        ("signup/confirm/", SignUpConfirmView, URLNames.SIGNUP_CONFIRM),  # Confirm signup
    ],
    # Authentication endpoints
    Features.BASIC_LOGIN: [
        ("login/basic/", BasicAuthLoginView, URLNames.BASIC_LOGIN),  # Email/password login
    ],
    Features.PASSWORDLESS_LOGIN: [
        ("login/passwordless/", PasswordlessLoginView, URLNames.PASSWORDLESS_LOGIN),  # Request OTP
        (
            "login/passwordless/confirm/",
            PasswordlessLoginConfirmView,
            URLNames.PASSWORDLESS_LOGIN_CONFIRM,
        ),  # Confirm OTP
    ],
    Features.WALLET_LOGIN: [
        # Challenge route must be declared before the login route so clients
        # never hit a slash-eating wildcard. Order doesn't matter for Django
        # URL resolution, but it keeps the pair visibly grouped.
        ("login/wallet/challenge/", WalletChallengeView, URLNames.WALLET_LOGIN_CHALLENGE),
        ("login/wallet/", WalletAuthLoginView, URLNames.WALLET_LOGIN),  # SIWE-backed wallet auth (#90)
    ],
    Features.TOKEN_REFRESH: [
        ("token/refresh/", AuthRefreshTokenView, URLNames.TOKEN_REFRESH),  # Refresh JWT tokens
    ],
    # Password management endpoints
    Features.PASSWORD_RESET: [
        ("password/reset/", PasswordResetView, URLNames.PASSWORD_RESET),  # Request reset OTP
        ("password/reset/confirm/", PasswordResetConfirmView, URLNames.PASSWORD_RESET_CONFIRM),  # Confirm reset
    ],
    Features.PASSWORD_CHANGE: [
        ("password/change/", PasswordChangeView, URLNames.PASSWORD_CHANGE),  # Change password (authenticated)
    ],
    # Email management endpoints
    Features.EMAIL_CHANGE: [
        ("email/change/", EmailChangeView, URLNames.EMAIL_CHANGE),  # Request email change OTP
        ("email/change/confirm/", EmailChangeConfirmView, URLNames.EMAIL_CHANGE_CONFIRM),  # Confirm email change
    ],
    # Wallet management endpoints
    Features.WALLET_EMAIL_ADD: [
        ("wallet/email/add/", WalletEmailAddView, URLNames.WALLET_EMAIL_ADD),  # Add email to wallet account
    ],
    Features.WALLET_LINK: [
        ("wallet/link/", WalletLinkView, URLNames.WALLET_LINK),
        ("wallet/unlink/", WalletUnlinkView, URLNames.WALLET_UNLINK),
    ],
    # Apple Sign-In endpoints (web flow + native verify + S2S notifications).
    # Gated by FEATURES.APPLE_LOGIN — independent of SOCIAL_AUTH so integrators
    # can enable Apple without enabling the Google/Facebook/LinkedIn web flows.
    Features.APPLE_LOGIN: [
        ("apple/", AppleWebAuthorizeView, URLNames.APPLE_LOGIN),  # 302 to Apple authorize
        ("apple/callback/", AppleWebCallbackView, URLNames.APPLE_CALLBACK),  # form_post callback
        ("apple/verify/", AppleNativeVerifyView, URLNames.APPLE_NATIVE_VERIFY),  # native id_token verify
        (
            "apple/notifications/",
            AppleServerToServerNotificationView,
            URLNames.APPLE_NOTIFICATIONS,
        ),  # S2S notification webhook
    ],
    # Google native id_token verify (Credential Manager / iOS / Web One Tap).
    # Separate from SOCIAL_AUTH because native verify needs no redirect/state
    # cookie — integrators may ship native-only without enabling the web flows.
    Features.GOOGLE_NATIVE_LOGIN: [
        (
            "google/native/verify/",
            GoogleNativeIdTokenVerifyView,
            URLNames.GOOGLE_NATIVE_VERIFY,
        ),
    ],
    # Passkey/WebAuthn authentication endpoints
    Features.PASSKEY_AUTH: [
        (
            "passkey/register/options/",
            PasskeyRegistrationOptionsView,
            URLNames.PASSKEY_REGISTER_OPTIONS,
        ),  # Get registration options
        (
            "passkey/register/verify/",
            PasskeyRegistrationVerifyView,
            URLNames.PASSKEY_REGISTER_VERIFY,
        ),  # Verify registration
        (
            "passkey/auth/options/",
            PasskeyAuthenticationOptionsView,
            URLNames.PASSKEY_AUTH_OPTIONS,
        ),  # Get authentication options
        (
            "passkey/auth/verify/",
            PasskeyAuthenticationVerifyView,
            URLNames.PASSKEY_AUTH_VERIFY,
        ),  # Verify authentication
        ("passkey/credentials/", PasskeyCredentialListView, URLNames.PASSKEY_CREDENTIALS),  # List user's passkeys
        (
            "passkey/credentials/<uuid:credential_id>/",
            PasskeyCredentialDetailView,
            URLNames.PASSKEY_CREDENTIAL_DETAIL,
        ),  # Manage single passkey
    ],
}

# Social authentication URL pattern mappings
# These endpoints are only available if SOCIAL_AUTH feature is enabled
# and the respective provider is configured in BLOCK_AUTH_SETTINGS['AUTH_PROVIDERS']
SOCIAL_URL_PATTERN_MAPPINGS = {
    SocialProviders.GOOGLE: [
        ("google/", GoogleAuthLoginView, URLNames.GOOGLE_LOGIN),  # Initiate Google OAuth flow
        ("google/callback/", GoogleAuthCallbackView, URLNames.GOOGLE_CALLBACK),  # Handle Google OAuth callback
    ],
    SocialProviders.FACEBOOK: [
        ("facebook/", FacebookAuthLoginView, URLNames.FACEBOOK_LOGIN),  # Initiate Facebook OAuth flow
        ("facebook/callback/", FacebookAuthCallbackView, URLNames.FACEBOOK_CALLBACK),  # Handle Facebook OAuth callback
    ],
    SocialProviders.LINKEDIN: [
        ("linkedin/", LinkedInAuthLoginView, URLNames.LINKEDIN_LOGIN),  # Initiate LinkedIn OAuth flow
        ("linkedin/callback/", LinkedInAuthCallbackView, URLNames.LINKEDIN_CALLBACK),  # Handle LinkedIn OAuth callback
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

    Example:
        If SIGNUP feature is enabled, the following URLs will be added:
        - /auth/signup/
        - /auth/signup/otp/resend/
        - /auth/signup/confirm/

        If SIGNUP feature is disabled, none of these URLs will be available.
    """
    urlpatterns = []

    # Build regular feature-based URLs
    # Iterate through all defined features and add URLs only for enabled ones
    for feature, patterns in URL_PATTERN_MAPPINGS.items():
        if is_feature_enabled(feature):
            for url_path, view_class, url_name in patterns:
                urlpatterns.append(path(url_path, view_class.as_view(), name=url_name))

    # Build social authentication URLs
    # Social auth requires both the SOCIAL_AUTH feature flag and provider configuration
    if is_feature_enabled(Features.SOCIAL_AUTH):
        for provider, patterns in SOCIAL_URL_PATTERN_MAPPINGS.items():
            if is_social_auth_configured(provider):
                for url_path, view_class, url_name in patterns:
                    urlpatterns.append(path(url_path, view_class.as_view(), name=url_name))

    return urlpatterns


# Generate the final URL patterns list
# This is the main export that Django will use for URL routing
urlpatterns = build_urlpatterns()
