"""
Core constants for BlockAuth package.

This module defines all core constants used throughout the BlockAuth package,
including feature flags, configuration keys, error messages, and URL names.

Constants are organized into logical groups:
- Features: Feature flag names for enabling/disabling functionality
- SocialProviders: Social authentication provider names
- ConfigKeys: Configuration setting keys
- ErrorMessages: Standard error messages
- URLNames: URL pattern names for reverse() lookups

Usage:
    from blockauth.constants import Features, URLNames
    
    # Check if a feature is enabled
    if is_feature_enabled(Features.SIGNUP):
        # Show signup form
        pass
    
    # Get URL by name
    signup_url = reverse(URLNames.SIGNUP)
    
    # Use in configuration
    BLOCK_AUTH_SETTINGS = {
        'FEATURES': {
            Features.SIGNUP: True,
            Features.EMAIL_CHANGE: False,
        }
    }
"""

# Feature Flag Constants
class Features:
    """
    Feature flag constants for BlockAuth.
    
    These constants define the available features that can be enabled/disabled
    in BLOCK_AUTH_SETTINGS['FEATURES']. Each feature controls a group of related
    endpoints and functionality.
    
    Usage:
        from blockauth.constants import Features
        from blockauth.utils.feature_flags import is_feature_enabled
        
        if is_feature_enabled(Features.SIGNUP):
            # Show signup functionality
            pass
    """
    
    # Core authentication features
    SIGNUP = 'SIGNUP'                    # User registration with email/password
    BASIC_LOGIN = 'BASIC_LOGIN'          # Email/password authentication
    PASSWORDLESS_LOGIN = 'PASSWORDLESS_LOGIN'  # OTP-based authentication
    WALLET_LOGIN = 'WALLET_LOGIN'        # Web3 wallet authentication
    TOKEN_REFRESH = 'TOKEN_REFRESH'      # JWT token refresh functionality
    
    # Password management features
    PASSWORD_RESET = 'PASSWORD_RESET'    # Password reset via OTP
    PASSWORD_CHANGE = 'PASSWORD_CHANGE'  # Password change for authenticated users
    
    # Email management features
    EMAIL_CHANGE = 'EMAIL_CHANGE'        # Email address change functionality
    EMAIL_VERIFICATION = 'EMAIL_VERIFICATION'  # Email verification requirement
    
    # Wallet management features
    WALLET_EMAIL_ADD = 'WALLET_EMAIL_ADD'  # Add email to wallet accounts
    
    # Social authentication features
    SOCIAL_AUTH = 'SOCIAL_AUTH'          # Master switch for social authentication
    
    @classmethod
    def all_features(cls):
        """
        Get all available feature constants.
        
        Returns:
            list: List of all feature constant values
            
        Usage:
            for feature in Features.all_features():
                print(f"Feature: {feature}")
        """
        return [
            cls.SIGNUP,
            cls.BASIC_LOGIN,
            cls.PASSWORDLESS_LOGIN,
            cls.WALLET_LOGIN,
            cls.TOKEN_REFRESH,
            cls.PASSWORD_RESET,
            cls.PASSWORD_CHANGE,
            cls.EMAIL_CHANGE,
            cls.EMAIL_VERIFICATION,
            cls.WALLET_EMAIL_ADD,
            cls.SOCIAL_AUTH,
        ]


# Social Auth Provider Constants
class SocialProviders:
    """
    Social authentication provider constants.
    
    These constants define the supported social authentication providers.
    Each provider requires configuration in BLOCK_AUTH_SETTINGS['AUTH_PROVIDERS'].
    
    Usage:
        from blockauth.constants import SocialProviders
        from blockauth.utils.config import is_social_auth_configured
        
        if is_social_auth_configured(SocialProviders.GOOGLE):
            # Google OAuth is configured
            pass
    """
    GOOGLE = 'google'      # Google OAuth2 provider
    FACEBOOK = 'facebook'  # Facebook OAuth2 provider
    LINKEDIN = 'linkedin'  # LinkedIn OAuth2 provider
    
    @classmethod
    def all_providers(cls):
        """
        Get all available social provider constants.
        
        Returns:
            list: List of all social provider constant values
            
        Usage:
            for provider in SocialProviders.all_providers():
                print(f"Provider: {provider}")
        """
        return [cls.GOOGLE, cls.FACEBOOK, cls.LINKEDIN]


# Configuration Keys
class ConfigKeys:
    """
    Configuration key constants for BLOCK_AUTH_SETTINGS.
    
    These constants define the valid configuration keys that can be used
    in the BLOCK_AUTH_SETTINGS dictionary in Django settings.
    
    Usage:
        from blockauth.constants import ConfigKeys
        
        BLOCK_AUTH_SETTINGS = {
            ConfigKeys.FEATURES: {...},
            ConfigKeys.ACCESS_TOKEN_LIFETIME: timedelta(hours=1),
        }
    """
    # Feature configuration
    FEATURES = 'FEATURES'                    # Feature flags dictionary
    
    # Authentication providers
    AUTH_PROVIDERS = 'AUTH_PROVIDERS'        # Social auth provider configuration
    
    # JWT token configuration
    ACCESS_TOKEN_LIFETIME = 'ACCESS_TOKEN_LIFETIME'    # Access token validity period
    REFRESH_TOKEN_LIFETIME = 'REFRESH_TOKEN_LIFETIME'  # Refresh token validity period
    ALGORITHM = 'ALGORITHM'                  # JWT signing algorithm
    AUTH_HEADER_NAME = 'AUTH_HEADER_NAME'    # HTTP header for JWT tokens
    USER_ID_FIELD = 'USER_ID_FIELD'          # User model field for JWT payload
    SECRET_KEY = 'SECRET_KEY'                # JWT signing secret key
    
    # OTP configuration
    OTP_VALIDITY = 'OTP_VALIDITY'            # OTP expiration time
    OTP_LENGTH = 'OTP_LENGTH'                # Number of digits in OTP
    
    # Rate limiting
    REQUEST_LIMIT = 'REQUEST_LIMIT'          # Rate limiting configuration
    
    # Email verification
    EMAIL_VERIFICATION_REQUIRED = 'EMAIL_VERIFICATION_REQUIRED'  # Require email verification
    
    # Trigger classes
    POST_SIGNUP_TRIGGER = 'POST_SIGNUP_TRIGGER'        # Post-signup trigger class
    PRE_SIGNUP_TRIGGER = 'PRE_SIGNUP_TRIGGER'          # Pre-signup trigger class
    POST_LOGIN_TRIGGER = 'POST_LOGIN_TRIGGER'          # Post-login trigger class
    
    # Utility classes
    DEFAULT_NOTIFICATION_CLASS = 'DEFAULT_NOTIFICATION_CLASS'  # Notification handler class
    BLOCK_AUTH_LOGGER_CLASS = 'BLOCK_AUTH_LOGGER_CLASS'        # Logger class


# Error Messages
class ErrorMessages:
    """Error message constants."""
    FEATURE_DISABLED = "This feature is currently disabled"
    INVALID_FEATURE = "Invalid feature name"
    CONFIGURATION_ERROR = "Feature configuration error"
    DEPENDENCY_ERROR = "Feature dependency not met"


# URL Names
class URLNames:
    """URL name constants."""
    # Signup
    SIGNUP = 'signup'
    SIGNUP_OTP_RESEND = 'signup-otp-resend'
    SIGNUP_CONFIRM = 'signup-confirm'
    
    # Login
    BASIC_LOGIN = 'basic-login'
    PASSWORDLESS_LOGIN = 'passwordless-login'
    PASSWORDLESS_LOGIN_CONFIRM = 'passwordless-login-confirm'
    WALLET_LOGIN = 'wallet-login'
    TOKEN_REFRESH = 'refresh-token'
    
    # Password
    PASSWORD_RESET = 'password-reset'
    PASSWORD_RESET_CONFIRM = 'password-reset-confirm'
    PASSWORD_CHANGE = 'change-password'
    
    # Email
    EMAIL_CHANGE = 'email-change'
    EMAIL_CHANGE_CONFIRM = 'confirm-email-change'
    
    # Wallet
    WALLET_EMAIL_ADD = 'wallet-email-add'
    
    # Social Auth
    GOOGLE_LOGIN = 'google-login'
    GOOGLE_CALLBACK = 'google-login-callback'
    FACEBOOK_LOGIN = 'facebook-login'
    FACEBOOK_CALLBACK = 'facebook-login-callback'
    LINKEDIN_LOGIN = 'linkedin-login'
    LINKEDIN_CALLBACK = 'linkedin-login-callback'
