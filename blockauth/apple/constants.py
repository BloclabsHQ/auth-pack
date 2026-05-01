"""Apple Sign-In constants — endpoints, claim names, notification event types.

Endpoints are pulled out of source code so test stubs can patch them and so
integrators can override for staging environments.
"""


class AppleEndpoints:
    AUTHORIZE = "https://appleid.apple.com/auth/authorize"
    TOKEN = "https://appleid.apple.com/auth/token"
    REVOKE = "https://appleid.apple.com/auth/revoke"
    JWKS = "https://appleid.apple.com/auth/keys"
    AUDIENCE = "https://appleid.apple.com"


class AppleClaimKeys:
    SUB = "sub"
    EMAIL = "email"
    EMAIL_VERIFIED = "email_verified"
    IS_PRIVATE_EMAIL = "is_private_email"
    NONCE = "nonce"
    NONCE_SUPPORTED = "nonce_supported"
    EVENTS = "events"


class AppleNotificationEvents:
    CONSENT_REVOKED = "consent-revoked"
    ACCOUNT_DELETED = "account-deleted"
    # Deprecated compatibility alias; use ACCOUNT_DELETED.
    ACCOUNT_DELETE = ACCOUNT_DELETED
    EMAIL_DISABLED = "email-disabled"
    EMAIL_ENABLED = "email-enabled"
