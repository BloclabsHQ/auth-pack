"""Errors raised by the SocialIdentity layer."""

from rest_framework.exceptions import APIException


class SocialIdentityMissingEmailError(APIException):
    """Raised when an OAuth/OIDC sign-in did not return an email and the
    integrator's user model requires one to create a new account.

    Every supported provider (Google, Apple, Facebook, LinkedIn) returns
    either a verified email or — in Apple's "hide my email" case — a
    relay address. A missing email therefore indicates either a missing
    scope on the client request or a misconfigured provider, both of
    which are surfaced to the integrator as HTTP 400 rather than papered
    over with a synthetic identifier that would corrupt the user table.
    """

    status_code = 400
    default_detail = "Provider did not return an email address."
    default_code = "SOCIAL_IDENTITY_MISSING_EMAIL"

    def __init__(self, *, provider: str):
        self.provider = provider
        super().__init__(
            detail=f"provider {provider!r} did not return an email",
            code=self.default_code,
        )


class SocialIdentityConflictError(APIException):
    """Raised when an OAuth/OIDC sign-in claims an email that maps to an
    existing user but the issuing provider is not authoritative for that
    email under `AccountLinkingPolicy`.

    Subclasses DRF's `APIException` so it auto-maps to HTTP 409 in the
    same way `WalletConflictError` does, keeping conflict semantics
    consistent across the package. `provider` and `existing_user_id`
    are stored on the exception instance so views can include
    structured context in the response body without re-deriving them.
    """

    status_code = 409
    default_detail = "This identity is already linked to a different account."
    default_code = "SOCIAL_IDENTITY_CONFLICT"

    def __init__(self, *, provider: str, existing_user_id: str):
        self.provider = provider
        self.existing_user_id = existing_user_id
        super().__init__(
            detail=f"social identity conflict for provider={provider}",
            code=self.default_code,
        )


class SocialIdentityUserUnavailableError(APIException):
    """Raised when a stored identity points at a user hidden by the default
    manager.

    Soft-delete integrations commonly keep the database row while excluding it
    from the model's default manager. The FK still resolves through Django's
    base manager, but returning that user would mint tokens for an account the
    application considers deleted or unavailable. Fail closed and let the
    integrator decide whether to restore, purge, or relink the identity.
    """

    status_code = 409
    default_detail = "This identity is linked to an unavailable account."
    default_code = "SOCIAL_IDENTITY_USER_UNAVAILABLE"

    def __init__(self, *, provider: str, existing_user_id: str):
        self.provider = provider
        self.existing_user_id = existing_user_id
        super().__init__(
            detail=f"linked user unavailable for provider={provider}",
            code=self.default_code,
        )
