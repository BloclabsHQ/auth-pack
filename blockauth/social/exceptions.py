"""Errors raised by the SocialIdentity layer."""

from rest_framework.exceptions import APIException


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
