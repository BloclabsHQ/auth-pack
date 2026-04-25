"""Errors raised by the SocialIdentity layer."""


class SocialIdentityConflictError(Exception):
    """Raised when an OAuth/OIDC sign-in claims an email that maps to an existing
    user, but the issuing provider is not authoritative for that email under
    `AccountLinkingPolicy`. Surfaced as HTTP 409 by views.
    """

    def __init__(self, *, provider: str, existing_user_id: str):
        super().__init__(f"social identity conflict for provider={provider}")
        self.provider = provider
        self.existing_user_id = existing_user_id
