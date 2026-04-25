"""SocialIdentity layer: durable links between OIDC `(provider, subject)` and User.

`blockauth.social` is registered as a separate Django app (label
`blockauth_social`) — distinct from sibling sub-packages `totp` and `passkey`,
which share the parent `blockauth` app label. The split is deliberate: the
`SocialIdentity` table belongs to its own migration namespace so it can be
introduced (and, if ever needed, retired) without entangling the existing
`blockauth` migrations.

Public exports use a PEP 562 `__getattr__` so model-bearing modules are not
imported at package-load time. Django imports `blockauth.social` while
populating `INSTALLED_APPS`; eagerly importing `models.py` here would trip
`AppRegistryNotReady`. Consumers can still write
`from blockauth.social import SocialIdentityService` — the lookup resolves
on first attribute access, after the app registry is ready.
"""

__all__ = [
    "AccountLinkingPolicy",
    "SocialIdentity",
    "SocialIdentityConflictError",
    "SocialIdentityService",
]


def __getattr__(name):
    if name == "SocialIdentityConflictError":
        from blockauth.social.exceptions import SocialIdentityConflictError

        return SocialIdentityConflictError
    if name == "AccountLinkingPolicy":
        from blockauth.social.linking_policy import AccountLinkingPolicy

        return AccountLinkingPolicy
    if name == "SocialIdentity":
        from blockauth.social.models import SocialIdentity

        return SocialIdentity
    if name == "SocialIdentityService":
        from blockauth.social.service import SocialIdentityService

        return SocialIdentityService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
