"""SocialIdentity layer: durable links between OIDC `(provider, subject)` and User.

`SocialIdentity` lives under the umbrella `blockauth` app (same convention as
sibling sub-packages `totp` and `passkey`), so consumers only add `"blockauth"`
to `INSTALLED_APPS` and can override the entire blockauth migration graph via
one `MIGRATION_MODULES` entry. The model is wired into the app registry by
`blockauth/models/__init__.py` importing `SocialIdentity` at module load.

Public exports below use a PEP 562 `__getattr__` so model-bearing modules are
not imported at package-load time from this `__init__` itself. Consumers can
still write `from blockauth.social import SocialIdentityService` — the lookup
resolves on first attribute access, after the app registry is ready.
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
