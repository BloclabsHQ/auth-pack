from django.apps import AppConfig


class AppleAuthConfig(AppConfig):
    name = "blockauth.apple"
    label = "blockauth_apple"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Connect the pre_delete handler explicitly here (not via a
        # top-level @receiver decorator in signals.py). The decorator's
        # `sender=` would resolve at import time, before the app registry
        # is populated, raising AppRegistryNotReady. Doing the connect()
        # inside ready() defers the lookup to a point where AUTH_USER_MODEL
        # is safe to dereference.
        from django.conf import settings
        from django.db.models.signals import pre_delete

        from blockauth.apple.signals import revoke_apple_identities

        # `dispatch_uid` makes the connect() idempotent. Production ready()
        # runs once, but tests that re-enter ready() (e.g. via apps.clear_cache())
        # would otherwise double-register the handler.
        pre_delete.connect(
            revoke_apple_identities,
            sender=settings.AUTH_USER_MODEL,
            dispatch_uid="blockauth.apple.revoke_apple_identities",
        )
