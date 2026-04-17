"""Django AppConfig for BlockAuth.

``ready()`` runs startup validation that would otherwise only surface at the
first wallet login request -- we want a non-DEBUG deployment with an empty
``WALLET_LOGIN_EXPECTED_DOMAINS`` list to fail to boot, not to silently
accept SIWE challenges against a host extracted from the dev URL
(hardening #3 in issue #90).
"""

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class BlockAuthConfig(AppConfig):
    name = "blockauth"
    verbose_name = "BlockAuth"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        validate_wallet_login_settings()


def validate_wallet_login_settings() -> None:
    """Refuse to start a non-DEBUG deployment with a missing SIWE allow-list.

    ``WALLET_LOGIN_EXPECTED_DOMAINS`` must be explicitly configured in
    production so SIWE messages are bound to a known set of domains. An
    empty list falls back to the dev-only behavior of extracting the host
    from ``CLIENT_APP_URL`` which is fine for local development but
    dangerous in production because a phishing relay could be "in the
    allow-list" by virtue of running under whatever happens to be in
    ``CLIENT_APP_URL`` at the moment.
    """
    if getattr(settings, "DEBUG", False):
        return

    # A skip flag lets deployments that are wiring things up in stages (for
    # example, a consumer that is rolling out the new endpoints behind a
    # feature flag) silence the check without turning DEBUG on. Prefer to
    # leave it off in real production.
    if getattr(settings, "WALLET_LOGIN_SKIP_STARTUP_VALIDATION", False):
        return

    domains = getattr(settings, "WALLET_LOGIN_EXPECTED_DOMAINS", ())
    if not domains:
        raise ImproperlyConfigured(
            "WALLET_LOGIN_EXPECTED_DOMAINS must be configured as a non-empty "
            "iterable of allowed SIWE domains when DEBUG is False. Set it to "
            "the exact host(s) you expect SIWE messages to bind to -- for "
            "example ('app.example.com',). Set "
            "WALLET_LOGIN_SKIP_STARTUP_VALIDATION=True to silence this check "
            "during a phased rollout."
        )

    if not isinstance(domains, (list, tuple, set, frozenset)):
        raise ImproperlyConfigured(
            "WALLET_LOGIN_EXPECTED_DOMAINS must be a list, tuple or set; " f"got {type(domains).__name__}"
        )

    bad = [d for d in domains if not isinstance(d, str) or not d.strip()]
    if bad:
        raise ImproperlyConfigured(f"WALLET_LOGIN_EXPECTED_DOMAINS contains invalid entries: {bad!r}")
