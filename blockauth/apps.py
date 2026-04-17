"""Django AppConfig for BlockAuth.

``ready()`` runs startup validation that would otherwise only surface at the
first wallet login request -- we want a non-DEBUG deployment with an empty
``WALLET_LOGIN_EXPECTED_DOMAINS`` list to fail to boot, not to silently
accept SIWE challenges against a host extracted from the dev URL
(hardening #3 in issue #90).

The validation is also guarded by a ``sys.argv`` check so it only fires for
commands that actually serve traffic (``runserver``, or a WSGI/ASGI server
booting through ``django.setup()``). Management commands that trigger
``ready()`` during a Docker build or a deploy (``collectstatic``,
``migrate``, ``check``, ...) don't need the allow-list -- forcing every
consumer's Dockerfile to set ``WALLET_LOGIN_SKIP_STARTUP_VALIDATION=true``
just to build a static-asset layer was a silent landmine every new consumer
tripped over (issue #93).
"""

import sys

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Management commands that run ``django.setup()`` but don't serve HTTP
# traffic. The SIWE allow-list check doesn't need to fire for any of these:
# they either run during a Docker build (``collectstatic``), a deploy step
# (``migrate``), CI (``check``, ``test``), ops inspection (``shell``,
# ``dbshell``, ``showmigrations``, ``diffsettings``), i18n build
# (``compilemessages``, ``makemessages``), data IO (``dumpdata``,
# ``loaddata``, ``flush``, ``clearsessions``), or user admin
# (``createsuperuser``, ``changepassword``).
#
# ``runserver`` / ``runserver_plus`` are deliberately absent -- they bind a
# port and must validate. WSGI/ASGI servers (``gunicorn``, ``uvicorn``,
# ``daphne``) don't run through manage.py so their ``sys.argv[1]`` is not
# in this set either, which is the desired fail-closed behavior.
_OFFLINE_MANAGEMENT_COMMANDS = frozenset(
    {
        "check",
        "changepassword",
        "clearsessions",
        "collectstatic",
        "compilemessages",
        "createsuperuser",
        "dbshell",
        "diffsettings",
        "dumpdata",
        "flush",
        "help",
        "loaddata",
        "makemessages",
        "makemigrations",
        "migrate",
        "sendtestemail",
        "shell",
        "shell_plus",
        "showmigrations",
        "sqlflush",
        "sqlmigrate",
        "sqlsequencereset",
        "test",
        "version",
    }
)


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

    # #93: when running an offline management command (``collectstatic``,
    # ``migrate``, ...), the check would crash a Docker build that hadn't
    # yet wired the allow-list. Those commands don't serve traffic, so
    # there's nothing to protect. We keep firing for ``runserver`` and for
    # WSGI/ASGI boots (no ``manage.py <cmd>`` argv).
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command in _OFFLINE_MANAGEMENT_COMMANDS:
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
