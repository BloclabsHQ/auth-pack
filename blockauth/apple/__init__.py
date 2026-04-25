"""Apple Sign-In: web flow, native id_token verify, revocation, S2S notifications.

Registered as a separate Django app (label `blockauth_apple`) for the same
reason `blockauth.social` is — its own migration namespace if any models are
added later (none in v0.16; the pre_delete signal in Task 10.4 attaches to
the User model). Drop the deprecated `default_app_config` declaration since
Django 3.2+ auto-discovers AppConfig.

Public exports use a PEP 562 `__getattr__` so model-bearing modules (when
they land in later tasks) won't be imported during INSTALLED_APPS
population.
"""

__all__ = []  # populated incrementally as later tasks add public surface


def __getattr__(name):
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
