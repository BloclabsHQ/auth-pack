"""Apple Sign-In: web flow, native id_token verify, revocation, S2S notifications.

`blockauth.apple` carries no Django models (only views, signals, and
verification helpers), so it doesn't need to be a separate Django app.
The User-model `pre_delete` revoke signal in `signals.py` is connected by
the umbrella `BlockAuthConfig.ready()` in `blockauth/apps.py`. Consumers
keep one INSTALLED_APPS entry (`"blockauth"`) — same as `passkey`/`totp`/
`social`.

Public exports use a PEP 562 `__getattr__` to defer any heavy submodule
imports until first attribute access.
"""

__all__ = []  # populated incrementally as later tasks add public surface


def __getattr__(name):
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
