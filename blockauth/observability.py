"""
Metrics / observability hook.

Auth-pack is library code and must stay backend-agnostic: different
consumers ship different stacks (Prometheus, StatsD, OpenTelemetry,
structured-log sinks, or nothing at all). Rather than take a hard
dependency on any of them, we expose a single callback and let the host
service translate events into whatever it already has wired up.

Configuration
-------------

Set ``BLOCK_AUTH_SETTINGS["METRICS_CALLBACK"]`` to the dotted path of a
callable with signature::

    def emit(
        event: str,
        tags: dict | None = None,
        *,
        duration_s: float | None = None,
        count: int = 1,
    ) -> None: ...

If the setting is absent (the default), events are dropped and emission
costs one dict lookup plus one attribute read.

Events emitted by auth-pack
---------------------------

``wallet_login.challenge_issued``
    On successful ``POST /login/wallet/challenge/``.

``wallet_login.success``
    On successful ``POST /login/wallet/``. Tags: ``flow`` (``"siwe"``).

``wallet_login.failure``
    On any rejected ``POST /login/wallet/``. Tags: ``code`` (the
    machine-readable error code returned to the client).

``wallet_login.latency``
    Always emitted from ``POST /login/wallet/`` (both success and
    failure paths). Tags: ``outcome`` (``"success"`` or ``"failure"``).
    ``duration_s`` carries the wall-clock time spent in the handler.

``wallet_nonce.pruned``
    From the ``prune_wallet_nonces`` management command. ``count``
    carries the number of rows deleted in the most recent batch.

The event names are a stable public contract; adding new events is
non-breaking, renaming existing ones is not.

Safety
------

Exceptions raised by the consumer's callback are caught and logged. A
broken metrics pipe must never take down an auth endpoint.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Callable, Dict, Optional

from django.conf import settings as django_settings
from django.core.signals import setting_changed
from django.dispatch import receiver

logger = logging.getLogger(__name__)

_SENTINEL = object()
_resolved_callback: Any = _SENTINEL


def _noop(event: str, tags: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
    """Default callback: drop everything."""


def _resolve_callback() -> Callable[..., None]:
    """Import and cache the user-supplied callback.

    Missing / ``None`` setting resolves to :func:`_noop` so the hot path
    stays branch-free after the first call. Any import error is logged
    and we fall back to the no-op -- a misconfigured callback must not
    take the login endpoint down.
    """
    global _resolved_callback
    if _resolved_callback is not _SENTINEL:
        return _resolved_callback

    block_auth_settings = getattr(django_settings, "BLOCK_AUTH_SETTINGS", None) or {}
    dotted: Optional[str] = (
        block_auth_settings.get("METRICS_CALLBACK") if isinstance(block_auth_settings, dict) else None
    )
    if not dotted:
        _resolved_callback = _noop
        return _resolved_callback

    try:
        module_path, attr = dotted.rsplit(".", 1)
        module = importlib.import_module(module_path)
        callback = getattr(module, attr)
    except (ValueError, ImportError, AttributeError) as exc:
        logger.error(
            "METRICS_CALLBACK %r could not be imported; falling back to no-op: %s",
            dotted,
            exc,
        )
        _resolved_callback = _noop
        return _resolved_callback

    if not callable(callback):
        logger.error(
            "METRICS_CALLBACK %r resolved to a non-callable; falling back to no-op",
            dotted,
        )
        _resolved_callback = _noop
        return _resolved_callback

    _resolved_callback = callback
    return _resolved_callback


def reset_callback_cache() -> None:
    """Clear the resolved-callback cache.

    Only public so tests can rebind ``METRICS_CALLBACK`` via
    ``override_settings`` and have the next :func:`emit` re-resolve.
    Also wired to Django's ``setting_changed`` signal below so tests
    generally don't need to call this directly.
    """
    global _resolved_callback
    _resolved_callback = _SENTINEL


@receiver(setting_changed)
def _invalidate_cache_on_setting_change(sender, setting, **kwargs):
    if setting == "BLOCK_AUTH_SETTINGS":
        reset_callback_cache()


def emit(
    event: str,
    tags: Optional[Dict[str, Any]] = None,
    *,
    duration_s: Optional[float] = None,
    count: int = 1,
) -> None:
    """Emit a single observability event.

    Never raises. If the consumer's callback raises, the exception is
    logged and swallowed -- a broken metrics pipe cannot be allowed to
    fail an auth request.
    """
    callback = _resolve_callback()
    try:
        callback(event, tags, duration_s=duration_s, count=count)
    except Exception as exc:  # pragma: no cover - defensive, narrow not possible here
        logger.exception("METRICS_CALLBACK raised while emitting %r: %s", event, exc)
