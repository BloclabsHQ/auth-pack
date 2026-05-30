import re
from datetime import date, datetime
from importlib import import_module
from typing import Any, Dict, List

from django.contrib.auth.password_validation import get_default_password_validators
from django.db import models

# Import from enums module (Django-independent, no AppRegistryNotReady errors)
from blockauth.enums import AuthenticationType

# Hard ceiling on how deep the sanitizer will walk a nested structure. Logging
# context is JSON-shaped (no cycles in practice), but a bound is cheap insurance
# against a pathological or cyclic payload spinning forever. Anything beyond the
# limit is redacted wholesale — fail safe, never leak.
_MAX_REDACTION_DEPTH = 6


def model_to_json(instance: models.Model, remove_fields: tuple = None) -> Dict[str, Any]:
    """
    Convert a Django model instance to a JSON-serializable dictionary.

    Args:
        instance: Django model instance
        remove_fields: Tuple of field names to exclude from the output

    Returns:
        Dictionary representation of the model instance
    """
    if remove_fields is None:
        remove_fields = ()

    data = {}
    for field in instance._meta.fields:
        if field.name not in remove_fields:
            value = getattr(instance, field.name)
            if isinstance(value, (datetime, date)):
                data[field.name] = value.isoformat()
            else:
                data[field.name] = value

    return data


def _is_sensitive_key(key: Any) -> bool:
    """
    Decide whether a mapping key names a sensitive value.

    Three layers, checked in order, all case-insensitive:
      0. Allowlist (``NON_SENSITIVE_KEYS``) — keys that match a broad pattern
         but are provably non-secret (e.g. ``credential_id``, a WebAuthn
         identifier; ``authentication_type`` / ``authentication_types``, enum
         display values). Checked FIRST so they are never redacted. None of
         these appear in ``SENSITIVE_FIELDS``, so exact-field redaction is
         unaffected by this ordering.
      1. Exact membership in ``SENSITIVE_FIELDS`` — the known request-body and
         token field names. Authoritative: an exact match always redacts,
         regardless of the allowlist.
      2. Regex match against ``SENSITIVE_PATTERNS`` — a defence-in-depth net for
         keys we don't enumerate (``user_password``, ``x_api_token``, a decoded
         JWT's ``signature``...), which matter most inside nested, unknown
         structures. Over-redaction is the safe failure mode for a log sink.
    """
    from blockauth.constants import NON_SENSITIVE_KEYS, SENSITIVE_FIELDS, SENSITIVE_PATTERNS

    lowered = str(key).lower()
    if lowered in NON_SENSITIVE_KEYS:
        return False
    if lowered in SENSITIVE_FIELDS:
        return True
    return any(re.fullmatch(pattern, lowered) for pattern in SENSITIVE_PATTERNS)


def _redact(value: Any, depth: int) -> Any:
    """
    Recursively redact sensitive keys inside a nested structure.

    A sensitive *key* redacts its entire value (subtree included) — we never
    walk into something already known to be secret. A non-sensitive key whose
    value is a ``dict``/``list`` is walked so secrets nested under innocuous keys
    (e.g. ``{"profile": {"password": "..."}}``) don't slip through. Scalars pass
    through untouched.
    """
    from blockauth.constants import REDACTION_STRING

    if depth > _MAX_REDACTION_DEPTH:
        # Too deep to reason about safely — redact wholesale rather than risk a leak.
        return REDACTION_STRING

    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            if _is_sensitive_key(key):
                result[key] = REDACTION_STRING
            else:
                result[key] = _redact(val, depth + 1)
        return result

    if isinstance(value, (list, tuple)):
        redacted = [_redact(item, depth + 1) for item in value]
        return type(value)(redacted) if isinstance(value, tuple) else redacted

    return value


def sanitize_log_context(data: Dict[str, Any], additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Sanitize sensitive data from logging context.

    Redaction is recursive: sensitive keys are redacted at every level of a
    nested ``dict``/``list``, not just the top, so a secret tucked under an
    innocuous key (a decoded JWT ``payload``, a serializer error ``detail``)
    cannot reach a log sink. A sensitive key redacts its whole value; the walker
    descends only through non-sensitive keys.

    Args:
        data: Original data dictionary
        additional_context: Additional context to include

    Returns:
        Sanitized dictionary safe for logging
    """
    # Merge first, then redact: additional_context can itself carry sensitive
    # keys (e.g. a decoded JWT under "payload"), so sanitizing only `data` and
    # updating afterwards would leak those values straight through.
    merged = {**data, **(additional_context or {})}

    return _redact(merged, depth=0)


def get_authentication_types_display(authentication_types: List[str]) -> List[str]:
    """
    Get human-readable display names for authentication types.

    Args:
        authentication_types: List of authentication type codes

    Returns:
        List of human-readable authentication type names
    """
    if not authentication_types:
        return []

    display_names = []
    for auth_type in authentication_types:
        try:
            display_name = AuthenticationType(auth_type).label
            display_names.append(display_name)
        except ValueError:
            # If not a valid choice, use the original value
            display_names.append(auth_type)

    return display_names


def validate_authentication_type(auth_type: str) -> bool:
    """
    Validate if an authentication type is supported.

    Args:
        auth_type: Authentication type to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        AuthenticationType(auth_type)
        return True
    except ValueError:
        return False


def get_available_authentication_types() -> List[Dict[str, str]]:
    """
    Get all available authentication types with their codes and labels.

    Returns:
        List of dictionaries with 'code' and 'label' keys
    """
    return [{"code": choice[0], "label": choice[1]} for choice in AuthenticationType.choices()]


def get_password_help_text():
    """
    Retrieve help text from all password validators in settings.
    """
    validators = get_default_password_validators()
    help_texts = [validator.get_help_text() for validator in validators]
    return "\n\n".join(help_texts)


def import_string_or_none(dotted_path: str | None) -> Any | None:
    """Import a dotted-path target, returning None for empty/None input.

    Used by the Apple notification trigger hook to lazily resolve an
    integrator-supplied class name from BLOCK_AUTH_SETTINGS.
    """
    if not dotted_path:
        return None
    module_name, _, attr = dotted_path.rpartition(".")
    if not module_name:
        return None
    return getattr(import_module(module_name), attr)
