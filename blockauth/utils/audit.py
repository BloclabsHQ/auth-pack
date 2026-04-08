"""
Audit Trail Decorator and Utilities

SOC2 compliant audit logging for sensitive operations.
See .claude/AUDIT_TRAIL_IMPLEMENTATION.md for full specification.
"""

from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, Optional

from .generics import sanitize_log_context
from .logger import blockauth_logger

# Sensitive parameter names that should be redacted
SENSITIVE_PARAMS = frozenset(
    [
        "password",
        "token",
        "secret",
        "key",
        "private",
        "credential",
        "code",
        "otp",
        "pin",
        "backup_code",
        "encrypted",
        "signature",
    ]
)


def _is_sensitive(param_name: str) -> bool:
    """Check if parameter name indicates sensitive data."""
    param_lower = param_name.lower()
    return any(s in param_lower for s in SENSITIVE_PARAMS)


def _sanitize_value(value: Any, max_length: int = 100) -> str:
    """Safely convert value to string with length limit."""
    try:
        str_val = str(value)
        if len(str_val) > max_length:
            return str_val[:max_length] + "..."
        return str_val
    except Exception:
        return "[UNSERIALIZABLE]"


def _extract_user_context(args: tuple, kwargs: dict) -> Dict[str, Any]:
    """Extract user and request context from function arguments."""
    context = {
        "user_id": None,
        "ip_address": None,
        "user_agent": None,
    }

    # Check args for request object or user_id
    for arg in args:
        # Django/DRF request object
        if hasattr(arg, "user") and hasattr(arg, "META"):
            if hasattr(arg.user, "id"):
                context["user_id"] = str(arg.user.id)
            context["ip_address"] = arg.META.get("REMOTE_ADDR")
            context["user_agent"] = arg.META.get("HTTP_USER_AGENT", "")[:200]
            break
        # Direct user_id string
        if isinstance(arg, str) and len(arg) == 36 and "-" in arg:
            context["user_id"] = arg

    # Check kwargs
    if "user_id" in kwargs:
        context["user_id"] = str(kwargs["user_id"])
    if "request" in kwargs and hasattr(kwargs["request"], "META"):
        req = kwargs["request"]
        context["ip_address"] = req.META.get("REMOTE_ADDR")
        context["user_agent"] = req.META.get("HTTP_USER_AGENT", "")[:200]

    return context


def audit_trail(
    event_type: Optional[str] = None,
    severity: str = "INFO",
    log_args: bool = False,
    log_result: bool = False,
):
    """
    Decorator for audit logging sensitive function calls.

    Automatically logs function entry, success, and failure with context.
    Compliant with SOC2 and SECURITY_STANDARDS.md requirements.

    Args:
        event_type: Override event type (default: module.function_name)
        severity: Log severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_args: Include sanitized arguments in audit log
        log_result: Include sanitized result in audit log

    Usage:
        @audit_trail(event_type="mfa.totp.setup")
        def setup_totp(self, user_id: str, ...):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Determine event type
            func_event = event_type or f"{func.__module__}.{func.__name__}"

            # Extract context
            context = _extract_user_context(args, kwargs)
            audit_data = {
                "event_type": func_event,
                "function": func.__name__,
                "module": func.__module__,
                "timestamp": datetime.utcnow().isoformat(),
                **context,
            }

            # Optionally include sanitized arguments
            if log_args:
                safe_args = {}
                # Skip 'self' for methods
                arg_names = func.__code__.co_varnames[: func.__code__.co_argcount]
                for i, name in enumerate(arg_names):
                    if name == "self":
                        continue
                    if i < len(args):
                        if _is_sensitive(name):
                            safe_args[name] = "[REDACTED]"
                        else:
                            safe_args[name] = _sanitize_value(args[i])

                for key, value in kwargs.items():
                    if _is_sensitive(key):
                        safe_args[key] = "[REDACTED]"
                    else:
                        safe_args[key] = _sanitize_value(value)

                audit_data["arguments"] = safe_args

            # Log function call
            blockauth_logger.info(f"AUDIT: {func_event}", sanitize_log_context(audit_data))

            try:
                # Execute function
                result = func(*args, **kwargs)

                # Log success
                success_data = {
                    **audit_data,
                    "status": "success",
                    "completed_at": datetime.utcnow().isoformat(),
                }

                if log_result and result is not None:
                    if isinstance(result, dict):
                        # Sanitize dict result
                        success_data["result"] = {
                            k: "[REDACTED]" if _is_sensitive(k) else _sanitize_value(v) for k, v in result.items()
                        }
                    else:
                        success_data["result"] = _sanitize_value(result)

                blockauth_logger.success(f"AUDIT: {func_event}.success", sanitize_log_context(success_data))

                return result

            except Exception as e:
                # Log failure
                failure_data = {
                    **audit_data,
                    "status": "failed",
                    "error_type": type(e).__name__,
                    "error_message": str(e)[:500],
                    "failed_at": datetime.utcnow().isoformat(),
                }

                # Log at appropriate severity
                if severity in ("ERROR", "CRITICAL"):
                    blockauth_logger.error(f"AUDIT: {func_event}.failed", sanitize_log_context(failure_data))
                else:
                    blockauth_logger.warning(f"AUDIT: {func_event}.failed", sanitize_log_context(failure_data))

                raise

        return wrapper

    return decorator
