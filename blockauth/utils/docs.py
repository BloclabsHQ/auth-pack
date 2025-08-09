# blockauth/utils/docs.py
# Lightweight helpers to make documentation decorators optional at runtime.

try:
    from drf_spectacular.utils import extend_schema as _extend_schema  # type: ignore

    def extend_schema(*args, **kwargs):
        return _extend_schema(*args, **kwargs)
except Exception:  # drf-spectacular not installed or unavailable
    def extend_schema(*args, **kwargs):
        def _decorator(func):
            return func
        return _decorator