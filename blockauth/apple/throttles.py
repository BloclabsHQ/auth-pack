"""Rate limits for public Apple Sign-In endpoints."""

import time

from django.core.cache import cache as default_cache
from rest_framework.throttling import BaseThrottle

from blockauth.apple._settings import apple_setting
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.rate_limiter import get_client_ip


def _rate_tuple(setting_name: str, default: tuple[int, int]) -> tuple[int, int]:
    raw = apple_setting(setting_name, default)
    if isinstance(raw, (list, tuple)) and len(raw) == 2:
        try:
            requests, seconds = int(raw[0]), int(raw[1])
        except (TypeError, ValueError):
            return default
        if requests > 0 and seconds > 0:
            return requests, seconds
    return default


class AppleEndpointThrottle(BaseThrottle):
    """Per-IP throttle for public Apple endpoints.

    Apple endpoints are intentionally `AllowAny`: the Apple-signed JWT or
    id_token is the auth material. Throttling happens before serializer and
    signature work so invalid floods cannot burn verifier CPU indefinitely.
    """

    cache = default_cache
    timer = time.time
    scope = "apple"
    setting_name = ""
    default_rate: tuple[int, int] = (30, 60)

    def __init__(self):
        self.num_requests, self.duration = _rate_tuple(self.setting_name, self.default_rate)
        self.now = self.timer()
        self.window_started_at = self._window_started_at(self.now)

    def _window_started_at(self, timestamp: float) -> float:
        return timestamp - (timestamp % self.duration)

    def get_cache_key(self, request) -> str:
        ip = get_client_ip(request) or "unknown"
        window = int(self.now // self.duration)
        return f"apple_throttle_{self.scope}_{ip}_{window}"

    def _increment_request_count(self, key: str) -> int:
        if self.cache.add(key, 1, self.duration):
            return 1
        try:
            return self.cache.incr(key)
        except ValueError:
            if self.cache.add(key, 1, self.duration):
                return 1
            return self.cache.incr(key)

    def allow_request(self, request, view) -> bool:
        self.now = self.timer()
        self.window_started_at = self._window_started_at(self.now)
        key = self.get_cache_key(request)
        request_count = self._increment_request_count(key)

        if request_count > self.num_requests:
            blockauth_logger.warning(
                "Apple endpoint throttle exceeded",
                sanitize_log_context(
                    {
                        "scope": self.scope,
                        "ip": get_client_ip(request),
                        "limit": self.num_requests,
                        "duration": self.duration,
                    }
                ),
            )
            return False

        return True

    def wait(self):  # pragma: no cover - DRF interface
        return max(0, self.duration - (self.now - self.window_started_at))


class AppleWebCallbackThrottle(AppleEndpointThrottle):
    scope = "apple_web_callback"
    setting_name = "APPLE_WEB_CALLBACK_RATE_LIMIT"
    default_rate = (30, 60)


class AppleNativeVerifyThrottle(AppleEndpointThrottle):
    scope = "apple_native_verify"
    setting_name = "APPLE_NATIVE_VERIFY_RATE_LIMIT"
    default_rate = (30, 60)


class AppleNotificationThrottle(AppleEndpointThrottle):
    scope = "apple_notification"
    setting_name = "APPLE_NOTIFICATION_RATE_LIMIT"
    default_rate = (60, 60)
