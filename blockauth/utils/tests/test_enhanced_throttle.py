"""
Tests for EnhancedThrottle progressive lockout.

Covers:
- record_failure() triggers cooldown after max_failures
- record_success() resets failure counter and cooldown
- Cooldown blocks requests
- Rate limiting (per-minute)
- Daily limits
"""

import pytest
from django.core.cache import cache

from blockauth.utils.rate_limiter import EnhancedThrottle


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


class FakeRequest:
    """Minimal request mock for throttle testing."""

    def __init__(self, identifier="test@example.com", ip="192.168.1.1"):
        self.data = {"identifier": identifier}
        self.META = {"REMOTE_ADDR": ip, "HTTP_X_FORWARDED_FOR": ""}
        self.user = type("User", (), {"is_authenticated": False, "id": None})()


class TestEnhancedThrottleFailureTracking:
    def test_cooldown_after_max_failures(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=3, cooldown_minutes=15)
        request = FakeRequest()
        subject = "test_login"

        # Record 3 failures (max_failures=3)
        for _ in range(3):
            throttle.record_failure(request, subject)

        # Now request should be blocked (cooldown)
        assert throttle.allow_request(request, subject) is False
        assert throttle.get_block_reason() == "cooldown"

    def test_under_max_failures_still_allowed(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=5, cooldown_minutes=15)
        request = FakeRequest()
        subject = "test_login"

        # Record 4 failures (under max_failures=5)
        for _ in range(4):
            throttle.record_failure(request, subject)

        # Should still be allowed
        assert throttle.allow_request(request, subject) is True

    def test_record_success_resets_failures(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=3, cooldown_minutes=15)
        request = FakeRequest()
        subject = "test_login"

        # Record 2 failures then a success
        throttle.record_failure(request, subject)
        throttle.record_failure(request, subject)
        throttle.record_success(request, subject)

        # Record 2 more failures — should NOT trigger cooldown (counter was reset)
        throttle.record_failure(request, subject)
        throttle.record_failure(request, subject)

        assert throttle.allow_request(request, subject) is True

    def test_success_clears_cooldown(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=2, cooldown_minutes=15)
        request = FakeRequest()
        subject = "test_login"

        # Trigger cooldown
        throttle.record_failure(request, subject)
        throttle.record_failure(request, subject)
        assert throttle.allow_request(request, subject) is False

        # Simulate successful auth (e.g., admin unlock)
        throttle.record_success(request, subject)
        assert throttle.allow_request(request, subject) is True


class TestEnhancedThrottleRateLimiting:
    def test_rate_limit_exceeded(self):
        throttle = EnhancedThrottle(rate=(2, 60), max_failures=100)
        request = FakeRequest()
        subject = "test_rate"

        # First 2 requests succeed
        assert throttle.allow_request(request, subject) is True
        assert throttle.allow_request(request, subject) is True

        # Third request blocked by rate limit
        assert throttle.allow_request(request, subject) is False
        assert throttle.get_block_reason() == "rate"


class TestEnhancedThrottleDailyLimit:
    def test_daily_limit_exceeded(self):
        throttle = EnhancedThrottle(rate=(100, 60), daily_limit=3, max_failures=100)
        request = FakeRequest()
        subject = "test_daily"

        # First 3 succeed
        for _ in range(3):
            assert throttle.allow_request(request, subject) is True

        # Fourth blocked
        assert throttle.allow_request(request, subject) is False
        assert throttle.get_block_reason() == "daily"


class TestDifferentIdentifiersIsolated:
    def test_failures_isolated_per_identifier(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=2, cooldown_minutes=15)
        req_a = FakeRequest(identifier="user_a@test.com")
        req_b = FakeRequest(identifier="user_b@test.com")
        subject = "test_login"

        # Trigger cooldown for user_a
        throttle.record_failure(req_a, subject)
        throttle.record_failure(req_a, subject)

        # user_a blocked
        assert throttle.allow_request(req_a, subject) is False
        # user_b still free
        assert throttle.allow_request(req_b, subject) is True


class AuthenticatedRequest:
    """Authenticated request: identifier derives from the user, not request body."""

    def __init__(self, user_id="user-123", ip="192.168.1.1"):
        self.data = {}
        self.META = {"REMOTE_ADDR": ip, "HTTP_X_FORWARDED_FOR": ip}
        self.user = type("User", (), {"is_authenticated": True, "id": user_id})()


class TestPrincipalKeyingPreventsIPReset:
    """A client-controlled IP must not be able to reset an authenticated
    principal's lockout (security advisory GHSA-6r23-jfg2-98q6)."""

    def test_cooldown_persists_across_ips_for_same_identifier(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=3, cooldown_minutes=15)
        subject = "totp_verify"

        # Three failures from one IP trips the cooldown for this identifier.
        for ip in ("1.1.1.1", "1.1.1.1", "1.1.1.1"):
            throttle.record_failure(FakeRequest(identifier="victim@test.com", ip=ip), subject)

        # A request from a *different* IP for the same identifier stays blocked —
        # rotating the IP does not mint a fresh bucket.
        rotated = FakeRequest(identifier="victim@test.com", ip="9.9.9.9")
        assert throttle.allow_request(rotated, subject) is False
        assert throttle.get_block_reason() == "cooldown"

    def test_authenticated_user_lockout_persists_across_ips(self):
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=3, cooldown_minutes=15)
        subject = "totp_verify"

        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            throttle.record_failure(AuthenticatedRequest(user_id="u-1", ip=ip), subject)

        assert throttle.allow_request(AuthenticatedRequest(user_id="u-1", ip="203.0.113.7"), subject) is False

    def test_anonymous_flow_still_keyed_on_ip(self):
        """With no identifier, the IP remains the discriminating axis."""
        throttle = EnhancedThrottle(rate=(100, 60), max_failures=2, cooldown_minutes=15)
        subject = "test_anon"

        anon_a = FakeRequest(identifier=None, ip="1.1.1.1")
        anon_b = FakeRequest(identifier=None, ip="2.2.2.2")
        throttle.record_failure(anon_a, subject)
        throttle.record_failure(anon_a, subject)

        assert throttle.allow_request(anon_a, subject) is False
        assert throttle.allow_request(anon_b, subject) is True


class SilentlyDegradedCache:
    """Mimics django-redis with IGNORE_EXCEPTIONS=True: reads return the
    default, writes are silent no-ops, nothing raises."""

    def get(self, key, default=None):
        return default

    def set(self, key, value, timeout=None):
        pass

    def delete(self, key):
        pass


class RaisingCache:
    """Mimics a cache backend that raises on every operation."""

    def get(self, *args, **kwargs):
        raise RuntimeError("cache down")

    def set(self, *args, **kwargs):
        raise RuntimeError("cache down")

    def delete(self, *args, **kwargs):
        raise RuntimeError("cache down")


class TestFailClosedOnCacheOutage:
    def test_fail_closed_denies_on_silently_degraded_cache(self):
        throttle = EnhancedThrottle(rate=(5, 60), fail_closed=True)
        throttle.cache = SilentlyDegradedCache()

        assert throttle.allow_request(FakeRequest(), "totp_verify") is False
        assert throttle.get_block_reason() == "cache_unavailable"

    def test_fail_closed_denies_on_raising_cache(self):
        throttle = EnhancedThrottle(rate=(5, 60), fail_closed=True)
        throttle.cache = RaisingCache()

        assert throttle.allow_request(FakeRequest(), "totp_verify") is False
        assert throttle.get_block_reason() == "cache_unavailable"

    def test_fail_open_allows_on_degraded_cache_for_non_critical(self):
        """Non-critical subjects (fail_closed=False) keep failing open so a
        cache blip does not break read-only endpoints."""
        throttle = EnhancedThrottle(rate=(5, 60), fail_closed=False)
        throttle.cache = SilentlyDegradedCache()

        assert throttle.allow_request(FakeRequest(), "totp_status") is True

    def test_healthy_cache_passes_probe(self):
        throttle = EnhancedThrottle(rate=(5, 60), fail_closed=True)
        # Uses the real LocMemCache from settings — probe should succeed.
        assert throttle.allow_request(FakeRequest(), "totp_verify") is True
