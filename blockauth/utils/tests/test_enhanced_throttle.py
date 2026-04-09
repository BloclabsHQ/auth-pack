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
