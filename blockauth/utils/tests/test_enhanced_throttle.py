"""
Tests for EnhancedThrottle progressive lockout.

Covers:
- record_failure() triggers cooldown after max_failures
- record_success() resets failure counter and cooldown
- Cooldown blocks requests
- Rate limiting (per-minute)
- Daily limits
"""

import threading

import pytest
from django.core.cache import cache

from blockauth.utils.rate_limiter import (
    EnhancedThrottle,
    OTPThrottle,
    RequestThrottle,
)
from blockauth.views.basic_auth_views import (
    BasicAuthLoginView,
    PasswordlessLoginConfirmView,
)


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


class TestEnhancedThrottleWait:
    """wait() returns the seconds until the blocking window ends."""

    # 2026-01-01T00:00:00Z plus 10 hours.
    NOW = 1767225600.0 + 36000

    def _throttle(self, **kwargs):
        throttle = EnhancedThrottle(**kwargs)
        throttle.timer = lambda: self.NOW
        return throttle

    def test_daily_wait_is_seconds_until_next_utc_day(self):
        throttle = self._throttle(rate=(100, 60), daily_limit=1, max_failures=100)
        request = FakeRequest()

        assert throttle.allow_request(request, "test_daily_wait") is True
        assert throttle.allow_request(request, "test_daily_wait") is False
        assert throttle.get_block_reason() == "daily"
        assert throttle.wait() == 86400 - 36000

    def test_rate_wait_is_seconds_until_oldest_request_expires(self):
        throttle = self._throttle(rate=(2, 3600), max_failures=100)
        request = FakeRequest()

        assert throttle.allow_request(request, "test_rate_wait") is True
        throttle.timer = lambda: self.NOW + 600
        assert throttle.allow_request(request, "test_rate_wait") is True
        throttle.timer = lambda: self.NOW + 900
        assert throttle.allow_request(request, "test_rate_wait") is False
        assert throttle.get_block_reason() == "rate"
        assert throttle.wait() == 3600 - 900

    def test_cooldown_wait_is_seconds_until_cooldown_ends(self):
        throttle = self._throttle(rate=(100, 60), max_failures=1, cooldown_minutes=15)
        request = FakeRequest()

        throttle.record_failure(request, "test_cooldown_wait")
        throttle.timer = lambda: self.NOW + 60
        assert throttle.allow_request(request, "test_cooldown_wait") is False
        assert throttle.get_block_reason() == "cooldown"
        assert throttle.wait() == 15 * 60 - 60

    def test_wait_is_none_when_allowed(self):
        throttle = self._throttle(rate=(100, 60))

        assert throttle.allow_request(FakeRequest(), "test_no_wait") is True
        assert throttle.wait() is None


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


def _run_pair(work_a, work_b):
    """Run two callables on separate threads; return [result_a, result_b]."""
    results = [None, None]
    errors = []

    def runner(index, work):
        try:
            results[index] = work()
        except Exception as exc:  # surfaced in the main thread below
            errors.append(exc)

    threads = []
    for index, work in enumerate((work_a, work_b)):
        threads.append(threading.Thread(target=runner, args=(index, work)))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    still_running = any(thread.is_alive() for thread in threads)
    assert not still_running, "worker thread did not finish"
    assert errors == []
    return results


class BarrierCache:
    """Dict-backed cache whose first two get() calls rendezvous, so two
    in-flight checks on one shared instance interleave."""

    def __init__(self):
        self.store = {}
        self._barrier = threading.Barrier(2)
        self._lock = threading.Lock()
        self._gets = 0

    def get(self, key, default=None):
        with self._lock:
            self._gets += 1
            rendezvous = self._gets <= 2
        if rendezvous:
            self._barrier.wait(timeout=10)
        return self.store.get(key, default)

    def set(self, key, value, timeout=None):
        self.store[key] = value

    def delete(self, key):
        self.store.pop(key, None)


class TestRequestThrottleThreadIsolation:
    """Each thread keeps its own bucket and wait (SEC-11)."""

    def test_concurrent_requests_keep_separate_buckets_and_wait(self):
        throttle = RequestThrottle(rate=(2, 60))
        throttle.cache = BarrierCache()
        throttle.timer = lambda: 1_000_000.0
        subject = "thread_isolation"

        def check(identifier):
            request = FakeRequest(identifier=identifier)
            allowed = throttle.allow_request(request, subject)
            return allowed, throttle.wait()

        results = _run_pair(
            lambda: check("a@test.com"),
            lambda: check("b@test.com"),
        )

        assert results == [(True, 30.0), (True, 30.0)]
        store = throttle.cache.store
        assert len(store) == 2
        for identifier in ("a@test.com", "b@test.com"):
            histories = []
            for key, value in store.items():
                if identifier in key:
                    histories.append(value)
            assert len(histories) == 1 and len(histories[0]) == 1


class TestEnhancedThrottleThreadIsolation:
    def test_block_reason_and_wait_are_per_thread(self):
        throttle = EnhancedThrottle(
            rate=(100, 60),
            max_failures=2,
            cooldown_minutes=15,
        )
        subject = "thread_block_reason"
        blocked = FakeRequest(identifier="blocked@test.com")
        throttle.record_failure(blocked, subject)
        throttle.record_failure(blocked, subject)

        gate = threading.Barrier(2)

        def check(request):
            allowed = throttle.allow_request(request, subject)
            # Read back only after both checks ran on the shared instance.
            gate.wait(timeout=10)
            return allowed, throttle.get_block_reason(), throttle.wait()

        blocked_result, allowed_result = _run_pair(
            lambda: check(blocked),
            lambda: check(FakeRequest(identifier="ok@test.com")),
        )

        assert blocked_result[0] is False and blocked_result[1] == "cooldown"
        assert blocked_result[2] is not None
        assert allowed_result == (True, None, None)


class TestOTPThrottleThreadIsolation:
    def test_rate_limit_type_is_per_thread(self):
        now = 1767225600.0
        throttle = OTPThrottle(rate=(5, 60), daily_limit=1)
        throttle.timer = lambda: now
        subject = "otp_thread_isolation"
        day_start = int(now // 86400) * 86400
        cache.set(f"otp_daily_daily@test.com_{subject}_{day_start}", 1, 86400)

        gate = threading.Barrier(2)

        def check(identifier):
            request = FakeRequest(identifier=identifier)
            allowed = throttle.allow_request(request, subject)
            gate.wait(timeout=10)
            return allowed, throttle.get_error_message()

        daily_result, ok_result = _run_pair(
            lambda: check("daily@test.com"),
            lambda: check("ok@test.com"),
        )

        assert daily_result[0] is False
        assert "Daily limit exceeded" in daily_result[1]
        assert ok_result[0] is True
        assert "Daily limit exceeded" not in ok_result[1]


class TestLoginThrottlesFailClosed:
    def test_login_throttles_deny_on_degraded_cache(self):
        for view, subject in (
            (BasicAuthLoginView, "basic_login"),
            (PasswordlessLoginConfirmView, "passwordless_login"),
        ):
            throttle = view.login_throttle
            assert throttle.fail_closed is True
            original_cache = throttle.cache
            throttle.cache = SilentlyDegradedCache()
            try:
                assert throttle.allow_request(FakeRequest(), subject) is False
                assert throttle.get_block_reason() == "cache_unavailable"
            finally:
                throttle.cache = original_cache
