import ipaddress
import os
import time
import uuid
from typing import Optional

from django.core.cache import cache as default_cache
from rest_framework.throttling import BaseThrottle

from blockauth.utils.config import get_config
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger

# Maximum length for IP-related header values (security limit)
MAX_IP_HEADER_LENGTH = 500

# Per-process token used by the cache-liveness probe. A fixed token per process
# means concurrent probes within the same worker write the same value, so a
# successful read-back is never a false negative under load.
_HEALTHCHECK_TOKEN = uuid.uuid4().hex


def validate_ip_address(ip_string: str) -> Optional[str]:
    """
    Validate and normalize an IP address string.

    Security: Prevents malformed header exploitation by validating
    that the extracted value is a legitimate IPv4 or IPv6 address.

    Args:
        ip_string: Raw IP address string to validate

    Returns:
        Normalized IP address string if valid, None otherwise
    """
    if not ip_string or not isinstance(ip_string, str):
        return None

    # Strip whitespace and check length limit
    ip_string = ip_string.strip()
    if len(ip_string) > 45:  # Max IPv6 length with zone ID
        return None

    # Reject obvious injection attempts
    if any(char in ip_string for char in [";", "|", "&", "$", "`", "\n", "\r", "\x00"]):
        blockauth_logger.warning(
            "Suspicious characters in IP address", sanitize_log_context({"raw_ip": ip_string[:50]})
        )
        return None

    try:
        # Parse and validate using Python's ipaddress module
        ip_obj = ipaddress.ip_address(ip_string)

        # Reject unspecified addresses (0.0.0.0 or ::)
        if ip_obj.is_unspecified:
            return None

        # Return the normalized string representation
        return str(ip_obj)

    except ValueError:
        # Invalid IP address format
        return None


def _get_trusted_proxy_depth() -> int:
    """Number of trusted reverse proxies in front of the application.

    Drives how X-Forwarded-For is interpreted in get_client_ip(). Defaults to
    1 (one trusted edge proxy). Set TRUSTED_PROXY_DEPTH to 0 for deployments
    where the application is directly internet-facing (no proxy), or to the
    number of trusted hops for multi-proxy topologies.
    """
    try:
        return max(0, int(get_config("TRUSTED_PROXY_DEPTH")))
    except (AttributeError, TypeError, ValueError):
        return 1


def get_client_ip(request) -> str:
    """
    Extract and validate the client IP from the request.

    Security: X-Forwarded-For is appended to by each proxy, so the rightmost
    entries are written by infrastructure we control and the leftmost entries
    are client-supplied and forgeable. We therefore count from the RIGHT using
    the configured trusted-proxy depth instead of trusting the leftmost value.
    The IP format is validated to prevent header injection. Falls back to
    REMOTE_ADDR (the immediate peer) when X-Forwarded-For cannot be trusted.

    Args:
        request: Django/DRF request object

    Returns:
        Validated IP address string, or empty string if none found
    """
    depth = _get_trusted_proxy_depth()
    remote_addr = request.META.get("REMOTE_ADDR", "")

    if depth > 0:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")

        if x_forwarded_for:
            # Security: Limit header length to prevent DoS
            if len(x_forwarded_for) > MAX_IP_HEADER_LENGTH:
                blockauth_logger.warning(
                    "X-Forwarded-For header exceeds maximum length",
                    sanitize_log_context({"length": len(x_forwarded_for)}),
                )
                x_forwarded_for = x_forwarded_for[:MAX_IP_HEADER_LENGTH]

            # "client, proxy1, proxy2" — trust the rightmost `depth` hops and
            # treat the next value in from the right as the real client.
            parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]

            if len(parts) >= depth:
                candidate = parts[-depth]
                validated_ip = validate_ip_address(candidate)
                if validated_ip:
                    return validated_ip

                blockauth_logger.warning(
                    "Invalid IP at trusted X-Forwarded-For position",
                    sanitize_log_context({"raw_value": candidate[:50]}),
                )
            else:
                # Fewer forwarded hops than trusted depth — the chain is shorter
                # than expected (possible spoof or misconfiguration). Do not
                # trust it; fall back to the immediate peer.
                blockauth_logger.warning(
                    "X-Forwarded-For shorter than trusted proxy depth",
                    sanitize_log_context({"entries": len(parts), "trusted_depth": depth}),
                )

    # Fall back to REMOTE_ADDR
    validated_remote = validate_ip_address(remote_addr)

    if validated_remote:
        return validated_remote

    # No valid IP found - return empty string for safety
    return ""


class RequestThrottle(BaseThrottle):
    """
    Limits request to a specific identifier, subject & IP address.
    """

    cache = default_cache
    timer = time.time

    def __init__(self, rate: tuple[int, int] = None):
        """
        :param rate: A tuple of (num_requests, duration) to limit the number of requests.
                     Meaning user can make at most `num_requests` within `duration` seconds.
        """
        if rate is None:
            rate = get_config("REQUEST_LIMIT")
        self.num_requests, self.duration = rate
        self.history = None
        self.now = None
        self.key = None

    def get_cache_key(self, request, subject):
        identifier = request.data.get("identifier")
        ip_address = get_client_ip(request)

        if not identifier and request.user.id:
            identifier = str(request.user.id)

        # Deny request if identifier, subject, or IP address is missing —
        # fail closed to prevent bypass via spoofed/missing headers.
        if not identifier or not subject or not ip_address:
            blockauth_logger.warning(
                "Rate limit: missing identifier/subject/IP — denying request",
                sanitize_log_context(
                    {
                        "has_identifier": bool(identifier),
                        "has_subject": bool(subject),
                        "has_ip": bool(ip_address),
                    }
                ),
            )
            return None

        return f"auth_throttle_{identifier}_{subject}_{ip_address}"

    def allow_request(self, request, subject):
        self.key = self.get_cache_key(request, subject)
        if self.key is None:
            # Fail closed: deny requests without identifiable source.
            # Initialize state so callers can safely call wait() after denial.
            self.history = []
            self.now = self.timer()
            return False

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()

        if len(self.history) >= self.num_requests:
            # Set rate limit type for OTPThrottle to use
            if hasattr(self, "daily_limit"):
                self._rate_limit_type = "per_minute"

            # Enhanced logging for rate limit violations
            identifier = request.data.get("identifier", "unknown")
            ip_address = get_client_ip(request)

            blockauth_logger.warning(
                f"Rate limit exceeded for {subject}",
                sanitize_log_context(
                    {
                        "identifier": identifier,
                        "subject": subject,
                        "ip_address": ip_address,
                        "current_requests": len(self.history),
                        "max_requests": self.num_requests,
                        "duration": self.duration,
                        "wait_time": self.wait(),
                    }
                ),
            )
            return self.throttle_failure()
        return self.throttle_success()

    def throttle_success(self):
        self.history.insert(0, self.now)
        self.cache.set(self.key, self.history, self.duration)
        return True

    def throttle_failure(self):
        return False

    def wait(self):
        # Returns the recommended next request time in seconds.
        if self.history:
            remaining_duration = self.duration - (self.now - self.history[-1])
        else:
            remaining_duration = self.duration

        available_requests = self.num_requests - len(self.history) + 1
        if available_requests <= 0:
            return None

        return remaining_duration / float(available_requests)


class EnhancedThrottle(BaseThrottle):
    """
    Enhanced throttle with daily limits, cooldowns, and failure tracking.

    Features:
    - Per-minute rate limiting
    - Daily limits
    - Cooldown after repeated failures
    - Fail-closed on cache unavailability for brute-force-critical subjects

    Bucket keying: all counters (rate, failures, cooldown, daily) are keyed on
    the authenticated principal when one is present, falling back to the client
    IP only for unauthenticated flows. A client-controlled IP / X-Forwarded-For
    therefore cannot be varied to mint a fresh bucket and reset the lockout for
    an authenticated user.
    """

    cache = default_cache
    timer = time.time

    def __init__(
        self,
        rate: tuple[int, int] = None,
        daily_limit: int = None,
        max_failures: int = 5,
        cooldown_minutes: int = 15,
        fail_closed: bool = False,
    ):
        """
        Args:
            rate: (num_requests, duration_seconds) - e.g., (10, 60) = 10/min
            daily_limit: Max requests per day (None = no daily limit)
            max_failures: Failures before cooldown triggers
            cooldown_minutes: Cooldown duration after max failures
            fail_closed: When True, deny the request if the cache backend is
                unavailable/degraded instead of failing open. Set for
                brute-force-critical subjects (verify, confirm, disable).
        """
        if rate is None:
            rate = get_config("REQUEST_LIMIT")
        self.num_requests, self.duration = rate
        self.daily_limit = daily_limit
        self.max_failures = max_failures
        self.cooldown_minutes = cooldown_minutes
        self.fail_closed = fail_closed
        self._block_reason = None

    def _get_identifier(self, request):
        """Get user identifier from request."""
        identifier = request.data.get("identifier")
        if not identifier and hasattr(request, "user") and request.user.is_authenticated:
            identifier = str(request.user.id)
        return identifier

    @staticmethod
    def _axis(ip, identifier) -> str:
        """Throttle bucket axis.

        Prefer the authenticated principal so the bucket cannot be reset by
        varying a client-controlled IP / X-Forwarded-For. Fall back to the IP
        for unauthenticated flows where it is the only available signal.
        """
        return identifier or ip or "anon"

    def _cache_alive(self) -> bool:
        """Active liveness probe for the cache backend.

        A backend configured to swallow errors (e.g. django-redis
        IGNORE_EXCEPTIONS=True) makes every cache.get() return its empty
        default and cache.set() a silent no-op — which would make every
        throttle read appear unthrottled. A raising backend is caught here too.
        Writes a per-process sentinel and reads it back to confirm the cache is
        actually serving reads/writes.
        """
        key = f"throttle_healthcheck_{os.getpid()}"
        try:
            self.cache.set(key, _HEALTHCHECK_TOKEN, 30)
            return self.cache.get(key) == _HEALTHCHECK_TOKEN
        except Exception:
            return False

    def allow_request(self, request, subject) -> bool:
        """Check all rate limits."""
        ip = get_client_ip(request)
        identifier = self._get_identifier(request)
        now = self.timer()

        # Fail closed for brute-force-critical subjects when the cache backend
        # is unavailable/degraded — otherwise every counter reads empty and the
        # throttle silently allows all requests.
        if self.fail_closed and not self._cache_alive():
            self._block_reason = "cache_unavailable"
            self._log_blocked(request, subject, "cache_unavailable")
            return False

        # Check cooldown first
        if not self._check_cooldown(ip, identifier, subject):
            self._block_reason = "cooldown"
            self._log_blocked(request, subject, "cooldown")
            return False

        # Check daily limit
        if self.daily_limit and not self._check_daily(ip, identifier, subject, now):
            self._block_reason = "daily"
            self._log_blocked(request, subject, "daily_limit")
            return False

        # Check rate limit
        if not self._check_rate(ip, identifier, subject, now):
            self._block_reason = "rate"
            self._log_blocked(request, subject, "rate_limit")
            return False

        return True

    def _check_rate(self, ip, identifier, subject, now) -> bool:
        """Check per-minute rate limit."""
        key = f"throttle_rate_{subject}_{self._axis(ip, identifier)}"
        history = self.cache.get(key, [])
        history = [t for t in history if now - t < self.duration]

        if len(history) >= self.num_requests:
            return False

        history.append(now)
        self.cache.set(key, history, self.duration)
        return True

    def _check_daily(self, ip, identifier, subject, now) -> bool:
        """Check daily limit."""
        day_key = f"throttle_daily_{subject}_{self._axis(ip, identifier)}_{int(now // 86400)}"
        count = self.cache.get(day_key, 0)

        if count >= self.daily_limit:
            return False

        self.cache.set(day_key, count + 1, 86400)
        return True

    def _check_cooldown(self, ip, identifier, subject) -> bool:
        """Check if in cooldown period."""
        key = f"throttle_cooldown_{subject}_{self._axis(ip, identifier)}"
        return not self.cache.get(key, False)

    def record_failure(self, request, subject):
        """Record a failed attempt. Call when operation fails."""
        ip = get_client_ip(request)
        identifier = self._get_identifier(request)
        key = f"throttle_failures_{subject}_{self._axis(ip, identifier)}"

        count = self.cache.get(key, 0) + 1
        self.cache.set(key, count, 3600)  # Track for 1 hour

        if count >= self.max_failures:
            cooldown_key = f"throttle_cooldown_{subject}_{self._axis(ip, identifier)}"
            self.cache.set(cooldown_key, True, self.cooldown_minutes * 60)
            blockauth_logger.warning(
                f"Cooldown triggered for {subject}",
                sanitize_log_context(
                    {
                        "ip": ip,
                        "identifier": identifier,
                        "failures": count,
                        "cooldown_minutes": self.cooldown_minutes,
                    }
                ),
            )

    def record_success(self, request, subject):
        """Record successful attempt. Resets failure counter."""
        ip = get_client_ip(request)
        identifier = self._get_identifier(request)

        # Clear failures
        key = f"throttle_failures_{subject}_{self._axis(ip, identifier)}"
        self.cache.delete(key)

        # Clear cooldown
        cooldown_key = f"throttle_cooldown_{subject}_{self._axis(ip, identifier)}"
        self.cache.delete(cooldown_key)

    def _log_blocked(self, request, subject, reason):
        """Log blocked request."""
        blockauth_logger.warning(
            f"Request blocked: {reason}",
            sanitize_log_context(
                {
                    "subject": subject,
                    "reason": reason,
                    "ip": get_client_ip(request),
                    "identifier": self._get_identifier(request),
                }
            ),
        )

    def get_block_reason(self) -> str:
        """Get reason for last block."""
        return self._block_reason


class OTPThrottle(RequestThrottle):
    """
    Enhanced throttling specifically for OTP operations with additional security measures.

    This throttle provides:
    1. Stricter rate limiting for OTP generation
    2. Per-identifier daily limits
    3. Progressive delays for repeated attempts
    4. Enhanced logging and monitoring
    """

    def __init__(self, rate: tuple[int, int] = None, daily_limit: int = 10):
        """
        Initialize OTP throttle with enhanced security.

        Args:
            rate: Tuple of (num_requests, duration) for basic rate limiting
            daily_limit: Maximum OTP requests per day per identifier
        """
        # Don't call super().__init__ yet - we need to handle rate properly
        if rate is None:
            rate = get_config("REQUEST_LIMIT")

        # Now set up the base throttle properly with our rate
        self.cache = default_cache
        self.timer = time.time
        self.num_requests, self.duration = rate
        self.history = None
        self.now = None
        self.key = None
        self.daily_limit = daily_limit
        self._rate_limit_type = None

    def allow_request(self, request, subject):
        """Enhanced allow_request with additional OTP-specific checks."""
        identifier = request.data.get("identifier")

        # Check daily limits first (more restrictive)
        if not self._check_daily_limit(request, subject):
            identifier = request.data.get("identifier", "unknown")
            ip_address = request.META.get("REMOTE_ADDR", "unknown")

            # Set a flag to indicate this is a daily limit
            self._rate_limit_type = "daily"

            blockauth_logger.warning(
                f"Daily OTP limit exceeded for {subject}",
                sanitize_log_context(
                    {
                        "identifier": identifier,
                        "subject": subject,
                        "ip_address": ip_address,
                        "daily_limit": self.daily_limit,
                    }
                ),
            )
            return False

        # Then check basic rate limiting (per-minute limit)
        if not super().allow_request(request, subject):
            # Set a flag to indicate this is a per-minute rate limit
            self._rate_limit_type = "per_minute"
            return False

        # Note: We allow new OTPs even if active ones exist
        # The send_otp function will invalidate old OTPs automatically
        # This provides better UX while maintaining security through rate limiting

        return True

    def get_error_message(self):
        """Get specific error message based on the type of rate limit exceeded."""
        if hasattr(self, "_rate_limit_type") and self._rate_limit_type:
            if self._rate_limit_type == "per_minute":
                wait_time = self.wait()
                wait_seconds = int(wait_time) if wait_time else 60
                return f"Rate limit exceeded. You can request {self.num_requests} OTPs per {self.duration} seconds. Please try again after {wait_seconds} seconds."
            elif self._rate_limit_type == "daily":
                return (
                    f"Daily limit exceeded. You can request {self.daily_limit} OTPs per day. Please try again tomorrow."
                )
        return "Request limit exceeded. Please try again later."

    def _check_daily_limit(self, request, subject):
        """Check daily OTP generation limits per identifier."""
        identifier = request.data.get("identifier")
        if not identifier:
            return True

        # Create daily limit cache key
        now = self.timer()
        day_start = int(now // 86400) * 86400  # Start of current day
        daily_key = f"otp_daily_{identifier}_{subject}_{day_start}"

        # Get current daily count
        daily_count = self.cache.get(daily_key, 0)

        if daily_count >= self.daily_limit:
            return False

        # Increment daily count
        self.cache.set(daily_key, daily_count + 1, 86400)  # Expire at end of day
        return True

    def _check_existing_otps(self, request, subject):
        """Check if there are existing active OTPs for this identifier and subject."""
        try:
            pass

            from blockauth.models.otp import OTP

            identifier = request.data.get("identifier")
            if not identifier:
                return True

            # Check for active OTPs (not expired and not used)
            active_otps = OTP.objects.filter(identifier=identifier, subject=subject, is_used=False).count()

            # Allow if no active OTPs exist
            return active_otps == 0

        except Exception as e:
            blockauth_logger.error(
                f"Error checking existing OTPs for {subject}",
                sanitize_log_context(
                    {"identifier": request.data.get("identifier", "unknown"), "subject": subject, "error": str(e)}
                ),
            )
            # Fail open for availability
            return True


class WalletLoginThrottle(BaseThrottle):
    """
    Throttle for the SIWE challenge + login endpoints.

    Addresses issue #90 hardening item #10 ("throttle scoping"):

    * The bucket key combines client IP **and** the wallet address the request
      is targeting. Behind a load balancer where ``REMOTE_ADDR`` is the LB IP,
      every legitimate user would share a bucket under a naive IP-only scheme;
      mixing the address breaks that up for challenge-flood scenarios while
      still rate-limiting pure address-enumeration from a single IP.
    * ``get_client_ip`` is XFF-aware with the existing validation, so
      deployments behind Kong / ALB keep per-user granularity.
    * Scope key ``scope`` defaults to ``"wallet_challenge"`` or
      ``"wallet_login"`` so the challenge and login endpoints get independent
      counters (the attacker needs to successfully mint a nonce AND bomb the
      login endpoint separately to exhaust both).

    ``rate`` is ``(num_requests, duration_seconds)`` and defaults to
    ``(30, 60)`` -- 30 requests per minute per (IP, address, scope) tuple.
    That is lax enough for a user who is retrying a flaky MetaMask popup but
    tight enough to make address enumeration expensive.
    """

    cache = default_cache
    timer = time.time
    DEFAULT_RATE: tuple[int, int] = (30, 60)

    def __init__(self, scope: str = "wallet_login", rate: tuple[int, int] = None):
        self.scope = scope
        self.num_requests, self.duration = rate or self.DEFAULT_RATE

    def _extract_address(self, request) -> str:
        """Best-effort extraction of the target wallet from the request body.

        Accepts ``address`` (challenge) or ``wallet_address`` (login). Returns
        an empty string when missing — that still produces a scoped bucket,
        because the IP + scope components are always present.
        """
        data = getattr(request, "data", None) or {}
        address = data.get("wallet_address") or data.get("address") or ""
        if isinstance(address, str):
            return address.lower()[:64]
        return ""

    def get_cache_key(self, request) -> str:
        ip = get_client_ip(request) or "unknown"
        address = self._extract_address(request) or "anon"
        return f"wallet_throttle_{self.scope}_{ip}_{address}"

    def allow_request(self, request, view) -> bool:
        key = self.get_cache_key(request)
        now = self.timer()
        history = self.cache.get(key, [])
        history = [t for t in history if now - t < self.duration]

        if len(history) >= self.num_requests:
            blockauth_logger.warning(
                "Wallet throttle exceeded",
                sanitize_log_context(
                    {
                        "scope": self.scope,
                        "ip": get_client_ip(request),
                        "address": self._extract_address(request),
                        "history_len": len(history),
                        "limit": self.num_requests,
                        "duration": self.duration,
                    }
                ),
            )
            return False

        history.append(now)
        self.cache.set(key, history, self.duration)
        return True

    def wait(self):  # pragma: no cover - DRF interface
        return self.duration


class WalletChallengeThrottle(WalletLoginThrottle):
    """Default throttle for the challenge endpoint (scope = wallet_challenge)."""

    def __init__(self, rate: tuple[int, int] = None):
        super().__init__(scope="wallet_challenge", rate=rate)
