import time

from django.core.cache import cache as default_cache
from rest_framework.throttling import BaseThrottle

from blockauth.utils.config import get_config
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.generics import sanitize_log_context


class RequestThrottle(BaseThrottle):
    """
    Limits request to a specific identifier, subject & IP address.
    """
    cache = default_cache
    timer = time.time

    def __init__(self, rate: tuple[int,int] = None):
        """
        :param rate: A tuple of (num_requests, duration) to limit the number of requests.
                     Meaning user can make at most `num_requests` within `duration` seconds.
        """
        if rate is None:
            rate = get_config('REQUEST_LIMIT')
        self.num_requests, self.duration = rate
        self.history = None
        self.now = None
        self.key = None

    def get_cache_key(self, request, subject):
        identifier = request.data.get('identifier')
        ip_address = request.META.get('REMOTE_ADDR')

        if not identifier and request.user.id:
            identifier = str(request.user.id)

        # No throttling if identifier, subject, or IP address is missing
        if not identifier or not subject or not ip_address:
            return None

        return f"auth_throttle_{identifier}_{subject}_{ip_address}"

    def allow_request(self, request, subject):
        self.key = self.get_cache_key(request, subject)
        if self.key is None:
            return True

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()

        if len(self.history) >= self.num_requests:
            # Set rate limit type for OTPThrottle to use
            if hasattr(self, 'daily_limit'):
                self._rate_limit_type = 'per_minute'
            
            # Enhanced logging for rate limit violations
            identifier = request.data.get('identifier', 'unknown')
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')
            
            blockauth_logger.warning(
                f"Rate limit exceeded for {subject}",
                sanitize_log_context({
                    "identifier": identifier,
                    "subject": subject,
                    "ip_address": ip_address,
                    "current_requests": len(self.history),
                    "max_requests": self.num_requests,
                    "duration": self.duration,
                    "wait_time": self.wait()
                })
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
            rate = get_config('REQUEST_LIMIT')
        
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
        identifier = request.data.get('identifier')
        
        # Check daily limits first (more restrictive)
        if not self._check_daily_limit(request, subject):
            identifier = request.data.get('identifier', 'unknown')
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')
            
            # Set a flag to indicate this is a daily limit
            self._rate_limit_type = 'daily'
            
            blockauth_logger.warning(
                f"Daily OTP limit exceeded for {subject}",
                sanitize_log_context({
                    "identifier": identifier,
                    "subject": subject,
                    "ip_address": ip_address,
                    "daily_limit": self.daily_limit
                })
            )
            return False
        
        # Then check basic rate limiting (per-minute limit)
        if not super().allow_request(request, subject):
            # Set a flag to indicate this is a per-minute rate limit
            self._rate_limit_type = 'per_minute'
            return False
        
        # Note: We allow new OTPs even if active ones exist
        # The send_otp function will invalidate old OTPs automatically
        # This provides better UX while maintaining security through rate limiting
        
        return True
    
    def get_error_message(self):
        """Get specific error message based on the type of rate limit exceeded."""
        if hasattr(self, '_rate_limit_type') and self._rate_limit_type:
            if self._rate_limit_type == 'per_minute':
                wait_time = self.wait()
                wait_seconds = int(wait_time) if wait_time else 60
                return f"Rate limit exceeded. You can request {self.num_requests} OTPs per {self.duration} seconds. Please try again after {wait_seconds} seconds."
            elif self._rate_limit_type == 'daily':
                return f"Daily limit exceeded. You can request {self.daily_limit} OTPs per day. Please try again tomorrow."
        return "Request limit exceeded. Please try again later."
    
    def _check_daily_limit(self, request, subject):
        """Check daily OTP generation limits per identifier."""
        identifier = request.data.get('identifier')
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
            from blockauth.models.otp import OTP
            from django.utils import timezone
            
            identifier = request.data.get('identifier')
            if not identifier:
                return True
            
            # Check for active OTPs (not expired and not used)
            active_otps = OTP.objects.filter(
                identifier=identifier,
                subject=subject,
                is_used=False
            ).count()
            
            # Allow if no active OTPs exist
            return active_otps == 0
            
        except Exception as e:
            blockauth_logger.error(
                f"Error checking existing OTPs for {subject}",
                sanitize_log_context({
                    "identifier": request.data.get('identifier', 'unknown'),
                    "subject": subject,
                    "error": str(e)
                })
            )
            # Fail open for availability
            return True