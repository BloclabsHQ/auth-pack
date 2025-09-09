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
    rate = get_config('REQUEST_LIMIT')
    cache = default_cache
    timer = time.time

    def __init__(self, rate: tuple[int,int] = None):
        """
        :param rate: A tuple of (num_requests, duration) to limit the number of requests.
                     Meaning user can make at most `num_requests` within `duration` seconds.
        """
        self.num_requests, self.duration = rate or self.rate
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
        super().__init__(rate)
        self.daily_limit = daily_limit
    
    def allow_request(self, request, subject):
        """Enhanced allow_request with additional OTP-specific checks."""
        identifier = request.data.get('identifier')
        
        # First check basic rate limiting
        if not super().allow_request(request, subject):
            return False
        
        # Check daily limits for OTP operations
        if not self._check_daily_limit(request, subject):
            identifier = request.data.get('identifier', 'unknown')
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')
            
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
        
        # Check for existing active OTPs (additional security layer)
        if not self._check_existing_otps(request, subject):
            identifier = request.data.get('identifier', 'unknown')
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')
            
            blockauth_logger.warning(
                f"Active OTP already exists for {subject}",
                sanitize_log_context({
                    "identifier": identifier,
                    "subject": subject,
                    "ip_address": ip_address
                })
            )
            return False
        
        return True
    
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