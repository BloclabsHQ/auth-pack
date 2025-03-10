import time

from django.core.cache import cache as default_cache
from rest_framework.throttling import BaseThrottle

from blockauth.utils.config import get_config


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
            identifier = request.user.id.hex

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