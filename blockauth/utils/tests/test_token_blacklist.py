"""
Tests for refresh token blacklist.

Covers:
- Blacklisting a token's jti
- Detecting blacklisted tokens
- Fresh tokens are not blacklisted
- Empty/None jti handling
- TTL expiry behavior
"""

import pytest
from django.core.cache import cache

from blockauth.utils.token_blacklist import blacklist_token, is_blacklisted


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


class TestBlacklistToken:
    def test_blacklisted_token_is_detected(self):
        blacklist_token("test-jti-001", remaining_ttl_seconds=3600)
        assert is_blacklisted("test-jti-001") is True

    def test_fresh_token_not_blacklisted(self):
        assert is_blacklisted("never-seen-jti") is False

    def test_different_jti_not_affected(self):
        blacklist_token("jti-A", remaining_ttl_seconds=3600)
        assert is_blacklisted("jti-B") is False

    def test_empty_jti_blacklist_is_noop(self):
        blacklist_token("", remaining_ttl_seconds=3600)
        assert is_blacklisted("") is False

    def test_none_jti_blacklist_is_noop(self):
        blacklist_token(None, remaining_ttl_seconds=3600)
        assert is_blacklisted(None) is False

    def test_zero_remaining_ttl_still_blacklists(self):
        """Even with 0 remaining TTL, we keep a 60s buffer."""
        blacklist_token("jti-zero-ttl", remaining_ttl_seconds=0)
        assert is_blacklisted("jti-zero-ttl") is True

    def test_custom_cache_backend(self):
        """Verify the cache override parameter works."""
        custom_cache = {}

        class FakeCache:
            def set(self, key, value, ttl):
                custom_cache[key] = value

            def get(self, key):
                return custom_cache.get(key)

        fake = FakeCache()
        blacklist_token("jti-custom", remaining_ttl_seconds=100, cache=fake)
        assert is_blacklisted("jti-custom", cache=fake) is True
        # Should NOT appear in default Django cache
        assert is_blacklisted("jti-custom") is False
