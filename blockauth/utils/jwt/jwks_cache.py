"""JWKS cache with rotation-on-kid-miss behavior.

Caches the keys fetched from a provider's JWKS endpoint. On a cache miss for an
unknown `kid` (e.g. provider rotated keys mid-window), refetches once and looks
again before reporting failure. Uses a threading lock to serialize concurrent
refetches so a thundering herd never multiplies the upstream call rate.

Failure policy: a transport-level failure (network error or non-200) leaves
`_keys_by_kid` and `_fetched_at` untouched. This avoids the failure mode where
a single transient 5xx wipes a working cache *and* marks the empty cache as
"fresh" for the entire TTL window. Surfaces as `JWKSUnreachable` when no key
is available; `KidNotFound` is reserved for "endpoint reachable, kid absent".
"""

import logging
import threading
import time
from typing import Any

import requests

from blockauth.utils.jwt.exceptions import JWKSUnreachable, KidNotFound

logger = logging.getLogger(__name__)


class JWKSCache:
    def __init__(self, jwks_uri: str, cache_ttl_seconds: int = 3600):
        self._jwks_uri = jwks_uri
        self._cache_ttl_seconds = cache_ttl_seconds
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def get_key_for_kid(self, kid: str) -> dict[str, Any]:
        cached = self._keys_by_kid.get(kid)
        if cached is not None and self._is_fresh():
            return cached

        with self._lock:
            cached = self._keys_by_kid.get(kid)
            if cached is not None and self._is_fresh():
                return cached

            # `last_fetch_ok` defaults True so the kid-miss-refetch branch below
            # still fires when the cache was simply fresh-but-missing-this-kid.
            last_fetch_ok = True
            if not self._is_fresh():
                last_fetch_ok = self._fetch_and_store()
                cached = self._keys_by_kid.get(kid)
                if cached is not None:
                    return cached
                # If the stale-refresh fetch itself failed, do not immediately
                # hammer the upstream again — short-circuit to JWKSUnreachable.
                if not last_fetch_ok:
                    raise JWKSUnreachable(f"JWKS at {self._jwks_uri} unreachable; cannot resolve kid {kid!r}")

            logger.info("oidc.verify.kid_miss_refetch", extra={"kid": kid})
            last_fetch_ok = self._fetch_and_store()
            cached = self._keys_by_kid.get(kid)
            if cached is not None:
                return cached

            if not last_fetch_ok:
                raise JWKSUnreachable(f"JWKS at {self._jwks_uri} unreachable; cannot resolve kid {kid!r}")
            logger.warning(
                "oidc.verify.kid_not_found",
                extra={"kid": kid, "jwks_uri": self._jwks_uri},
            )
            raise KidNotFound(f"kid {kid!r} not present in JWKS at {self._jwks_uri}")

    def _is_fresh(self) -> bool:
        return (time.time() - self._fetched_at) < self._cache_ttl_seconds

    def _fetch_and_store(self) -> bool:
        """Fetch JWKS and update cache.

        Returns True if a fresh response was successfully consumed (200 or 304),
        False on any failure. On failure, `_keys_by_kid` and `_fetched_at` are
        left unchanged so a transient outage cannot evict a working cache.
        """
        try:
            response = requests.get(self._jwks_uri, timeout=10)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "oidc.jwks.fetch_failed",
                extra={
                    "jwks_uri": self._jwks_uri,
                    "error_class": exc.__class__.__name__,
                },
            )
            return False

        # 304 path is unreachable today (we send no conditional headers) but
        # coding it correctly now avoids a regression once ETag /
        # If-Modified-Since support is added. Only refresh `_fetched_at` when
        # we already have keys; a 304 against an empty cache must NOT mark the
        # empty cache fresh — that would re-introduce the wipe-and-bump bug.
        if response.status_code == 304:
            if self._keys_by_kid:
                self._fetched_at = time.time()
                return True
            logger.warning(
                "oidc.jwks.fetch_failed",
                extra={"jwks_uri": self._jwks_uri, "status_code": 304, "reason": "304_with_empty_cache"},
            )
            return False

        if response.status_code != 200:
            logger.warning(
                "oidc.jwks.fetch_failed",
                extra={
                    "jwks_uri": self._jwks_uri,
                    "status_code": response.status_code,
                },
            )
            return False

        try:
            payload = response.json()
        except ValueError as exc:
            logger.warning(
                "oidc.jwks.parse_failed",
                extra={
                    "jwks_uri": self._jwks_uri,
                    "error_class": exc.__class__.__name__,
                },
            )
            return False

        self._keys_by_kid = {jwk["kid"]: jwk for jwk in payload.get("keys", []) if "kid" in jwk}
        self._fetched_at = time.time()
        logger.info(
            "oidc.jwks.refresh",
            extra={"jwks_uri": self._jwks_uri, "key_count": len(self._keys_by_kid)},
        )
        return True
