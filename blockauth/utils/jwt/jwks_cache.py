"""JWKS cache with rotation-on-kid-miss behavior.

Caches the keys fetched from a provider's JWKS endpoint. On a cache miss for an
unknown `kid` (e.g. provider rotated keys mid-window), refetches once and looks
again before reporting failure. Uses a threading lock to serialize concurrent
refetches so a thundering herd never multiplies the upstream call rate.
"""

import logging
import threading
import time
from typing import Any

import requests

from blockauth.utils.jwt.exceptions import KidNotFound

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
            if not self._is_fresh():
                self._fetch_and_store()
                cached = self._keys_by_kid.get(kid)
                if cached is not None:
                    return cached

            logger.info("oidc.verify.kid_miss_refetch", extra={"kid": kid})
            self._fetch_and_store()
            cached = self._keys_by_kid.get(kid)
            if cached is None:
                raise KidNotFound(f"kid {kid!r} not present in JWKS at {self._jwks_uri}")
            return cached

    def _is_fresh(self) -> bool:
        return (time.time() - self._fetched_at) < self._cache_ttl_seconds

    def _fetch_and_store(self) -> None:
        response = requests.get(self._jwks_uri, timeout=5)
        if response.status_code != 200:
            self._keys_by_kid = {}
            self._fetched_at = time.time()
            return
        payload = response.json()
        self._keys_by_kid = {jwk["kid"]: jwk for jwk in payload.get("keys", []) if "kid" in jwk}
        self._fetched_at = time.time()
