"""Shared fixtures for the E2E flow suite.

Every test resets the database via ``/auth/_test/reset/`` and receives
a :class:`BlockauthClient` bound to the running dev server.  The base
URL is taken from ``E2E_BASE_URL`` (default ``http://localhost:8000``),
so CI can point the same suite at a staging environment by exporting
the variable.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import pytest
import requests


BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8765").rstrip("/")


@dataclass
class BlockauthClient:
    """Tiny HTTP client purpose-built for the BlockAuth E2E suite."""

    base_url: str = BASE_URL
    session: requests.Session = field(default_factory=requests.Session)

    # ----- low-level ------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        expect: Optional[int] = None,
    ) -> requests.Response:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, json=json_body, headers=headers, timeout=15)
        if expect is not None and resp.status_code != expect:
            raise AssertionError(
                f"{method} {path} -> {resp.status_code} (expected {expect})\n{resp.text}"
            )
        return resp

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.request("POST", path, **kwargs)

    # ----- dev-only helpers ----------------------------------------------

    def reset(self) -> None:
        self.post("/auth/_test/reset/", expect=200)

    def latest_otp(self, identifier: str) -> str:
        resp = self.get(f"/auth/_test/otp/{identifier}/", expect=200)
        return resp.json()["code"]


@pytest.fixture(scope="session")
def ensure_server_up() -> None:
    """Abort the whole session with a clear message if no dev server is reachable."""
    try:
        requests.get(f"{BASE_URL}/auth/_test/otp/__ping__/", timeout=3)
    except requests.RequestException as exc:
        pytest.exit(
            f"E2E dev server not reachable at {BASE_URL}. "
            f"Start it with `make e2e-server` before running `make e2e-run`.\n{exc}",
            returncode=2,
        )


@pytest.fixture()
def client(ensure_server_up) -> BlockauthClient:
    c = BlockauthClient()
    c.reset()
    return c


@pytest.fixture()
def unique_email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@e2e.test"
