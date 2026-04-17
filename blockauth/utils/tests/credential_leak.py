"""Shared test helper for asserting login responses don't leak credentials.

Issue #99 lock-down: the ``user`` payload returned by every login-style
endpoint (basic-login, passwordless-login, wallet-login) must never carry
password-hash material or private Django ``_state``-style attributes. This
module centralises the allow-list and the assertion helper so every login
test shares one source of truth -- adding a new forbidden field only
requires updating ``FORBIDDEN_USER_PAYLOAD_KEYS`` here.

The check recurses into nested dicts and into dict elements inside
lists/tuples so a future refactor that buries credentials under a
``credentials`` sub-object (or returns ``[{...}]`` lists) still trips the
guard. Top-level-only was the original shape; the recursion is defence in
depth against future serializer changes.
"""

from __future__ import annotations

from typing import Any

# Adding a new forbidden field: append it here. No test-file edit needed.
FORBIDDEN_USER_PAYLOAD_KEYS = frozenset(
    {"password", "password_hash", "hashed_password"}
)


def assert_no_credential_leak(user_payload: Any) -> None:
    """Fail loudly if a login response's ``user`` object carries secrets.

    Asserts:

    * The payload is a non-empty mapping -- an empty ``{}`` is almost
      certainly a regression ("serializer returned nothing") rather than a
      safe "no credentials leaked" state, so we refuse to silently pass it.
    * No key is in :data:`FORBIDDEN_USER_PAYLOAD_KEYS` (``password`` /
      ``password_hash`` / ``hashed_password``).
    * No key starts with ``_`` -- Django / DRF attach private state under
      ``_state`` and friends and those must never go over the wire.
    * Nested dict values are walked recursively; list / tuple values have
      their dict elements walked. Non-mapping leaves are ignored.

    Deliberately strict so that the assertion fails closed on structural
    changes -- the whole point of the helper is to catch a future refactor
    to a ``ModelSerializer`` with ``fields = "__all__"``.
    """
    assert user_payload, "user payload must not be empty"
    _walk(user_payload)


def _walk(node: Any) -> None:
    """Recurse into ``node``, flagging forbidden keys wherever they appear."""
    if isinstance(node, dict):
        for key, value in node.items():
            assert key not in FORBIDDEN_USER_PAYLOAD_KEYS, (
                f"Forbidden credential field '{key}' leaked in login user payload"
            )
            assert not (isinstance(key, str) and key.startswith("_")), (
                f"Private field '{key}' leaked in login user payload"
            )
            _walk(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk(item)
    # Non-container leaves (str, int, None, UUID, ...) are fine -- the
    # check is about keys, not values. A string value that happens to
    # equal "password" is not a leak.
