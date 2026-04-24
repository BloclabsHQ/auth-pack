"""Tests for ``blockauth.utils.auth_state.build_user_payload``.

Covers the shape fix (#128) where the helper drifted from the
``@bloclabshq/auth`` shell ``AuthUser`` schema:

* ``is_active`` always present (true + false cases).
* ``date_joined`` always present and serialized as ISO-8601 string.
* ``wallets`` is ``[]`` when ``wallet_address`` unset, ``[address]`` when set.
* ``first_name`` / ``last_name`` absent from payload when falsy, present
  as string when set.
* Downstream user model without ``first_name`` / ``last_name`` attributes
  (the ``getattr`` guard path) — payload omits both keys cleanly, no
  ``AttributeError``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from blockauth.utils.auth_state import build_user_payload


def _make_user(**overrides):
    """Build a duck-typed user stub. ``build_user_payload`` reads
    attributes only, so a ``SimpleNamespace`` is sufficient — no Django
    model or DB write needed.
    """
    defaults = {
        "id": "01936f4e-1234-7abc-8def-0123456789ab",
        "email": "user@example.com",
        "is_verified": True,
        "is_active": True,
        "date_joined": datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc),
        "wallet_address": None,
        "first_name": "",
        "last_name": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestIsActive:
    def test_is_active_true_present(self):
        payload = build_user_payload(_make_user(is_active=True))
        assert payload["is_active"] is True

    def test_is_active_false_present(self):
        payload = build_user_payload(_make_user(is_active=False))
        assert payload["is_active"] is False


class TestDateJoined:
    def test_date_joined_serialized_as_iso8601_string(self):
        joined = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)
        payload = build_user_payload(_make_user(date_joined=joined))
        assert payload["date_joined"] == "2026-04-20T12:00:00+00:00"
        assert isinstance(payload["date_joined"], str)

    def test_date_joined_none_emits_null(self):
        payload = build_user_payload(_make_user(date_joined=None))
        assert payload["date_joined"] is None


class TestWallets:
    def test_wallets_empty_when_unset(self):
        payload = build_user_payload(_make_user(wallet_address=None))
        assert payload["wallets"] == []
        assert payload["wallet_address"] is None

    def test_wallets_populated_when_set(self):
        """#537: wallets must be ``WalletItem[]`` not ``string[]`` — the
        shell's Zod schema rejects bare address strings."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        payload = build_user_payload(_make_user(wallet_address=address))
        assert payload["wallet_address"] == address
        assert len(payload["wallets"]) == 1
        item = payload["wallets"][0]
        assert item["address"] == address
        assert item["chain_id"] == 1
        assert item["primary"] is True
        assert item["label"] is None
        assert "linked_at" in item


class TestFirstLastNameDropWhenFalsy:
    def test_first_name_absent_when_empty_string(self):
        payload = build_user_payload(_make_user(first_name=""))
        assert "first_name" not in payload

    def test_first_name_absent_when_none(self):
        payload = build_user_payload(_make_user(first_name=None))
        assert "first_name" not in payload

    def test_first_name_present_when_set(self):
        payload = build_user_payload(_make_user(first_name="Ada"))
        assert payload["first_name"] == "Ada"

    def test_last_name_absent_when_empty_string(self):
        payload = build_user_payload(_make_user(last_name=""))
        assert "last_name" not in payload

    def test_last_name_present_when_set(self):
        payload = build_user_payload(_make_user(last_name="Lovelace"))
        assert payload["last_name"] == "Lovelace"


class TestGetattrGuard:
    """Downstream user models that never added ``first_name`` /
    ``last_name`` fields should not trigger ``AttributeError``. Same
    for ``date_joined`` (not defined on ``AbstractBaseUser``) — the
    helper reads it defensively and emits ``None`` when absent.
    """

    def test_user_without_name_fields_omits_keys(self):
        user = SimpleNamespace(
            id="01936f4e-1234-7abc-8def-0123456789ab",
            email="user@example.com",
            is_verified=True,
            is_active=True,
            date_joined=datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc),
            wallet_address=None,
        )
        payload = build_user_payload(user)
        assert "first_name" not in payload
        assert "last_name" not in payload
        assert payload["id"] == "01936f4e-1234-7abc-8def-0123456789ab"
        assert payload["wallets"] == []

    def test_user_without_date_joined_emits_null(self):
        """``BlockUser`` extends ``AbstractBaseUser``, which has no
        ``date_joined`` field. The helper must not crash on such models.
        """
        user = SimpleNamespace(
            id="01936f4e-1234-7abc-8def-0123456789ab",
            email="user@example.com",
            is_verified=True,
            is_active=True,
            wallet_address=None,
        )
        payload = build_user_payload(user)
        assert payload["date_joined"] is None
        assert payload["is_active"] is True

    def test_user_without_is_active_defaults_true(self):
        """``AbstractBaseUser.is_active`` is a class attribute (default
        ``True``). Downstream models that drop it entirely still get a
        sensible default.
        """
        user = SimpleNamespace(
            id="01936f4e-1234-7abc-8def-0123456789ab",
            email="user@example.com",
            is_verified=True,
            wallet_address=None,
        )
        payload = build_user_payload(user)
        assert payload["is_active"] is True


class TestFullShape:
    def test_payload_contains_all_required_keys(self):
        address = "0x1234567890abcdef1234567890abcdef12345678"
        payload = build_user_payload(
            _make_user(
                wallet_address=address,
                first_name="Ada",
                last_name="Lovelace",
            )
        )
        assert set(payload.keys()) == {
            "id",
            "email",
            "is_verified",
            "is_active",
            "date_joined",
            "wallet_address",
            "wallets",
            "first_name",
            "last_name",
        }
