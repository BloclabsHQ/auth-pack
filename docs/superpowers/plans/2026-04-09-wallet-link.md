# Wallet Link Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /wallet/link/` so authenticated email/OAuth users can link a MetaMask wallet to their account.

**Architecture:** View + serializer pattern matching `WalletEmailAddView`. Signature verification delegated entirely to the existing `WalletAuthenticator` (replay protection, nonce, timestamp all included). Business logic lives in `WalletLinkSerializer`; `WalletLinkView` handles throttle, saves, fires trigger.

**Tech Stack:** Python 3.12, Django 5.x, Django REST Framework 3.14, pytest, uv, Docker (test runner only)

**Spec:** `docs/superpowers/specs/2026-04-08-wallet-link-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `Dockerfile` | Create | Reproducible test runner image |
| `docker-compose.yml` | Create | `docker compose run --rm test` shortcut |
| `blockauth/constants/core.py` | Modify | Add `Features.WALLET_LINK`, `URLNames.WALLET_LINK` |
| `blockauth/conf.py` | Modify | Add `WALLET_LINK` feature flag + `POST_WALLET_LINK_TRIGGER` |
| `blockauth/triggers.py` | Modify | Add `DummyPostWalletLinkTrigger` |
| `blockauth/utils/custom_exception.py` | Modify | Add `WalletConflictError` (HTTP 409) |
| `blockauth/serializers/wallet_serializers.py` | Modify | Add `WalletLinkSerializer` |
| `blockauth/views/wallet_auth_views.py` | Modify | Add `WalletLinkView` |
| `blockauth/urls.py` | Modify | Register `wallet/link/` URL pattern |
| `blockauth/utils/tests/test_wallet_link_serializer.py` | Create | Serializer unit tests |
| `blockauth/views/tests/__init__.py` | Create | Package marker |
| `blockauth/views/tests/test_wallet_link_view.py` | Create | View integration tests |

---

## Task 1: Docker Test Environment

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`

- [ ] **Step 1: Create Dockerfile**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock ./
RUN uv sync
COPY . .
CMD ["uv", "run", "pytest", "-v"]
```

- [ ] **Step 2: Create docker-compose.yml**

```yaml
services:
  test:
    build: .
    command: uv run pytest -v
```

- [ ] **Step 3: Build and run existing tests in Docker**

Run:
```bash
docker compose build
docker compose run --rm test
```

Expected: all existing tests pass, no errors in the build step.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "chore: add Docker test runner for local validation"
```

---

## Task 2: Constants

**Files:**
- Modify: `blockauth/constants/core.py`

- [ ] **Step 1: Write the failing test**

Create `blockauth/utils/tests/test_wallet_link_constants.py`:

```python
from blockauth.constants import Features, URLNames


def test_wallet_link_feature_constant_exists():
    assert Features.WALLET_LINK == "WALLET_LINK"


def test_wallet_link_feature_in_all_features():
    assert "WALLET_LINK" in Features.all_features()


def test_wallet_link_url_name_constant_exists():
    assert URLNames.WALLET_LINK == "wallet-link"
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_constants.py -v
```

Expected: `AttributeError: type object 'Features' has no attribute 'WALLET_LINK'`

- [ ] **Step 3: Add constants to `blockauth/constants/core.py`**

In the `Features` class, after `WALLET_EMAIL_ADD = "WALLET_EMAIL_ADD"`:

```python
# Wallet linking (email/OAuth user links an external wallet)
WALLET_LINK = "WALLET_LINK"
```

In `Features.all_features()`, add `cls.WALLET_LINK` to the return list:

```python
return [
    cls.SIGNUP,
    cls.BASIC_LOGIN,
    cls.PASSWORDLESS_LOGIN,
    cls.WALLET_LOGIN,
    cls.TOKEN_REFRESH,
    cls.PASSWORD_RESET,
    cls.PASSWORD_CHANGE,
    cls.EMAIL_CHANGE,
    cls.EMAIL_VERIFICATION,
    cls.WALLET_EMAIL_ADD,
    cls.WALLET_LINK,
    cls.SOCIAL_AUTH,
    cls.PASSKEY_AUTH,
    cls.TOTP_2FA,
]
```

In the `URLNames` class, after `WALLET_EMAIL_ADD = "wallet-email-add"`:

```python
WALLET_LINK = "wallet-link"
```

- [ ] **Step 4: Run to verify pass**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_constants.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/constants/core.py blockauth/utils/tests/test_wallet_link_constants.py
git commit -m "feat: add WALLET_LINK feature constant and URL name"
```

---

## Task 3: Config and Trigger

**Files:**
- Modify: `blockauth/conf.py`
- Modify: `blockauth/triggers.py`

- [ ] **Step 1: Add feature flag to `blockauth/conf.py`**

In the `FEATURES` dict inside `DEFAULTS`, after `"WALLET_EMAIL_ADD": True`:

```python
"WALLET_LINK": True,  # Enable linking a MetaMask wallet to an existing account
```

After the existing trigger defaults (`POST_PASSWORD_RESET_TRIGGER`), add:

```python
"POST_WALLET_LINK_TRIGGER": "blockauth.triggers.DummyPostWalletLinkTrigger",
```

Add `"POST_WALLET_LINK_TRIGGER"` to the `IMPORT_STRINGS` tuple:

```python
IMPORT_STRINGS = (
    "DEFAULT_NOTIFICATION_CLASS",
    "POST_SIGNUP_TRIGGER",
    "PRE_SIGNUP_TRIGGER",
    "POST_LOGIN_TRIGGER",
    "POST_PASSWORD_CHANGE_TRIGGER",
    "POST_PASSWORD_RESET_TRIGGER",
    "POST_WALLET_LINK_TRIGGER",
    "BLOCK_AUTH_LOGGER_CLASS",
)
```

- [ ] **Step 2: Add `DummyPostWalletLinkTrigger` to `blockauth/triggers.py`**

After `DummyPostPasswordResetTrigger`, add:

```python
class DummyPostWalletLinkTrigger(BaseTrigger):
    """
    Default no-op trigger fired after a user successfully links a wallet.

    Replace with a real implementation to handle post-link events
    such as syncing wallet data or updating JWT claims.

    Context keys:
        user (dict): Serialized user data (no password).
        wallet_address (str): The wallet address that was linked.
    """

    def trigger(self, context: dict) -> None:
        pass
```

- [ ] **Step 3: Write a smoke test for the trigger**

Append to `blockauth/utils/tests/test_wallet_link_constants.py`:

```python
from blockauth.triggers import DummyPostWalletLinkTrigger
from blockauth.utils.config import get_config


def test_dummy_post_wallet_link_trigger_is_no_op():
    trigger = DummyPostWalletLinkTrigger()
    trigger.trigger(context={"user": {}, "wallet_address": "0xabc"})  # must not raise


def test_post_wallet_link_trigger_resolves_from_config():
    trigger_class = get_config("POST_WALLET_LINK_TRIGGER")
    assert trigger_class is DummyPostWalletLinkTrigger
```

- [ ] **Step 4: Run to verify pass**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_constants.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/conf.py blockauth/triggers.py blockauth/utils/tests/test_wallet_link_constants.py
git commit -m "feat: add WALLET_LINK feature flag and DummyPostWalletLinkTrigger"
```

---

## Task 4: WalletConflictError

**Files:**
- Modify: `blockauth/utils/custom_exception.py`

- [ ] **Step 1: Write the failing test**

Create `blockauth/utils/tests/test_wallet_conflict_error.py`:

```python
from blockauth.utils.custom_exception import WalletConflictError


def test_wallet_conflict_error_has_409_status():
    assert WalletConflictError.status_code == 409


def test_wallet_conflict_error_is_raised_with_detail():
    error = WalletConflictError(detail="This wallet address is already linked to another account.")
    assert error.status_code == 409
    assert "already linked" in str(error.detail)
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_conflict_error.py -v
```

Expected: `ImportError: cannot import name 'WalletConflictError'`

- [ ] **Step 3: Add `WalletConflictError` to `blockauth/utils/custom_exception.py`**

```python
class WalletConflictError(APIException):
    """Raised when a wallet address is already linked to a different account (HTTP 409)."""

    status_code = 409
    default_detail = "This wallet address is already linked to another account."
    default_code = "WALLET_IN_USE"
```

- [ ] **Step 4: Run to verify pass**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_conflict_error.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/utils/custom_exception.py blockauth/utils/tests/test_wallet_conflict_error.py
git commit -m "feat: add WalletConflictError (HTTP 409) for wallet-in-use case"
```

---

## Task 5: WalletLinkSerializer (TDD)

**Files:**
- Create: `blockauth/utils/tests/test_wallet_link_serializer.py`
- Modify: `blockauth/serializers/wallet_serializers.py`

- [ ] **Step 1: Write the failing tests**

Create `blockauth/utils/tests/test_wallet_link_serializer.py`:

```python
"""
Unit tests for WalletLinkSerializer.

WalletAuthenticator.verify_signature is mocked throughout — replay protection
and crypto are covered by test_wallet_replay_protection.py.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from blockauth.serializers.wallet_serializers import WalletLinkSerializer
from blockauth.utils.custom_exception import WalletConflictError


def _make_request(wallet_address=None):
    """Return a mock request whose user has the given wallet_address."""
    user = MagicMock()
    user.pk = "user-test-uuid-123"
    user.wallet_address = wallet_address
    request = MagicMock()
    request.user = user
    return request


def _make_data(wallet_address="0xabcdef1234567890abcdef1234567890abcdef12"):
    return {
        "wallet_address": wallet_address,
        "message": json.dumps({
            "nonce": "test-nonce-0000-1111-2222",
            "timestamp": int(time.time()),
            "body": "Link wallet to TestApp",
        }),
        "signature": "0x" + "a" * 130,
    }


# ---------------------------------------------------------------------------
# Address field validation
# ---------------------------------------------------------------------------

class TestValidateWalletAddress:
    def test_valid_address_is_lowercased(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(
                data=_make_data("0xABCDEF1234567890ABCDEF1234567890ABCDEF12"),
                context={"request": request},
            )
            assert s.is_valid(), s.errors
            assert s.validated_data["wallet_address"] == "0xabcdef1234567890abcdef1234567890abcdef12"

    def test_address_without_0x_prefix_is_invalid(self):
        request = _make_request()
        s = WalletLinkSerializer(
            data=_make_data("abcdef1234567890abcdef1234567890abcdef12"),
            context={"request": request},
        )
        assert not s.is_valid()
        assert "wallet_address" in s.errors

    def test_address_wrong_length_is_invalid(self):
        request = _make_request()
        s = WalletLinkSerializer(
            data=_make_data("0xshort"),
            context={"request": request},
        )
        assert not s.is_valid()
        assert "wallet_address" in s.errors


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    def test_verify_signature_returns_false_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "signature" in s.errors

    def test_expired_message_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError("Message has expired. Please sign a new message.")
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "message" in s.errors
            assert "expired" in str(s.errors["message"]).lower()

    def test_nonce_reused_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError("Nonce has already been used. Please sign a new message.")
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "message" in s.errors


# ---------------------------------------------------------------------------
# Business rule validation
# ---------------------------------------------------------------------------

class TestBusinessRules:
    def test_wallet_in_use_by_another_user_raises_conflict(self):
        request = _make_request(wallet_address=None)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = True
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            with pytest.raises(WalletConflictError):
                s.is_valid(raise_exception=True)

    def test_user_already_has_wallet_gives_400(self):
        existing = "0x1111111111111111111111111111111111111111"
        request = _make_request(wallet_address=existing)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "wallet_address" in s.errors

    def test_valid_unlinked_user_passes_validation(self):
        request = _make_request(wallet_address=None)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert s.is_valid(), s.errors
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_serializer.py -v
```

Expected: `ImportError: cannot import name 'WalletLinkSerializer'`

- [ ] **Step 3: Implement `WalletLinkSerializer` in `blockauth/serializers/wallet_serializers.py`**

Add after the `WalletEmailAddSerializer` class:

```python
class WalletLinkSerializer(serializers.Serializer):
    """
    Validates a wallet link request from an already-authenticated user.

    Performs full signature verification (including replay protection) via
    WalletAuthenticator. Raises WalletConflictError (409) if the address
    belongs to another user, ValidationError (400) if the user already has
    a wallet linked.
    """

    wallet_address = serializers.CharField(max_length=42, help_text="Ethereum wallet address (0x...)")
    message = serializers.CharField(help_text="JSON-encoded message with nonce + timestamp that was signed.")
    signature = serializers.CharField(
        max_length=132, help_text="Ethereum signature (0x-prefixed, 130 hex chars)"
    )

    def validate_wallet_address(self, value):
        if not value.startswith("0x") or len(value) != 42:
            raise ValidationError(
                detail={
                    "wallet_address": "Invalid wallet address format. Must be a 42-character hex string starting with 0x."
                }
            )
        return value.lower()

    def validate(self, data):
        super().validate(data)

        wallet_address = data.get("wallet_address")
        message = data.get("message")
        signature = data.get("signature")
        request = self.context.get("request")

        # 1. Verify signature — replay protection, nonce, timestamp all handled here
        try:
            authenticator = WalletAuthenticator()
            if not authenticator.verify_signature(wallet_address, message, signature):
                raise ValidationError(
                    detail={"signature": "Invalid signature. Signature verification failed."}, code="INVALID_SIGNATURE"
                )
        except ValueError as e:
            raise ValidationError(detail={"message": str(e)}, code="INVALID_SIGNATURE")
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            raise ValidationError(detail={"signature": "Signature verification failed."}, code="INVALID_SIGNATURE")

        # 2. Wallet must not belong to a different account
        from blockauth.utils.custom_exception import WalletConflictError

        if _User.objects.filter(wallet_address=wallet_address).exclude(pk=request.user.pk).exists():
            raise WalletConflictError()

        # 3. User must not already have a wallet linked
        if request.user.wallet_address:
            raise ValidationError(
                detail={"wallet_address": "Your account already has a linked wallet. Unlink it first."},
                code="WALLET_ALREADY_LINKED",
            )

        return data
```

Also add to the top-level imports of `wallet_serializers.py` (it already imports `WalletAuthenticator`; no new imports needed beyond what's already there).

- [ ] **Step 4: Run to verify pass**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_serializer.py -v
```

Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add blockauth/serializers/wallet_serializers.py blockauth/utils/tests/test_wallet_link_serializer.py
git commit -m "feat: add WalletLinkSerializer with signature verification and business rules"
```

---

## Task 6: WalletLinkView (TDD)

**Files:**
- Create: `blockauth/views/tests/__init__.py`
- Create: `blockauth/views/tests/test_wallet_link_view.py`
- Modify: `blockauth/views/wallet_auth_views.py`

- [ ] **Step 1: Create test package marker**

Create an empty `blockauth/views/tests/__init__.py`:

```python
```

- [ ] **Step 2: Write the failing tests**

Create `blockauth/views/tests/test_wallet_link_view.py`:

```python
"""
Integration tests for WalletLinkView.

WalletAuthenticator.verify_signature is mocked — crypto is not under test here.
Focus: HTTP contract, persistence, trigger firing, rate limiting, auth gate.
"""

import json
import time
from unittest.mock import MagicMock, call, patch

import pytest
from rest_framework import status
from rest_framework.test import APIRequestFactory

from blockauth.views.wallet_auth_views import WalletLinkView

factory = APIRequestFactory()
VIEW = WalletLinkView.as_view()

VALID_ADDRESS = "0xabcdef1234567890abcdef1234567890abcdef12"


def _make_payload(wallet_address=VALID_ADDRESS):
    return {
        "wallet_address": wallet_address,
        "message": json.dumps({
            "nonce": "test-nonce-0000-1111-2222",
            "timestamp": int(time.time()),
            "body": "Link wallet to TestApp",
        }),
        "signature": "0x" + "a" * 130,
    }


def _make_user(wallet_address=None):
    user = MagicMock()
    user.id = "user-test-uuid-123"
    user.pk = "user-test-uuid-123"
    user.wallet_address = wallet_address
    user.is_authenticated = True
    user.authentication_types = []
    return user


def _patch_sig_valid(target_user=None):
    """Context manager stack: valid signature + no wallet conflict."""
    return (
        patch("blockauth.serializers.wallet_serializers.WalletAuthenticator"),
        patch("blockauth.serializers.wallet_serializers._User"),
        patch("blockauth.views.wallet_auth_views.get_config"),
        patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}),
    )


# ---------------------------------------------------------------------------
# Authentication gate
# ---------------------------------------------------------------------------

class TestAuthGate:
    def test_unauthenticated_returns_401(self):
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = MagicMock(is_authenticated=False)
        response = VIEW(request)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

class TestSuccessPath:
    def test_valid_request_returns_200(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model, \
             patch("blockauth.views.wallet_auth_views.get_config") as mock_config, \
             patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            response = VIEW(request)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["wallet_address"] == VALID_ADDRESS
        assert "message" in response.data

    def test_valid_request_saves_wallet_address_on_user(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model, \
             patch("blockauth.views.wallet_auth_views.get_config") as mock_config, \
             patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            VIEW(request)

        assert user.wallet_address == VALID_ADDRESS
        user.save.assert_called()

    def test_valid_request_adds_wallet_authentication_type(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model, \
             patch("blockauth.views.wallet_auth_views.get_config") as mock_config, \
             patch("blockauth.views.wallet_auth_views.model_to_json", return_value={}):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = MagicMock()
            VIEW(request)

        user.add_authentication_type.assert_called_once_with("WALLET")

    def test_post_wallet_link_trigger_fires_with_correct_context(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user
        mock_trigger = MagicMock()

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model, \
             patch("blockauth.views.wallet_auth_views.get_config") as mock_config, \
             patch("blockauth.views.wallet_auth_views.model_to_json", return_value={"id": "user-test-uuid-123"}):
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            mock_config.return_value.return_value = mock_trigger
            VIEW(request)

        mock_trigger.trigger.assert_called_once()
        ctx = mock_trigger.trigger.call_args[1]["context"]
        assert ctx["wallet_address"] == VALID_ADDRESS
        assert "user" in ctx
        assert "password" not in str(ctx)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestErrorPaths:
    def test_wallet_already_linked_returns_400(self):
        user = _make_user(wallet_address="0x1111111111111111111111111111111111111111")
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_wallet_in_use_returns_409(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = True
            response = VIEW(request)

        assert response.status_code == status.HTTP_409_CONFLICT

    def test_invalid_signature_returns_400(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.return_value = False
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_expired_message_returns_400(self):
        user = _make_user()
        request = factory.post("/wallet/link/", data=_make_payload(), format="json")
        request.user = user

        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError("Message has expired. Please sign a new message.")
            response = VIEW(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------

class TestFeatureFlag:
    def test_wallet_link_url_absent_when_feature_disabled(self):
        from unittest.mock import patch as _patch
        from blockauth.urls import build_urlpatterns

        with _patch("blockauth.urls.is_feature_enabled", side_effect=lambda f: f != "WALLET_LINK"):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-link" not in names

    def test_wallet_link_url_present_when_feature_enabled(self):
        from blockauth.urls import build_urlpatterns

        with patch("blockauth.urls.is_feature_enabled", return_value=True), \
             patch("blockauth.urls.is_social_auth_configured", return_value=False):
            patterns = build_urlpatterns()
            names = [p.name for p in patterns if hasattr(p, "name")]
            assert "wallet-link" in names
```

- [ ] **Step 3: Run to verify failure**

Run:
```bash
uv run pytest blockauth/views/tests/test_wallet_link_view.py -v
```

Expected: `ImportError: cannot import name 'WalletLinkView'`

- [ ] **Step 4: Implement `WalletLinkView` in `blockauth/views/wallet_auth_views.py`**

Make these exact import changes at the top of the file:

Change line 10 (wallet_auth_docs import) to also include `wallet_link_docs` — **skip this for now**, the view won't use `@extend_schema` yet.

Change line 13:
```python
# Before
from blockauth.serializers.wallet_serializers import WalletEmailAddSerializer, WalletLoginSerializer
# After
from blockauth.serializers.wallet_serializers import WalletEmailAddSerializer, WalletLinkSerializer, WalletLoginSerializer
```

Change line 14:
```python
# Before
from blockauth.utils.config import get_block_auth_user_model
# After
from blockauth.utils.config import get_block_auth_user_model, get_config
```

Change line 15:
```python
# Before
from blockauth.utils.custom_exception import ValidationErrorWithCode
# After
from blockauth.utils.custom_exception import ValidationErrorWithCode, WalletConflictError
```

Change line 16:
```python
# Before
from blockauth.utils.generics import sanitize_log_context
# After
from blockauth.utils.generics import model_to_json, sanitize_log_context
```

Add after line 18 (after the `EnhancedThrottle` import):
```python
from blockauth.enums import AuthenticationType
```

Add after `WalletEmailAddView`:

```python
class WalletLinkView(APIView):
    """
    API endpoint for authenticated users to link a MetaMask (or compatible) wallet.

    The user must already hold a valid JWT. They sign a structured JSON message
    with their wallet and submit address + message + signature. Full replay
    protection (nonce + timestamp) is enforced by WalletAuthenticator.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = WalletLinkSerializer
    link_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    def post(self, request):
        if not self.link_throttle.allow_request(request, "wallet_link"):
            reason = self.link_throttle.get_block_reason()
            msg = (
                "Too many failed attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data, context={"request": request})
        blockauth_logger.info("Wallet link attempt", sanitize_log_context(request.data))

        try:
            serializer.is_valid(raise_exception=True)

            user = request.user
            wallet_address = serializer.validated_data["wallet_address"]

            user.wallet_address = wallet_address
            user.add_authentication_type(AuthenticationType.WALLET)
            user.save()

            user_data = model_to_json(user, remove_fields=("password",))
            post_wallet_link_trigger = get_config("POST_WALLET_LINK_TRIGGER")()
            post_wallet_link_trigger.trigger(context={"user": user_data, "wallet_address": wallet_address})

            self.link_throttle.record_success(request, "wallet_link")
            blockauth_logger.success(
                "Wallet linked successfully",
                sanitize_log_context(request.data, {"user": user.id}),
            )

            return Response(
                data={"message": "Wallet linked successfully.", "wallet_address": wallet_address},
                status=status.HTTP_200_OK,
            )

        except WalletConflictError:
            self.link_throttle.record_failure(request, "wallet_link")
            raise

        except ValidationError as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.warning(
                "Wallet link validation failed",
                sanitize_log_context(request.data, {"errors": e.detail}),
            )
            raise ValidationErrorWithCode(detail=e.detail)

        except Exception as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.error("Wallet link failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet link request failed: {e}", exc_info=True)
            raise APIException()
```

Also add the missing imports to the top of `wallet_auth_views.py`. Current imports include `sanitize_log_context` but not `model_to_json` or `WalletConflictError`. Add:

```python
from blockauth.utils.custom_exception import ValidationErrorWithCode, WalletConflictError
from blockauth.utils.generics import model_to_json, sanitize_log_context
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.enums import AuthenticationType
```

Check the current imports in the file and add only lines that are not already present.

- [ ] **Step 5: Run to verify pass**

Run:
```bash
uv run pytest blockauth/views/tests/test_wallet_link_view.py -v
```

Expected: all tests passed.

- [ ] **Step 6: Commit**

```bash
git add blockauth/views/wallet_auth_views.py \
        blockauth/views/tests/__init__.py \
        blockauth/views/tests/test_wallet_link_view.py
git commit -m "feat: add WalletLinkView — POST /wallet/link/ for authenticated users"
```

---

## Task 7: Wire Up the URL

**Files:**
- Modify: `blockauth/urls.py`

- [ ] **Step 1: Update imports in `blockauth/urls.py`**

Change the existing wallet import line from:

```python
from blockauth.views.wallet_auth_views import WalletAuthLoginView, WalletEmailAddView
```

To:

```python
from blockauth.views.wallet_auth_views import WalletAuthLoginView, WalletEmailAddView, WalletLinkView
```

- [ ] **Step 2: Add URL pattern to `URL_PATTERN_MAPPINGS`**

After the `Features.WALLET_EMAIL_ADD` entry:

```python
Features.WALLET_LINK: [
    ("wallet/link/", WalletLinkView, URLNames.WALLET_LINK),
],
```

- [ ] **Step 3: Run full test suite locally**

Run:
```bash
uv run pytest -v
```

Expected: all tests pass, no regressions.

- [ ] **Step 4: Run lint**

Run:
```bash
make check
```

Expected: no formatting or lint errors.

- [ ] **Step 5: Commit**

```bash
git add blockauth/urls.py
git commit -m "feat: register wallet/link/ URL under WALLET_LINK feature flag"
```

---

## Task 8: Docker Validation (Full Suite)

This is the acceptance gate. Every test must pass inside Docker before this feature is considered done.

- [ ] **Step 1: Rebuild Docker image with all new code**

Run:
```bash
docker compose build
```

Expected: build completes with no errors.

- [ ] **Step 2: Run full test suite in Docker**

Run:
```bash
docker compose run --rm test
```

Expected output includes:
- `blockauth/utils/tests/test_wallet_link_constants.py` — 5 passed
- `blockauth/utils/tests/test_wallet_conflict_error.py` — 2 passed
- `blockauth/utils/tests/test_wallet_link_serializer.py` — 10 passed
- `blockauth/views/tests/test_wallet_link_view.py` — all passed
- No pre-existing tests regressed

- [ ] **Step 3: Run targeted wallet link tests only (quick re-check)**

Run:
```bash
docker compose run --rm test uv run pytest \
  blockauth/utils/tests/test_wallet_link_constants.py \
  blockauth/utils/tests/test_wallet_conflict_error.py \
  blockauth/utils/tests/test_wallet_link_serializer.py \
  blockauth/views/tests/test_wallet_link_view.py \
  -v
```

Expected: all pass.

- [ ] **Step 4: Commit final validation evidence and close issue**

```bash
git add .
git commit -m "feat: wallet link endpoint — POST /wallet/link/ complete

Adds authenticated endpoint for email/OAuth users to link a MetaMask wallet.
Full signature verification via WalletAuthenticator (replay protection, nonce,
timestamp). Blocks re-linking. Fires POST_WALLET_LINK_TRIGGER.

Closes #59"
```

Then close the GitHub issue:
```bash
gh issue close 59 --repo BloclabsHQ/auth-pack --comment "Implemented in this branch. All tests pass in Docker."
```

---

## Validation Checklist

Before considering this done, verify each item manually:

- [ ] `docker compose run --rm test` exits with code 0
- [ ] `POST /wallet/link/` returns 401 with no JWT
- [ ] `POST /wallet/link/` returns 400 when user already has a wallet
- [ ] `POST /wallet/link/` returns 409 when address belongs to another user
- [ ] `POST /wallet/link/` returns 400 when signature verification fails
- [ ] `POST /wallet/link/` returns 200 and persists `wallet_address` on success
- [ ] `WALLET` appears in `authentication_types` after successful link
- [ ] `POST_WALLET_LINK_TRIGGER` context contains no password or token data
- [ ] URL absent when `WALLET_LINK: False` in feature flags
- [ ] `make check` passes (format + lint clean)
