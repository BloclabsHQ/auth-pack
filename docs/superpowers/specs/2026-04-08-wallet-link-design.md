# Wallet Link Endpoint — Design Spec

**Date:** 2026-04-08
**Issue:** BloclabsHQ/auth-pack#59
**Status:** Approved

---

## Problem

BlockAuth has two wallet flows but a gap in the middle:

| Flow | Status |
|------|--------|
| Wallet-first signup (`POST /login/wallet/`) | Implemented |
| Wallet user adds email (`POST /wallet/email/add/`) | Implemented |
| **Email/OAuth user links a MetaMask wallet** | **Missing** |

Email and OAuth users who acquire a MetaMask wallet have no way to associate it with their existing account. Consuming apps must reimplement signature verification and replay protection themselves — duplicating security-critical code.

---

## Decision: Re-linking

Re-linking (overwriting an existing `wallet_address`) is **blocked** in this implementation.

**Reasoning:** The signing message lifecycle is a stateless ownership proof — it says "I own this wallet right now." It says nothing about intent to discard a previous wallet. Silently overwriting an existing wallet association is a destructive mutation. A stolen JWT could be exploited to hijack a user's wallet link. Re-linking belongs with a future unlink endpoint (separate issue).

---

## Architecture

### Approach

View + serializer pattern, matching `WalletEmailAddView` + `WalletLoginSerializer`. Business logic in the serializer, view handles throttle and logging. Consistent with the rest of the codebase.

### Request

**`POST /auth/wallet/link/`**
- Auth: JWT Bearer required (`IsAuthenticated`)
- Feature flag: `WALLET_LINK` (default `True`)
- Rate limiting: same as wallet login — `EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)`

```json
{
  "wallet_address": "0xAbC...",
  "message": "{\"body\": \"Link wallet to MyApp\", \"nonce\": \"uuid\", \"timestamp\": 1712345678}",
  "signature": "0x..."
}
```

### Flow

```
Authenticated user               BlockAuth
 |                                  |
 |  POST /auth/wallet/link/         |
 |  {address, message, signature}   |
 |  + JWT Bearer token              |
 |--------------------------------->|
 |                                  |  1. Check rate limit
 |                                  |  2. Authenticate user (JWT)
 |                                  |  3. Validate address format
 |                                  |  4. WalletAuthenticator.verify_signature()
 |                                  |     - parse JSON message
 |                                  |     - validate timestamp (< WALLET_MESSAGE_TTL)
 |                                  |     - check nonce not reused (cache)
 |                                  |     - recover signer from signature
 |                                  |     - hmac.compare_digest(recovered, address)
 |                                  |     - consume nonce
 |                                  |  5. Check wallet_address not on another user
 |                                  |  6. Check user has no existing wallet_address
 |                                  |  7. Set user.wallet_address
 |                                  |  8. user.add_authentication_type(WALLET)
 |                                  |  9. Fire POST_WALLET_LINK_TRIGGER
 |                                  |
 |<-- 200 {"message": "Wallet linked successfully.", "wallet_address": "0xAbC..."}
```

### Error Responses

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `WALLET_ALREADY_LINKED` | User already has a `wallet_address` |
| 409 | `WALLET_IN_USE` | Address belongs to another user |
| 400 | `INVALID_SIGNATURE` | Signature verification failed |
| 400 | `MESSAGE_EXPIRED` | Timestamp outside `WALLET_MESSAGE_TTL` window |
| 400 | `NONCE_REUSED` | Nonce replay detected |
| 429 | — | Rate limit exceeded |

---

## Components

### 1. `WalletLinkSerializer` — `blockauth/serializers/wallet_serializers.py`

Fields: `wallet_address`, `message`, `signature` (identical to `WalletLoginSerializer`).

`validate_wallet_address()`: format check (starts with `0x`, length 42), lowercase.

`validate()`:
1. Call `WalletAuthenticator().verify_signature(wallet_address, message, signature)` — handles replay protection, nonce, timestamp, crypto check.
2. If `verify_signature` returns `False` → `ValidationError(INVALID_SIGNATURE)`.
3. If `verify_signature` raises `ValueError` → re-raise as `ValidationError` with the message (covers `MESSAGE_EXPIRED`, `NONCE_REUSED`, bad format).
4. Check `_User.objects.filter(wallet_address=wallet_address).exclude(pk=request.user.pk).exists()` → `ValidationError(WALLET_IN_USE, status=409)`.
5. Check `request.user.wallet_address` is not None → `ValidationError(WALLET_ALREADY_LINKED)`.

Requires `request` in serializer context (passed from view).

### 2. `WalletLinkView` — `blockauth/views/wallet_auth_views.py`

```python
class WalletLinkView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = WalletLinkSerializer
    link_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    def post(self, request):
        # 1. Check throttle
        # 2. Validate serializer (context={"request": request})
        # 3. Save: user.wallet_address, add_authentication_type(WALLET)
        # 4. Fire POST_WALLET_LINK_TRIGGER
        # 5. Return 200
```

Trigger context: `{"user": user_data, "wallet_address": wallet_address}` — no private data, no tokens.

### 3. `DummyPostWalletLinkTrigger` — `blockauth/triggers.py`

Follows the same no-op pattern as all other Dummy triggers. Registered in `conf.py` under `POST_WALLET_LINK_TRIGGER` and added to `IMPORT_STRINGS`.

### 4. Feature Flag — `blockauth/constants/core.py`

- `Features.WALLET_LINK = "WALLET_LINK"` added to class and `all_features()` list.
- `conf.py` FEATURES dict: `"WALLET_LINK": True`.

### 5. URL — `blockauth/urls.py`

```python
Features.WALLET_LINK: [
    ("wallet/link/", WalletLinkView, URLNames.WALLET_LINK),
],
```

`URLNames.WALLET_LINK = "wallet-link"` in `constants/core.py`.

---

## Files Changed

| File | Change |
|------|--------|
| `blockauth/constants/core.py` | Add `Features.WALLET_LINK`, `URLNames.WALLET_LINK` |
| `blockauth/conf.py` | Add `WALLET_LINK` feature flag, `POST_WALLET_LINK_TRIGGER` default + import string |
| `blockauth/triggers.py` | Add `DummyPostWalletLinkTrigger` |
| `blockauth/serializers/wallet_serializers.py` | Add `WalletLinkSerializer` |
| `blockauth/views/wallet_auth_views.py` | Add `WalletLinkView` |
| `blockauth/urls.py` | Import `WalletLinkView`, add to `URL_PATTERN_MAPPINGS` |

---

## Testing

### Unit tests — `blockauth/utils/tests/test_wallet_link_serializer.py`

Mock `WalletAuthenticator.verify_signature`. Test cases:

- Valid signature, unlinked user → validation passes
- `verify_signature` returns `False` → `400 INVALID_SIGNATURE`
- `verify_signature` raises `ValueError("expired")` → `400 MESSAGE_EXPIRED`
- `verify_signature` raises `ValueError("nonce")` → `400 NONCE_REUSED`
- `wallet_address` already on another user → `409 WALLET_IN_USE`
- `request.user.wallet_address` already set → `400 WALLET_ALREADY_LINKED`
- Invalid address format → `400`

### Integration tests — `blockauth/views/tests/test_wallet_link_view.py`

Use Django test client with JWT auth header. Mock `verify_signature` at the `WalletAuthenticator` level.

- Unauthenticated request → `401`
- Valid request → `200`, `wallet_address` saved on user, `WALLET` in `authentication_types`
- `POST_WALLET_LINK_TRIGGER` fires with correct context (mock trigger)
- Rate limit: 6 failures in window → `429`
- `WALLET_LINK` feature flag `False` → URL does not exist (`404`)

### Replay protection — included in integration tests

- Same `{address, message, signature}` submitted twice → second call `400 NONCE_REUSED`
- `timestamp` older than `WALLET_MESSAGE_TTL` → `400 MESSAGE_EXPIRED`

### Verification commands

```bash
uv run pytest blockauth/utils/tests/test_wallet_link_serializer.py blockauth/views/tests/test_wallet_link_view.py -v
uv run pytest   # full suite — no regressions
make check      # format + lint
```

---

## Out of Scope

- **Unlink endpoint** (`DELETE /wallet/link/`) — separate issue
- **Re-linking** (replacing existing wallet) — requires unlink first
- **Multiple wallets per user** — single `wallet_address` field in model, not supported
- **KDF + linked wallet coexistence** — model already supports it; no changes needed
