# Breaking Change Policy + PR Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a breaking change policy with GitHub-native enforcement, then apply it immediately to fix three bugs in PR #86 that include a breaking change (error code standardization).

**Architecture:** Policy lives in `.github/CONTRIBUTING.md` (human docs) + `.github/PULL_REQUEST_TEMPLATE.md` (enforcement). CLAUDE.md gets one pointer line only. Bug fixes go on the existing `feat/wallet-link` branch since they are corrections to in-flight work. The error code fix IS a breaking change — it gets a CHANGELOG entry.

**Tech Stack:** Python 3.12, Django REST Framework, pytest, uv, gh CLI

**Spec:** `docs/superpowers/specs/2026-04-09-breaking-change-policy-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `.github/CONTRIBUTING.md` | Create | Full breaking change policy — table + 5-step process |
| `.github/PULL_REQUEST_TEMPLATE.md` | Create | PR checklist with breaking change checkbox |
| `CHANGELOG.md` | Create | Keep a Changelog format, backfilled v0.3.0 + v0.4.0 |
| `CLAUDE.md` | Modify | Add one-line pointer to CONTRIBUTING.md |
| GitHub label `breaking-change` | Create | Via `gh label create` |
| `blockauth/serializers/wallet_serializers.py` | Modify | Fix validate_wallet_address bug + standardize error codes + rule order |

---

## Task 1: Create `breaking-change` GitHub Label

**Files:**
- No file changes — GitHub label via CLI

- [ ] **Step 1: Create the label**

Run:
```bash
gh label create "breaking-change" \
  --repo BloclabsHQ/auth-pack \
  --description "This PR contains breaking changes for consumers" \
  --color "d73a4a"
```

Expected: `✓ Label "breaking-change" created`

---

## Task 2: Create `.github/CONTRIBUTING.md`

**Files:**
- Create: `.github/CONTRIBUTING.md`

- [ ] **Step 1: Create `.github/` directory if it doesn't exist**

Run:
```bash
ls /Users/mrmonkey/fabricbloc/auth-pack/.github/ 2>/dev/null || mkdir -p /Users/mrmonkey/fabricbloc/auth-pack/.github
```

- [ ] **Step 2: Write the file**

Create `.github/CONTRIBUTING.md` with this exact content:

```markdown
# Contributing to BlockAuth

## Breaking Changes

A breaking change is any modification that forces consumers to update their code.

### What Counts as Breaking

| Breaking | Not Breaking |
|----------|-------------|
| Changing `error_code` value in any response | Adding a new endpoint |
| Changing HTTP status code on any existing response | Adding a new optional serializer field |
| Renaming or removing a public class, method, or setting | Adding a new feature flag (default `True`) |
| Changing a `BLOCK_AUTH_SETTINGS` default that affects behavior | Fixing a 500 to return the correct 4xx |
| Removing or renaming a trigger context key | Adding a new trigger |
| Making a previously optional serializer field required | Adding new error codes for new endpoints |
| Changing `authentication_types` enum values | Internal refactors with no contract change |

**Special rule:** If the current behavior is a bug but consumers might depend on it, treat it as a breaking change regardless. Do not silently change observable behavior.

### The 5-Step Process

When a PR touches anything in the Breaking column above:

1. **Label** — add the `breaking-change` label to the PR on GitHub
2. **CHANGELOG** — add an entry under `## [Unreleased]` → `### Breaking Changes`, one sentence per change with a migration note
3. **Version bump** — update `pyproject.toml` and `blockauth/__init__.py`. Pre-1.0: breaking = minor bump. Post-1.0: breaking = major bump.
4. **Release note** — when tagging, the GitHub release body must include a `## Breaking Changes` section with migration steps
5. **Never silent** — every observable behavior change gets a CHANGELOG entry, even small ones

### Versioning Rules

| Change type | Version bump |
|-------------|-------------|
| Bug fix (no contract change) | Patch — `0.4.0` → `0.4.1` |
| New feature | Minor — `0.4.0` → `0.5.0` |
| Breaking change (pre-1.0) | Minor — `0.4.0` → `0.5.0` |
| Breaking change (post-1.0) | Major — `1.0.0` → `2.0.0` |

## Development

```bash
uv sync            # install deps
uv run pytest      # run tests
make check         # format + lint
uv build           # build package
```

## Releasing

Bump version in `pyproject.toml` and `blockauth/__init__.py`, then:

```bash
git tag v0.5.0 && git push origin v0.5.0
```
```

- [ ] **Step 3: Commit**

```bash
git add .github/CONTRIBUTING.md
git commit -m "docs: add breaking change policy to CONTRIBUTING.md"
```

---

## Task 3: Create `.github/PULL_REQUEST_TEMPLATE.md`

**Files:**
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

- [ ] **Step 1: Write the file**

Create `.github/PULL_REQUEST_TEMPLATE.md` with this exact content:

```markdown
## Summary

- 
- 

## Breaking Changes

- [ ] This PR contains breaking changes

<!-- If checked, list each change and the migration path:
     e.g. `error_code` in wallet login responses changed from `4009` → `"INVALID_SIGNATURE"`.
     Update any client code checking this field. -->

## Test plan

- [ ] `uv run pytest` passes
- [ ] `make check` (format + lint) clean
- [ ] Version bumped in `pyproject.toml` + `blockauth/__init__.py` (if breaking or new feature)
- [ ] `CHANGELOG.md` updated (if breaking changes or notable additions)
```

- [ ] **Step 2: Commit**

```bash
git add .github/PULL_REQUEST_TEMPLATE.md
git commit -m "docs: add PR template with breaking change checkbox"
```

---

## Task 4: Create `CHANGELOG.md`

**Files:**
- Create: `CHANGELOG.md`

- [ ] **Step 1: Write the file**

Create `CHANGELOG.md` at repo root with this exact content:

```markdown
# Changelog

All notable changes to BlockAuth are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, breaking changes increment the minor version.

---

## [Unreleased]

### Breaking Changes

- `error_code` in wallet login responses changed from integer `4009` to string `"INVALID_SIGNATURE"`. Update any client code that checks this field by value.

### Fixed

- `POST /wallet/link/` with an invalid wallet address format now returns `400` instead of `500`.
- Business rule evaluation order in `WalletLinkSerializer` — user's existing wallet check now runs before the DB conflict query, preventing unnecessary database queries and wallet enumeration.

---

## [0.4.0] - 2026-04-09

### Added

- Passkey/WebAuthn authentication (FIDO2)
- TOTP 2FA
- Step-up authentication receipts (RFC 9470)
- RS256/ES256 asymmetric JWT support alongside HS256
- KDF services (PBKDF2, Argon2)
- Social auth (Google, Facebook, LinkedIn)
- Enhanced JWT with custom claims support

---

## [0.3.0] - 2026-04-08

### Added

- Initial public release
- JWT authentication (HS256)
- Basic auth (email + password)
- Passwordless login (OTP)
- Wallet login (MetaMask signature verification with replay protection)
- Feature-flag-driven URL routing
- Trigger system for post-action hooks
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG with backfilled v0.3.0 and v0.4.0 entries"
```

---

## Task 5: Update `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add one-line pointer**

In `CLAUDE.md`, find the `## Commands` section. Add one line immediately after the opening of that section:

```markdown
## Commands

**Breaking changes** — check `.github/CONTRIBUTING.md` before opening any PR.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add breaking change pointer to CLAUDE.md"
```

---

## Task 6: Fix `validate_wallet_address` 500 Bug (Both Serializers)

**Files:**
- Modify: `blockauth/serializers/wallet_serializers.py`

**Background:** In DRF, `validate_<field>` already associates errors under the field name. Raising `ValidationError(detail={"wallet_address": "..."})` double-nests the error to `{"wallet_address": {"wallet_address": [...]}}`. When `ValidationErrorWithCode.__init__` then processes this, it calls `errors.code` on a dict — raising `AttributeError` and producing a 500.

- [ ] **Step 1: Add a failing view-level test for invalid address**

Add to `blockauth/views/tests/test_wallet_link_view.py`, inside a new `TestInvalidAddress` class at the bottom of the file:

```python
class TestInvalidAddress:
    def test_invalid_address_returns_400_not_500(self):
        user = _make_user()
        request = factory.post(
            "/wallet/link/",
            data={**_make_payload(), "wallet_address": "notvalid"},
            format="json",
        )
        request._force_auth_user = user
        response = VIEW(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
uv run pytest blockauth/views/tests/test_wallet_link_view.py::TestInvalidAddress -v
```

Expected: FAIL — response is 500, not 400.

- [ ] **Step 3: Fix `WalletLoginSerializer.validate_wallet_address`**

In `blockauth/serializers/wallet_serializers.py`, find lines 25–33 (`WalletLoginSerializer.validate_wallet_address`):

Change from:
```python
def validate_wallet_address(self, value):
    """Validate Ethereum wallet address format"""
    if not value.startswith("0x") or len(value) != 42:
        raise ValidationError(
            detail={
                "wallet_address": "Invalid wallet address format. Must be a 42-character hex string starting with 0x."
            }
        )
    return value.lower()
```

Change to:
```python
def validate_wallet_address(self, value):
    if not value.startswith("0x") or len(value) != 42:
        raise ValidationError(
            "Invalid wallet address format. Must be a 42-character hex string starting with 0x."
        )
    return value.lower()
```

- [ ] **Step 4: Fix `WalletLinkSerializer.validate_wallet_address`**

Find the same method in `WalletLinkSerializer` (approximately 30 lines below `WalletLoginSerializer`):

Change from:
```python
def validate_wallet_address(self, value):
    if not value.startswith("0x") or len(value) != 42:
        raise ValidationError(
            detail={
                "wallet_address": "Invalid wallet address format. Must be a 42-character hex string starting with 0x."
            }
        )
    return value.lower()
```

Change to:
```python
def validate_wallet_address(self, value):
    if not value.startswith("0x") or len(value) != 42:
        raise ValidationError(
            "Invalid wallet address format. Must be a 42-character hex string starting with 0x."
        )
    return value.lower()
```

- [ ] **Step 5: Run tests to verify fix**

Run:
```bash
uv run pytest blockauth/views/tests/test_wallet_link_view.py -v
```

Expected: all pass including `TestInvalidAddress::test_invalid_address_returns_400_not_500`.

- [ ] **Step 6: Run full suite to catch regressions**

Run:
```bash
uv run pytest -v
```

Expected: no new failures.

- [ ] **Step 7: Commit**

```bash
git add blockauth/serializers/wallet_serializers.py \
        blockauth/views/tests/test_wallet_link_view.py
git commit -m "fix: validate_wallet_address raises plain string — prevents 500 on invalid address format"
```

---

## Task 7: Standardize Error Codes to Strings (Breaking Change)

**Files:**
- Modify: `blockauth/serializers/wallet_serializers.py`

**Background:** `WalletLoginSerializer` uses `code=4009` (integer) for signature errors. `WalletLinkSerializer` uses `code="INVALID_SIGNATURE"` (string). String codes are self-documenting for consumers. This is a breaking change — the `error_code` field in wallet login error responses changes from `4009` to `"INVALID_SIGNATURE"`.

- [ ] **Step 1: Add a failing test for string error code**

Add to `blockauth/utils/tests/test_wallet_link_serializer.py`, inside `TestSignatureVerification`:

```python
def test_signature_error_code_is_string(self):
    request = _make_request()
    with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
        mock_auth.return_value.verify_signature.return_value = False
        s = WalletLinkSerializer(data=_make_data(), context={"request": request})
        s.is_valid()
        error = s.errors.get("signature", [])
        assert len(error) > 0
        assert error[0].code == "INVALID_SIGNATURE"
```

- [ ] **Step 2: Run to verify it passes already for WalletLinkSerializer**

Run:
```bash
uv run pytest blockauth/utils/tests/test_wallet_link_serializer.py::TestSignatureVerification::test_signature_error_code_is_string -v
```

Expected: PASS (WalletLinkSerializer already uses string codes).

- [ ] **Step 3: Fix `WalletLoginSerializer` — change integer codes to strings**

In `blockauth/serializers/wallet_serializers.py`, in `WalletLoginSerializer.validate()`, make these three changes:

Change line ~50 from:
```python
raise ValidationError(
    detail={"signature": "Invalid signature. Signature verification failed."}, code=4009
)
```
To:
```python
raise ValidationError(
    detail={"signature": "Invalid signature. Signature verification failed."}, code="INVALID_SIGNATURE"
)
```

Change line ~55 from:
```python
raise ValidationError(detail={"message": str(e)}, code=4009)
```
To:
```python
raise ValidationError(detail={"message": str(e)}, code="INVALID_SIGNATURE")
```

Change line ~60 from:
```python
raise ValidationError(detail={"signature": "Signature verification failed."}, code=4009)
```
To:
```python
raise ValidationError(detail={"signature": "Signature verification failed."}, code="INVALID_SIGNATURE")
```

- [ ] **Step 4: Run full suite**

Run:
```bash
uv run pytest -v
```

Expected: all pass, no regressions.

- [ ] **Step 5: Commit**

```bash
git add blockauth/serializers/wallet_serializers.py
git commit -m "fix: standardize wallet serializer error codes to strings (INVALID_SIGNATURE)

BREAKING CHANGE: error_code in wallet login error responses changes from
integer 4009 to string 'INVALID_SIGNATURE'. Update any client code that
checks this field by value."
```

---

## Task 8: Swap Business Rule Order + Cleanup in `WalletLinkSerializer`

**Files:**
- Modify: `blockauth/serializers/wallet_serializers.py`

**Background:** In `WalletLinkSerializer.validate()`, the DB conflict check (rule 2) runs before the user's own wallet check (rule 3). Rule 3 is a free attribute access — it should run first. Also: `super().validate(data)` is a no-op and the deferred import of `WalletConflictError` should move to the top of the file.

- [ ] **Step 1: Move deferred import to file top**

In `blockauth/serializers/wallet_serializers.py`, find the top-level imports section. `WalletConflictError` is currently imported inside `validate()`. Add it to the top-level imports alongside other `blockauth.utils` imports:

```python
from blockauth.utils.custom_exception import WalletConflictError
```

Remove the deferred import line from inside `WalletLinkSerializer.validate()`.

- [ ] **Step 2: Rewrite `WalletLinkSerializer.validate()` with correct rule order**

Replace the full `validate()` method body with:

```python
def validate(self, data):
    wallet_address = data.get("wallet_address")
    message = data.get("message")
    signature = data.get("signature")
    request = self.context.get("request")

    # 1. Verify signature — replay protection, nonce, timestamp all handled here
    try:
        authenticator = WalletAuthenticator()
        if not authenticator.verify_signature(wallet_address, message, signature):
            raise ValidationError(
                detail={"signature": "Invalid signature. Signature verification failed."},
                code="INVALID_SIGNATURE",
            )
    except ValueError as e:
        raise ValidationError(detail={"message": str(e)}, code="INVALID_SIGNATURE")
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        raise ValidationError(
            detail={"signature": "Signature verification failed."},
            code="INVALID_SIGNATURE",
        )

    # 2. User must not already have a wallet linked (cheap — attribute access, no DB)
    if request.user.wallet_address:
        raise ValidationError(
            detail={"wallet_address": "Your account already has a linked wallet. Unlink it first."},
            code="WALLET_ALREADY_LINKED",
        )

    # 3. Wallet must not belong to a different account (DB query — only runs if user is unlinked)
    if _User.objects.filter(wallet_address=wallet_address).exclude(pk=request.user.pk).exists():
        raise WalletConflictError()

    return data
```

- [ ] **Step 3: Run full suite**

Run:
```bash
uv run pytest -v
```

Expected: all pass.

- [ ] **Step 4: Run lint**

Run:
```bash
make check
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add blockauth/serializers/wallet_serializers.py
git commit -m "fix: swap wallet link rule order — check existing wallet before DB conflict query"
```

---

## Task 9: Apply Breaking Change Label to PR #86

- [ ] **Step 1: Add label to PR**

Run:
```bash
gh pr edit 86 --repo BloclabsHQ/auth-pack --add-label "breaking-change"
```

Expected: PR #86 now shows the `breaking-change` label.

- [ ] **Step 2: Push the branch**

Run:
```bash
git push origin feat/wallet-link
```

- [ ] **Step 3: Verify all checks pass**

Run:
```bash
gh pr checks 86 --repo BloclabsHQ/auth-pack
```

Expected: all checks green.

---

## Validation Checklist

Before considering this done:

- [ ] `uv run pytest` exits clean
- [ ] `make check` exits clean
- [ ] `POST /wallet/link/` with invalid address returns 400 (not 500)
- [ ] Wallet login error response has `"error_code": "INVALID_SIGNATURE"` (string, not integer)
- [ ] `WalletLinkSerializer.validate()` checks `request.user.wallet_address` before DB query
- [ ] `WalletConflictError` imported at file top, not inside method body
- [ ] `CHANGELOG.md` exists at repo root with `[Unreleased]` breaking change entry
- [ ] `.github/CONTRIBUTING.md` exists with full policy table and 5-step process
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` exists with breaking change checkbox
- [ ] `CLAUDE.md` has one-line pointer to CONTRIBUTING.md
- [ ] PR #86 has `breaking-change` label
