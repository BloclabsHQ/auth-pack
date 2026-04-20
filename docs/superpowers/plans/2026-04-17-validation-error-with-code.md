# `ValidationErrorWithCode` DRF-native subclass — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `blockauth.utils.custom_exception.ValidationErrorWithCode` a real DRF `ValidationError` subclass so downstream `isinstance(exc, ValidationError)` checks fire and `.detail` is a DRF-native `{field: [ErrorDetail, ...]}` map; promote the top-level numeric code to an `.error_code` attribute.

**Architecture:** Single-file behavior change (`blockauth/utils/custom_exception.py`) plus a dedicated test module that locks in the contract. Breaking wire change for consumers using DRF's default handler; fixed with a 0.7.0 minor bump, CHANGELOG entry, and no compat shim.

**Tech Stack:** Python 3.12, Django REST Framework (`rest_framework.exceptions.ValidationError`, `ErrorDetail`), pytest, uv, black/isort/flake8.

**Spec:** `docs/superpowers/specs/2026-04-17-validation-error-with-code-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `blockauth/utils/tests/test_validation_error_with_code.py` | Create | 12 tests — locks in subclass contract, `.detail` preservation, `.error_code` derivation, wire body |
| `blockauth/utils/custom_exception.py` | Modify | Rewrite `ValidationErrorWithCode` to subclass `ValidationError`; add `_derive_error_code` static helper |
| `CHANGELOG.md` | Modify | Add Breaking Changes + Migration notes entries under `[Unreleased]` |
| `pyproject.toml` | Modify | Bump `version = "0.7.0"` |
| `blockauth/__init__.py` | Modify | Bump `__version__ = "0.7.0"` |

---

## Task 1: Write the failing test file

**Files:**
- Create: `blockauth/utils/tests/test_validation_error_with_code.py`

- [ ] **Step 1: Create the test file with all 12 tests**

Path: `blockauth/utils/tests/test_validation_error_with_code.py`

```python
"""Tests for `ValidationErrorWithCode` — the DRF-native upstream fix for #101.

These tests lock in the contract that `ValidationErrorWithCode`:
  * is a real `rest_framework.exceptions.ValidationError` subclass
    (so downstream `isinstance` and field-map iteration work without
    special-casing), and
  * exposes the legacy numeric top-level code as `.error_code` (a fresh
    instance attribute) while leaving `.detail` as DRF-native
    `{field: [ErrorDetail, ...]}`.
"""

import pytest
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.views import exception_handler

from blockauth.utils.custom_exception import ValidationErrorWithCode


def test_is_subclass_of_drf_validation_error():
    """Regressing this line re-introduces auth-pack#101."""
    assert issubclass(ValidationErrorWithCode, ValidationError)


def test_isinstance_check_passes_for_raised_instance():
    """Behavioral form of the subclass contract — catching
    `ValidationError` MUST catch `ValidationErrorWithCode`."""
    with pytest.raises(ValidationError) as exc_info:
        raise ValidationErrorWithCode(
            detail={"email": [ErrorDetail("required", code="required")]}
        )
    assert isinstance(exc_info.value, ValidationErrorWithCode)


def test_detail_is_drf_native_field_map():
    """No flatten — `.detail[field]` stays a list of `ErrorDetail`."""
    exc = ValidationErrorWithCode(
        detail={"password": [ErrorDetail("too short", code="min_length")]}
    )
    assert isinstance(exc.detail, dict)
    assert isinstance(exc.detail["password"], list)
    assert exc.detail["password"][0] == "too short"
    assert exc.detail["password"][0].code == "min_length"


def test_error_code_derived_from_first_field_code():
    exc = ValidationErrorWithCode(
        detail={"email": [ErrorDetail("bad address", code="invalid")]}
    )
    assert exc.error_code == "invalid"


def test_error_code_required_maps_to_4000():
    """`code="required"` is treated as the default-code sentinel."""
    exc = ValidationErrorWithCode(
        detail={"email": [ErrorDetail("This field is required.", code="required")]}
    )
    assert exc.error_code == "4000"


def test_error_code_explicit_overrides_derivation():
    exc = ValidationErrorWithCode(
        detail={"email": [ErrorDetail("bad", code="invalid")]},
        code="4042",
    )
    assert exc.error_code == "4042"


def test_error_code_falls_back_to_default_for_bare_strings():
    """A field value that's a plain string (not an ErrorDetail/list) must
    not blow up derivation — the old implementation called `.code` on it
    and crashed."""
    exc = ValidationErrorWithCode(detail={"email": "raw string with no code"})
    assert exc.error_code == "4000"


def test_error_code_falls_back_to_default_for_empty_detail():
    """An empty dict must not `StopIteration` through `next(iter(...))`."""
    exc = ValidationErrorWithCode(detail={})
    assert exc.error_code == "4000"


def test_default_detail_when_none_passed():
    exc = ValidationErrorWithCode()
    assert exc.error_code == "4000"
    assert "non_field_errors" in exc.detail
    # DRF wraps scalar strings into `[ErrorDetail(...)]` during __init__.
    assert isinstance(exc.detail["non_field_errors"], list)
    assert "validation error" in str(exc.detail["non_field_errors"][0]).lower()


def test_multi_message_per_field_preserved_as_list():
    """Old class joined multiple messages per field into a single
    space-separated string. New class preserves DRF's list — per-error
    codes and messages stay iterable individually."""
    exc = ValidationErrorWithCode(
        detail={
            "password": [
                ErrorDetail("too short", code="min_length"),
                ErrorDetail("needs a digit", code="no_digit"),
            ]
        }
    )
    assert len(exc.detail["password"]) == 2
    assert exc.detail["password"][0].code == "min_length"
    assert exc.detail["password"][1].code == "no_digit"


def test_status_code_is_400():
    exc = ValidationErrorWithCode(
        detail={"email": [ErrorDetail("required", code="required")]}
    )
    assert exc.status_code == 400


def test_default_drf_handler_renders_field_map():
    """Locks in the new wire contract: DRF's default exception_handler
    renders `{field: [message]}` without the legacy `{"detail": ...}`
    outer wrap."""
    exc = ValidationErrorWithCode(
        detail={"password": [ErrorDetail("This field is required.", code="required")]}
    )
    response = exception_handler(exc, context={})
    assert response is not None
    assert response.status_code == 400
    assert response.data == {"password": ["This field is required."]}
```

- [ ] **Step 2: Run the new tests and verify they fail**

```bash
uv run pytest blockauth/utils/tests/test_validation_error_with_code.py -v
```

Expected: most tests FAIL (notably `test_is_subclass_of_drf_validation_error`, `test_isinstance_check_passes_for_raised_instance`, `test_detail_is_drf_native_field_map`, `test_default_drf_handler_renders_field_map`). `test_status_code_is_400` may pass incidentally because the old class already has `status_code = 400`.

This failure set confirms the tests exercise the new contract. If everything passes on the old class, the tests aren't specific enough — stop and rewrite them.

- [ ] **Step 3: Commit the failing tests**

```bash
git add blockauth/utils/tests/test_validation_error_with_code.py
git commit -m "test(custom_exception): add failing tests for DRF-native ValidationErrorWithCode (#101)"
```

---

## Task 2: Rewrite `ValidationErrorWithCode`

**Files:**
- Modify: `blockauth/utils/custom_exception.py`

- [ ] **Step 1: Read the current file**

```bash
cat blockauth/utils/custom_exception.py
```

The file currently has `WalletConflictError(APIException)` (keep as-is) and the legacy `ValidationErrorWithCode(APIException)` (replace).

- [ ] **Step 2: Replace the full file contents**

```python
from rest_framework.exceptions import APIException, ValidationError


class WalletConflictError(APIException):
    """Raised when a wallet address is already linked to a different account (HTTP 409)."""

    status_code = 409
    default_detail = "This wallet address is already linked to another account."
    default_code = "WALLET_IN_USE"


class ValidationErrorWithCode(ValidationError):
    """DRF ``ValidationError`` with a top-level error-code attribute for legacy envelopes.

    ``.detail`` is DRF-native ``{field: [ErrorDetail, ...]}`` — untransformed.
    ``.error_code`` carries a single top-level code (convenience for handlers
    that want to tag the whole response, not just individual fields).

    Subclassing ``ValidationError`` means ``isinstance(exc, ValidationError)``
    checks in downstream exception handlers pick this up automatically and
    can iterate ``.detail`` as a standard DRF field map.
    """

    default_code = "4000"

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = {
                "non_field_errors": "A validation error occurred. Please check your input and try again."
            }
        self.error_code = code if code is not None else self._derive_error_code(detail)
        super().__init__(detail, code=None)

    @staticmethod
    def _derive_error_code(detail):
        if not isinstance(detail, dict) or not detail:
            return ValidationErrorWithCode.default_code
        first_field = next(iter(detail.values()))
        first_err = first_field[0] if isinstance(first_field, list) and first_field else first_field
        err_code = getattr(first_err, "code", None)
        return ValidationErrorWithCode.default_code if err_code in (None, "required") else err_code
```

- [ ] **Step 3: Run the new tests and verify they pass**

```bash
uv run pytest blockauth/utils/tests/test_validation_error_with_code.py -v
```

Expected: all 12 tests PASS.

If any fail, read the failure output against the spec's contract table (§Behavioral contract) and the `_derive_error_code` trace. Do NOT adjust the tests to match a broken implementation — fix the implementation.

---

## Task 3: Run the full suite and triage regressions

**Files:** potentially any test that implicitly asserted on the old `{"detail": {"error_code": ..., "detail": ...}}` envelope.

- [ ] **Step 1: Run the full test suite**

```bash
uv run pytest blockauth/ -q
```

Expected: all tests PASS. A pre-spec grep confirmed no view/unit tests assert on the legacy body envelope (`response.data["detail"]["error_code"]` appears in zero test files), so regressions are unlikely.

- [ ] **Step 2: If any test fails, triage**

For each failure:

1. Confirm the failure is a shape change caused by this fix (assertion on `.detail["error_code"]`, `.detail["detail"]`, or a single-string-per-field body) — not an unrelated bug.
2. Update the assertion to the new contract:
   - `exc.detail["error_code"]` → `exc.error_code`
   - `exc.detail["detail"][<field>]` → `exc.detail[<field>]`
   - `response.data["detail"]["detail"][<field>] == "msg"` → `response.data[<field>] == ["msg"]`
3. Rerun the single test until green.

Only update failing tests — do not sweep the test suite for other edits.

- [ ] **Step 3: Rerun the full suite to confirm green**

```bash
uv run pytest blockauth/ -q
```

Expected: all tests PASS.

---

## Task 4: Lint and commit the core fix

**Files:** none new.

- [ ] **Step 1: Format with black and isort**

```bash
uv run black blockauth/utils/custom_exception.py blockauth/utils/tests/test_validation_error_with_code.py
uv run isort blockauth/utils/custom_exception.py blockauth/utils/tests/test_validation_error_with_code.py
```

Expected: both commands succeed; may reformat imports/whitespace.

- [ ] **Step 2: Lint the whole package**

```bash
uv run flake8 blockauth/
```

Expected: exit code 0, no warnings.

- [ ] **Step 3: Commit the fix**

```bash
git add blockauth/utils/custom_exception.py blockauth/utils/tests/test_validation_error_with_code.py
# If Task 3 triaged any regressions, add those test files too.
git commit -m "fix(custom_exception): ValidationErrorWithCode subclasses DRF ValidationError (#101)

Closes #101.

- ValidationErrorWithCode now inherits from rest_framework.exceptions.ValidationError,
  so downstream isinstance(exc, ValidationError) checks fire and .detail is a
  DRF-native {field: [ErrorDetail, ...]} map.
- The top-level numeric error code moves from .detail[\"error_code\"] to the
  .error_code instance attribute.
- Per-field multi-message behavior changes: DRF's list of ErrorDetail is
  preserved (old code joined messages into a single space-separated string).

Breaking wire change for consumers using DRF's default handler — see
CHANGELOG Breaking Changes + Migration notes."
```

---

## Task 5: Update CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current `[Unreleased]` section**

```bash
sed -n '1,50p' CHANGELOG.md
```

- [ ] **Step 2: Add a Breaking Changes bullet under `[Unreleased]`**

Open `CHANGELOG.md`. Under `## [Unreleased]` → `### Breaking Changes`, append a new bullet (after any existing bullets, before `### Added`):

```markdown
- **`ValidationErrorWithCode` now subclasses DRF's `ValidationError`** (#101). `.detail` is a DRF-native `{field: [ErrorDetail, ...]}` map; the top-level error code moves from `.detail["error_code"]` to the `.error_code` attribute on the exception instance.
  - Response body for DRF's default exception handler changes from `{"detail": {"error_code": "4000", "detail": {field: message}}}` to `{field: [message]}`. The top-level code is no longer in the body when using DRF's default handler.
  - Custom exception handlers that branch on `isinstance(exc, ValidationError)` now pick up `ValidationErrorWithCode` automatically and can iterate `exc.detail` as a DRF-native field map.
  - Per-field multi-message behavior changes: the old code joined multiple error messages per field into a single space-separated string. The new class preserves DRF's list of `ErrorDetail` so per-error codes and messages are iterable individually.
```

- [ ] **Step 3: Append a bullet to the `### Migration notes` list under `[Unreleased]`**

```markdown
- If your service uses a custom DRF `EXCEPTION_HANDLER` that special-cases `ValidationErrorWithCode` by reading `exc.detail["error_code"]` or `exc.detail["detail"]`, switch to reading `exc.error_code` and iterating `exc.detail` as a standard DRF field map. If your service relies on DRF's default handler and was parsing the legacy envelope, switch to the DRF-native `{field: [message]}` shape (#101).
```

- [ ] **Step 4: Sanity-check the diff**

```bash
git diff CHANGELOG.md
```

Confirm both entries land under `[Unreleased]` and the formatting matches surrounding bullets.

---

## Task 6: Bump version to 0.7.0

**Files:**
- Modify: `pyproject.toml`
- Modify: `blockauth/__init__.py`

- [ ] **Step 1: Bump `pyproject.toml`**

Open `pyproject.toml`, change line 3 from:

```toml
version = "0.6.1"
```

to:

```toml
version = "0.7.0"
```

- [ ] **Step 2: Bump `blockauth/__init__.py`**

Open `blockauth/__init__.py`, change the `__version__` line from:

```python
__version__ = "0.6.1"
```

to:

```python
__version__ = "0.7.0"
```

- [ ] **Step 3: Cut `[Unreleased]` → `[0.7.0] - 2026-04-17` in `CHANGELOG.md`**

Rename the `## [Unreleased]` header to `## [0.7.0] - 2026-04-17`. Add a fresh empty `## [Unreleased]` section above it (with empty `### Added`, `### Changed`, `### Fixed` subsections ready for the next release).

- [ ] **Step 4: Verify versions match and package imports**

```bash
uv run python -c "import blockauth; print(blockauth.__version__)"
grep '^version' pyproject.toml
```

Expected: both print `0.7.0`.

- [ ] **Step 5: Commit the release prep**

```bash
git add pyproject.toml blockauth/__init__.py CHANGELOG.md
git commit -m "chore(release): bump version to 0.7.0

Breaking: #101 — ValidationErrorWithCode is now a DRF ValidationError
subclass; .detail shape and default response body change. See CHANGELOG
Breaking Changes + Migration notes."
```

---

## Task 7: Final verification

**Files:** none.

- [ ] **Step 1: Re-run the full suite**

```bash
uv run pytest blockauth/ -q
```

Expected: all PASS.

- [ ] **Step 2: Re-run lint**

```bash
uv run black --check blockauth/
uv run isort --check-only blockauth/
uv run flake8 blockauth/
```

Expected: all exit 0.

- [ ] **Step 3: Confirm downstream breakage surface is the one described**

```bash
grep -rn 'exc\.detail\["error_code"\]\|response\.data\["detail"\]\["detail"\]' blockauth/ tests/
```

Expected: no matches. If anything shows up, it's either a forgotten legacy assertion (update to the new shape) or a runtime consumer path we missed (reopen Task 3).

- [ ] **Step 4: Sanity-check the commit history**

```bash
git log --oneline dev..HEAD
```

Expected three commits in order:

1. `test(custom_exception): add failing tests for DRF-native ValidationErrorWithCode (#101)`
2. `fix(custom_exception): ValidationErrorWithCode subclasses DRF ValidationError (#101)`
3. `chore(release): bump version to 0.7.0`

- [ ] **Step 5: Push and open PR — STOP HERE and confirm with the user before running this step**

Do NOT push or open the PR autonomously. Tagging `v0.7.0` triggers `publish.yml` and cuts a GitHub Release — a cross-service visible action. Surface the diff summary to the user and let them decide when to push.

```bash
# For the user to run when they're ready:
git push -u origin HEAD
gh pr create --base dev --title "fix: ValidationErrorWithCode is a real DRF ValidationError (#101) — 0.7.0" --body "..."
```

After the PR merges to `dev`, the maintainer tags `v0.7.0` and pushes the tag separately to trigger the publish workflow (per the release flow in the spec).
