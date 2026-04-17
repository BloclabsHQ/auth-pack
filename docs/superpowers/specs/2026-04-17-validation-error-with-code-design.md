# `ValidationErrorWithCode` — DRF-native subclass (upstream fix for #101)

**Date:** 2026-04-17
**Issue:** [auth-pack#101](https://github.com/BloclabsHQ/auth-pack/issues/101)
**Downstream context:** [fabric-auth#412](https://github.com/BloclabsHQ/fabric-auth/issues/412), [fabric-auth#417](https://github.com/BloclabsHQ/fabric-auth/pull/417) (workaround already shipped)

---

## Problem

`blockauth.utils.custom_exception.ValidationErrorWithCode` currently inherits from DRF's `APIException`, not from `rest_framework.exceptions.ValidationError`. Every consumer whose custom `EXCEPTION_HANDLER` branches on `isinstance(exc, ValidationError)` misses it, and field-level validation errors fall through to a generic 500-flavored envelope.

fabric-auth hit this on every signup and shipped a local workaround (PR #417). Every new consumer will hit the same paper cut.

A secondary concern: the current class flattens DRF's native `{field: [ErrorDetail, ...]}` shape into `{field: "space-joined message"}`, destroying per-error codes and per-error messages. This makes `ValidationErrorWithCode` misrepresent DRF's type contract even if inheritance were fixed.

## Goal

Make `ValidationErrorWithCode` an honest DRF `ValidationError` subclass so downstream `isinstance` and field-map iteration work without special-casing, and preserve DRF's native per-field list-of-`ErrorDetail` shape so per-error codes survive to the handler.

## Non-goals

- **Do not ship a blockauth exception handler.** Consumers keep owning their own response envelopes.
- **Do not rename the class.** All 17 callsites use `ValidationErrorWithCode` by name; the rename churn isn't worth the cosmetic win.
- **Do not ship a compat shim / feature flag for the old body shape.** Pre-1.0, the breaking-change policy (`.github/CONTRIBUTING.md`) explicitly allows breaking changes on minor bumps with a CHANGELOG entry. Two code paths forever is the tech debt we're trying to avoid.

---

## Design

### Class surface

```python
# blockauth/utils/custom_exception.py
from rest_framework.exceptions import APIException, ValidationError


class WalletConflictError(APIException):
    """Raised when a wallet address is already linked to a different account (HTTP 409)."""

    status_code = 409
    default_detail = "This wallet address is already linked to another account."
    default_code = "WALLET_IN_USE"


class ValidationErrorWithCode(ValidationError):
    """DRF ValidationError with a top-level error-code attribute for legacy envelopes.

    `.detail` is DRF-native `{field: [ErrorDetail, ...]}` — untransformed.
    `.error_code` carries a single top-level code (convenience for handlers
    that want to tag the whole response, not just individual fields).

    Subclassing `ValidationError` means `isinstance(exc, ValidationError)`
    checks in downstream exception handlers pick this up automatically and
    can iterate `.detail` as a standard DRF field map.
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

### Behavioral contract

| Aspect | Before | After |
|---|---|---|
| Base class | `APIException` | `ValidationError` |
| `isinstance(exc, ValidationError)` | `False` | `True` |
| `.detail` shape | `{"error_code": "4000", "detail": {field: "joined string"}}` | `{field: [ErrorDetail("msg", code="...")]}` (DRF-native, untransformed) |
| `.error_code` | not present (nested in `.detail`) | instance attribute |
| `.status_code` | `400` | `400` (unchanged) |
| `default_code` | `"4000"` | `"4000"` (unchanged) |
| Multi-message per field | joined with single space | preserved as a list |

### Response body impact (DRF default handler)

| Scenario | Before | After |
|---|---|---|
| Single-field validation failure | `{"detail": {"error_code": "4000", "detail": {"password": "This field is required."}}}` | `{"password": ["This field is required."]}` |
| Top-level code in wire body | present at `.detail.error_code` | not in body; handler reads `exc.error_code` |

Consumers using DRF's default handler see a flat field-map body. Consumers with custom handlers get `isinstance(exc, ValidationError) == True` and iterate `.detail` as a standard DRF field map; the top-level code is available via `exc.error_code`.

### Callsite impact (in-repo)

All 17 callsites pass `detail=<dict-shape>`; none pass `code=`. No signature change. Callsites keep working verbatim. Example:

```python
# blockauth/views/basic_auth_views.py (unchanged)
try:
    serializer.is_valid(raise_exception=True)
except ValidationError as e:
    raise ValidationErrorWithCode(detail=e.detail)
```

Now that `ValidationErrorWithCode` is a `ValidationError`, the `except (ValidationError, ValidationErrorWithCode)` at `basic_auth_views.py:324` is technically redundant (the second tuple element is covered by the first). **Leave it alone** for readability — deleting a name from a tuple to shave a line isn't worth the diff noise.

---

## Versioning & CHANGELOG

### Version bump

`0.6.1` → `0.7.0`. Breaking wire change per `.github/CONTRIBUTING.md`. Bump in both:
- `pyproject.toml` → `version = "0.7.0"`
- `blockauth/__init__.py` → `__version__ = "0.7.0"`

### CHANGELOG entry

Under `[Unreleased]` → `### Breaking Changes`:

> **`ValidationErrorWithCode` now subclasses DRF's `ValidationError`** (#101). `.detail` is a DRF-native `{field: [ErrorDetail, ...]}` map; the top-level error code moves from `.detail["error_code"]` to the `.error_code` attribute on the exception instance.
>
> - **Response body for DRF's default exception handler** changes from `{"detail": {"error_code": "4000", "detail": {field: message}}}` to `{field: [message]}`. The top-level code is no longer in the body when using DRF's default handler.
> - **Custom exception handlers** that branch on `isinstance(exc, ValidationError)` now pick up `ValidationErrorWithCode` automatically and can iterate `exc.detail` as a DRF-native field map.
> - **Per-field multi-message behavior** changes: the old code joined multiple error messages per field into a single space-separated string. The new class preserves DRF's list of `ErrorDetail` so per-error codes and messages are iterable individually.

Under `### Migration notes`:

> If your service uses a custom DRF `EXCEPTION_HANDLER` that special-cases `ValidationErrorWithCode` by reading `exc.detail["error_code"]` or `exc.detail["detail"]`, switch to reading `exc.error_code` and iterating `exc.detail` as a standard DRF field map. If your service relies on DRF's default handler and was parsing the legacy envelope, switch to the DRF-native `{field: [message]}` shape.

### Release flow

1. Merge fix on `dev`; CI must be green.
2. Bump version in `pyproject.toml` and `blockauth/__init__.py` → `0.7.0`.
3. In `CHANGELOG.md`, cut `[Unreleased]` → `[0.7.0] - 2026-04-17`.
4. Tag `v0.7.0` and push; `publish.yml` validates the version match, builds, and creates a GitHub Release.
5. **fabric-auth follow-up (separate PR, out of scope for this fix):** bump the blockauth pin (`uv lock --upgrade-package blockauth`) and retire the `ValidationErrorWithCode` special-case branch in `structured_exception_handler` now that the generic `ValidationError` branch covers it. Filed as a fabric-auth issue by the implementer.

---

## Testing

### New test file

`blockauth/utils/tests/test_validation_error_with_code.py` — dedicated coverage, following the `test_wallet_conflict_error.py` convention.

| # | Test | Asserts |
|---|------|---------|
| 1 | `is_subclass_of_drf_validation_error` | `issubclass(ValidationErrorWithCode, rest_framework.exceptions.ValidationError)`. Guards the core contract — regressing this re-introduces #101. |
| 2 | `isinstance_check_passes_for_raised_instance` | Raise `ValidationErrorWithCode(...)`, catch with `except ValidationError`, confirm caught. Behavioral form of #1. |
| 3 | `detail_is_drf_native_field_map` | Input `{"password": [ErrorDetail("required", code="required")]}` → `.detail["password"]` is a list of `ErrorDetail`, code preserved, no string join. |
| 4 | `error_code_derived_from_first_field_code` | Input `{"email": [ErrorDetail("bad", code="invalid")]}` → `.error_code == "invalid"`. |
| 5 | `error_code_required_maps_to_4000` | Input `{"email": [ErrorDetail("x", code="required")]}` → `.error_code == "4000"`. |
| 6 | `error_code_explicit_overrides_derivation` | `ValidationErrorWithCode(detail={...}, code="4042")` → `.error_code == "4042"`. |
| 7 | `error_code_falls_back_to_default_for_bare_strings` | Input `{"email": "raw string"}` → `.error_code == "4000"` (no `TypeError`). |
| 8 | `error_code_falls_back_to_default_for_empty_detail` | Input `{}` → `.error_code == "4000"` (no `IndexError` / `StopIteration`). |
| 9 | `default_detail_when_none_passed` | `ValidationErrorWithCode()` → `.detail == {"non_field_errors": [ErrorDetail("A validation error occurred...")]}`, `.error_code == "4000"`. |
| 10 | `multi_message_per_field_preserved_as_list` | Input `{"password": [ErrorDetail("too short"), ErrorDetail("no digits")]}` → `.detail["password"]` is a 2-element list; not joined. |
| 11 | `status_code_is_400` | Instance `.status_code == 400`. |
| 12 | `default_drf_handler_renders_field_map` | Drive `rest_framework.views.exception_handler(exc, context)` and assert `response.data == {"password": ["This field is required."]}`, `response.status_code == 400`. Locks in the new wire contract. |

### Existing-test audit

Pre-spec grep of the test tree:

- `blockauth/utils/tests/test_wallet_link_serializer.py` — references `error_code` only on DRF `ErrorDetail.code` surfaced via serializer `.errors`. **Unaffected** (reads the underlying DRF shape, not `ValidationErrorWithCode.detail`).
- `blockauth/totp/tests/{test_totp_service,test_security}.py` — reference `error_code` only on TOTP's own exception classes (unrelated). **Unaffected.**
- `blockauth/views/tests/*.py` — no assertions on `response.data["detail"]["error_code"]` or the legacy double-nested envelope. **No updates needed.**

If an implementation-time regression surfaces a test that did implicitly rely on the legacy body shape, update it to the new `{field: [message]}` shape and call it out in the PR.

### Verification commands

```bash
uv run pytest blockauth/utils/tests/test_validation_error_with_code.py -v
uv run pytest blockauth/ -q          # full suite must stay green
uv run black blockauth/ && uv run isort blockauth/ && uv run flake8 blockauth/
```

---

## Implementation notes

- **Single-file change** for the core behavior: `blockauth/utils/custom_exception.py`.
- **Docs:** no runtime doc changes required. `CLAUDE.md` mentions `ValidationErrorWithCode` once in the architecture tree — no edit needed.
- **Lint gate:** `flake8`, `black`, `isort` are enforced.
- **No new dependencies.**
- **No migration** (the class is in-process only; no DB, no cache).

## Out of scope

- Shipping a `blockauth.utils.exception_handler.blockauth_exception_handler` (issue #101's Option B). Reasonable follow-up; separate design.
- Retiring fabric-auth PR #417's `ValidationErrorWithCode` special-case branch — fabric-auth-side work, filed as a separate issue there.
- Any change to `WalletConflictError` or other blockauth exceptions.
