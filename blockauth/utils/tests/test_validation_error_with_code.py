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
