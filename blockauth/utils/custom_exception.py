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
            detail = {"non_field_errors": ["A validation error occurred. Please check your input and try again."]}
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
