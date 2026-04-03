from rest_framework.exceptions import APIException


class ValidationErrorWithCode(APIException):
    status_code = 400
    default_code = "4000"

    def __init__(self, detail=None, code=None):
        errors = list(detail.values())[0]
        error_code = errors[0].code if isinstance(errors, list) else errors.code

        if code is None:
            code = self.default_code if error_code == "required" else error_code
        if detail is None:
            detail = {"non_field_errors": "A validation error occurred. Please check your input and try again."}

        transformed_detail = self.transform_errors(detail)
        super().__init__({"error_code": code, "detail": transformed_detail})

    def transform_errors(self, errors):
        transformed = {}
        for field, messages in errors.items():
            if isinstance(messages, list):
                transformed[field] = " ".join(messages)  # Join multiple errors
            else:
                transformed[field] = str(messages)  # Convert non-list errors
        return transformed
