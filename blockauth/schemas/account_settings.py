from blockauth.schemas.examples.account_settings import password_change_bad_request_examples, \
    email_change_bad_request_examples, email_change_confirm_bad_request_examples
from blockauth.schemas.examples.common import authorization_combo_examples, otp_rate_limit_exceed
from blockauth.schemas.factory import CustomOpenApiResponse

password_change_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=password_change_bad_request_examples
        ),
        401: CustomOpenApiResponse(
            status=401,
            examples=authorization_combo_examples
        ),
    }
}

email_change_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=email_change_bad_request_examples
        ),
        401: CustomOpenApiResponse(
            status=401,
            examples=authorization_combo_examples
        ),
        429: CustomOpenApiResponse(
            status=429,
            examples=[
                otp_rate_limit_exceed
            ]
        )
    }
}

email_change_confirm_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=email_change_confirm_bad_request_examples
        ),
        401: CustomOpenApiResponse(
            status=401,
            examples=authorization_combo_examples
        )
    }
}