from blockauth.schemas.examples.login import basic_login_schema_examples
from blockauth.schemas.examples.common import invalid_otp, expired_otp, empty_refresh_token, \
    token_expired, token_invalid, token_invalid_signature
from blockauth.schemas.factory import CustomOpenApiResponse
from blockauth.schemas.examples.common import common_empty_email_password, common_invalid_email_password, common_empty_email, \
    otp_rate_limit_exceed, common_empty_email_otp

basic_login_schema = {
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            response={
                'type': 'object',
                'properties': {
                    'access': {'type': 'string'},
                    'refresh': {'type': 'string'}
                }
            }
        ),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=[
                common_invalid_email_password,
                common_empty_email_password,
            ] + basic_login_schema_examples
        )
    }
}

passwordless_login_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=[
                common_empty_email,
            ]
        ),
        429: CustomOpenApiResponse(
            status=429,
            examples=[
                otp_rate_limit_exceed
            ]
        )
    }
}

passwordless_login_confirm_schema = {
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            response={
                'type': 'object',
                'properties': {
                    'access': {'type': 'string'},
                    'refresh': {'type': 'string'}
                }
            }
        ),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=[
                common_empty_email_otp,
                invalid_otp,
                expired_otp
            ]
        )
    }
}

refresh_token_schema = {
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            response={
                'type': 'object',
                'properties': {
                    'access': {'type': 'string'},
                    'refresh': {'type': 'string'}
                }
            }
        ),
        500: CustomOpenApiResponse(status=500),
        401: CustomOpenApiResponse(
            status=401,
            examples=[
                token_expired,
                token_invalid,
                token_invalid_signature
            ]
        ),
        400: CustomOpenApiResponse(
            status=400,
            examples=[
                empty_refresh_token,
            ]
        )
    }
}
