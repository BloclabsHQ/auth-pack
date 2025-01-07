from drf_spectacular.utils import OpenApiResponse

from blockauth.schemas.examples.common import common_invalid_email_password, common_empty_email_password, \
    common_empty_email, common_invalid_email
from blockauth.schemas.examples.common import invalid_otp, expired_otp
from blockauth.schemas.examples.signup import sign_up_email_already_in_use, \
    signup_user_not_found, signup_resend_otp_rate_limit, signup_confirm_empty_input
from blockauth.schemas.factory import CustomOpenApiResponse

signup_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: OpenApiResponse(
            description='Invalid request',
            response={
                'type': 'object',
                'properties': {
                    'email': {'type': 'array', 'items': {'type': 'string'}},
                    'password': {'type': 'array', 'items': {'type': 'string'}}
                }
            },
            examples=[
                common_invalid_email_password,
                common_empty_email_password,
                sign_up_email_already_in_use
            ]
        )
    }
}

signup_confirm_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: OpenApiResponse(
            description='Invalid request',
            response={
                'type': 'object',
                'properties': {
                    'email': {'type': 'array', 'items': {'type': 'string'}},
                    'otp_code': {'type': 'array', 'items': {'type': 'string'}}
                }
            },
            examples=[
                signup_confirm_empty_input,
                common_invalid_email,
                invalid_otp,
                expired_otp
            ]
        )
    }
}

signup_resend_otp_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: OpenApiResponse(
            description='Invalid request',
            response={
                'type': 'object',
                'properties': {
                    'email': {'type': 'array', 'items': {'type': 'string'}}
                }
            },
            examples=[
                common_empty_email,
                signup_user_not_found,
                sign_up_email_already_in_use
            ]
        ),
        429: OpenApiResponse(
            description='Too many requests',
            response={
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            },
            examples=[signup_resend_otp_rate_limit],
        )
    }
}