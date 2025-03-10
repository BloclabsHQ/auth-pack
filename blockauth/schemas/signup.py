from drf_spectacular.utils import OpenApiResponse
from blockauth.schemas.factory import CustomOpenApiResponse

signup_schema = {
    "responses": {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400)
            # examples=[
            #     common_invalid_identifier_password,
            #     common_empty_identifier_password,
            #     sign_up_identifier_already_in_use,
            # ],
    }
}

signup_confirm_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400),
            # examples=[
            #     signup_confirm_empty_input,
            #     common_invalid_identifier,
            #     invalid_otp,
            #     expired_otp
            # ]

    }
}

signup_resend_otp_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400),
            # examples=[
            #     common_invalid_identifier,
            #     common_empty_identifier,
            #     signup_user_not_found,
            #     sign_up_identifier_already_in_use
            # ]
        429: OpenApiResponse(
            description='Too many requests',
            response={
                'type': 'object',
                'properties': {
                    'detail': {'type': 'string'}
                }
            },
            # examples=[signup_resend_otp_rate_limit],
        )
    }
}