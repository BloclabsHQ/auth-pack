from blockauth.schemas.factory import CustomOpenApiResponse

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
        400: CustomOpenApiResponse(status=400),
        500: CustomOpenApiResponse(status=500),
        # 400: CustomOpenApiResponse(
        #     status=400,
        #     examples=[
        #         common_invalid_identifier_password,
        #         common_empty_identifier_password,
        #     ] + basic_login_schema_examples
        # )
    }
}

passwordless_login_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400),
        # 400: CustomOpenApiResponse(
        #     status=400,
        #     examples=[
        #         common_invalid_identifier,
        #         common_empty_identifier
        #     ]
        # ),
        429: CustomOpenApiResponse(
            status=429,
            # examples=[
            #     otp_rate_limit_exceed
            # ]
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
        400: CustomOpenApiResponse(status=400),
        # 400: CustomOpenApiResponse(
        #     status=400,
        #     examples=[
        #         common_empty_identifier_otp,
        #         invalid_otp,
        #         expired_otp
        #     ]
        # )
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
        400: CustomOpenApiResponse(status=400),
        401: CustomOpenApiResponse(
            status=401,
            # examples=[
            #     token_expired,
            #     token_invalid,
            #     token_invalid_signature
            # ]
        ),
        # 400: CustomOpenApiResponse(
        #     status=400,
        #     examples=[
        #         empty_refresh_token,
        #     ]
        # )
    }
}
