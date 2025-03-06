from blockauth.schemas.examples.common import invalid_otp, expired_otp, common_empty_identifier, \
    common_invalid_identifier
from blockauth.schemas.examples.password_reset import password_reset_400_examples
from blockauth.schemas.factory import CustomOpenApiResponse
from blockauth.schemas.examples.common import otp_rate_limit_exceed

password_reset_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=[
                common_empty_identifier,
                common_invalid_identifier
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

password_reset_confirm_schema = {
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(
            status=400,
            examples=password_reset_400_examples + [
                invalid_otp,
                expired_otp
            ]
        )
    }
}
