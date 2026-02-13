from drf_spectacular.utils import OpenApiExample

"""signup examples"""

sign_up_identifier_already_in_use = OpenApiExample(
    name='sign_up_identifier_already_in_use',
    summary='Identifier already in use',
    value={
        "identifier": [
            "Unable to complete registration with the provided information."
        ]
    }
)

"""signup resend otp examples"""
signup_resend_otp_empty_input = OpenApiExample(
    name='signup_resend_otp_empty_input',
    summary='Empty input',
    value={
        "identifier": [
            "This field is required."
        ]
    }
)

signup_user_not_found = OpenApiExample(
    name='signup_user_not_found',
    summary='User not found',
    value={
        "identifier": [
            "the provided identifier is not acceptable."
        ]
    }
)

signup_resend_otp_rate_limit = OpenApiExample(
    name='signup_resend_otp_rate_limit',
    summary='Rate limit exceeded',
    value={
        "detail": "Rate limit exceeded. Try again in 30 seconds."
    }
)

"""signup confirm examples"""
signup_confirm_empty_input = OpenApiExample(
    name='signup_confirm_empty_input',
    summary='Empty input',
    value={
        "identifier": [
            "This field is required."
        ],
        "code": [
            "This field is required."
        ]
    }
)

signup_confirm_invalid_identifier = OpenApiExample(
    name='signup_confirm_invalid_identifier',
    summary='Invalid identifier',
    value={
        "identifier": [
            "invalid email or phone number."
        ]
    }
)