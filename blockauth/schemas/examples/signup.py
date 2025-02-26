from drf_spectacular.utils import OpenApiExample

"""signup examples"""

sign_up_email_already_in_use = OpenApiExample(
    name='sign_up_email_already_in_use',
    summary='Email already in use',
    value={
        "email": [
            "Request cannot be processed"
        ]
    }
)

"""signup resend otp examples"""
singup_resend_otp_empty_input = OpenApiExample(
    name='singup_resend_otp_empty_input',
    summary='Empty input',
    value={
        "email": [
            "This field is required."
        ]
    }
)

signup_user_not_found = OpenApiExample(
    name='signup_user_not_found',
    summary='User not found',
    value={
        "email": [
            "Request cannot be processed"
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
        "email": [
            "This field is required."
        ],
        "code": [
            "This field is required."
        ]
    }
)

signup_confirm_invalid_email = OpenApiExample(
    name='signup_confirm_invalid_email',
    summary='Invalid email',
    value={
        "email": [
            "Enter a valid email address."
        ]
    }
)