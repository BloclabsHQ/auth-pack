from drf_spectacular.utils import OpenApiExample

"""identifier & others"""
common_invalid_identifier_password = OpenApiExample(
    name="common_invalid_identifier_password",
    summary="Invalid identifier & password",
    value={
        "identifier": ["enter a valid email address / phone number."],
        "password": [
            "This password is too short. It must contain at least 8 characters.",
            "This password is too common.",
            "This password is entirely numeric.",
        ],
    },
)

common_empty_identifier_password = OpenApiExample(
    name="common_empty_identifier_password",
    summary="Empty identifier & password",
    value={"identifier": ["This field is required."], "password": ["This field is required."]},
)

common_empty_identifier_otp = OpenApiExample(
    name="common_empty_identifier_otp",
    summary="Empty identifier & otp",
    value={"identifier": ["This field is required."], "code": ["This field is required."]},
)

common_invalid_identifier = OpenApiExample(
    name="common_invalid_identifier",
    summary="Invalid identifier",
    value={"identifier": ["invalid email or phone number."]},
)

common_empty_identifier = OpenApiExample(
    name="common_empty_identifier", summary="Invalid identifier", value={"identifier": ["This field is required."]}
)

"""otp"""

invalid_otp = OpenApiExample(name="invalid_otp", summary="Invalid OTP", value={"code": "Invalid OTP."})

expired_otp = OpenApiExample(name="expired_otp", summary="Expired OTP", value={"code": "OTP has expired."})

otp_rate_limit_exceed = OpenApiExample(
    name="otp_rate_limit_exceed",
    summary="OTP rate limit exceed",
    value={"detail": "Request limit exceeded. Please try again after x seconds."},
)

"""token"""


token_expired = OpenApiExample(name="token_expired", summary="Token expired", value={"detail": "Token has expired."})

token_invalid = OpenApiExample(name="token_invalid", summary="Invalid token", value={"detail": "Invalid token."})

token_invalid_signature = OpenApiExample(
    name="token_invalid_signature", summary="Invalid signature", value={"detail": "Invalid signature."}
)

empty_refresh_token = OpenApiExample(
    name="empty_refresh_token", summary="Empty refresh token", value={"refresh": ["This field is required."]}
)

empty_authorization_header = OpenApiExample(
    name="empty_authorization_header",
    summary="Empty authorization header",
    value={"detail": "Authentication credentials were not provided."},
)

invalid_authorization_header = OpenApiExample(
    name="invalid_authorization_header",
    summary="Invalid authorization header",
    value={"detail": "Invalid Authorization header."},
)

unrecognized_user_id_field = OpenApiExample(
    name="unrecognized_user_id_field",
    summary="Unrecognized user id field",
    value={"detail": "Token contained no recognizable user id field"},
)

unrecognized_user = OpenApiExample(
    name="unrecognized_user", summary="Unrecognized user", value={"detail": "User not found"}
)

authorization_combo_examples = [
    token_expired,
    token_invalid,
    token_invalid_signature,
    empty_authorization_header,
    unrecognized_user_id_field,
    unrecognized_user,
    invalid_authorization_header,
]
