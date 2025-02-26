from drf_spectacular.utils import OpenApiExample

from blockauth.schemas.examples.common import invalid_otp, expired_otp

"""password change"""

password_change_empty_input = OpenApiExample(
    name='password_change_empty_input',
    summary='Empty input',
    value={
        "old_password": [
            "This field is required."
        ],
        "new_password": [
            "This field is required."
        ],
        "confirm_password": [
            "This field is required."
        ]
    }
)

password_change_invalid_password = OpenApiExample(
    name='password_change_invalid_password',
    summary='Invalid password',
    value={
        "old_password": [
            "This password is too short. It must contain at least 8 characters.",
            "This password is too common.",
            "This password is entirely numeric."
        ],
        "new_password": [
            "This password is too short. It must contain at least 8 characters.",
            "This password is too common.",
            "This password is entirely numeric."
        ],
        "confirm_password": [
            "This password is too short. It must contain at least 8 characters.",
            "This password is too common.",
            "This password is entirely numeric."
        ]
    }
)

password_change_unmatched_password = OpenApiExample(
    name='password_change_unmatched_password',
    summary='Unmatched passwords',
    value={
        "detail": [
            "Passwords do not match."
        ]
    }
)

password_change_incorrect_password = OpenApiExample(
    name='password_change_incorrect_password',
    summary='Incorrect old password',
    value={
        "detail": [
            "Old password is incorrect."
        ]
    }
)

password_change_bad_request_examples = [
    password_change_empty_input,
    password_change_invalid_password,
    password_change_unmatched_password,
    password_change_incorrect_password
]

"""email change"""

email_change_empty_input = OpenApiExample(
    name='email_change_empty_input',
    summary='Empty input',
    value={
        "email": [
            "This field is required."
        ],
        "password": [
            "This field is required."
        ]
    }
)

email_change_invalid_input = OpenApiExample(
    name='common_invalid_email_password',
    summary='Invalid email & password',
    value={
        "email": [
            "Enter a valid email address."
        ],
        "current_password": [
            "This password is too short. It must contain at least 8 characters.",
            "This password is too common.",
            "This password is entirely numeric."
        ]
    }
)

email_change_incorrect_password = OpenApiExample(
    name='email_change_incorrect_password',
    summary='Incorrect password',
    value={
        "current_password": [
            "Incorrect password."
        ]
    }
)

email_change_passwordless_account = OpenApiExample(
    name='email_change_passwordless_account',
    summary='Passwordless account',
    value={
        "detail": [
            "Passwordless account. Please change or reset password."
        ]
    }
)

email_change_bad_request_examples = [
    email_change_empty_input,
    email_change_invalid_input,
    email_change_incorrect_password,
    email_change_passwordless_account
]


email_change_confirm_empty_input = OpenApiExample(
    name='email_change_confirm_empty_input',
    summary='Empty input',
    value={
        "email": [
            "This field is required."
        ],
        "code": [
            "This field is required."
        ],
        "new_email": [
            "This field is required."
        ]
    }
)

email_change_confirm_invalid_input = OpenApiExample(
    name='email_change_confirm_invalid_input',
    summary='Invalid input',
    value={
        "email": [
            "Enter a valid email address."
        ],
        "new_email": [
            "Enter a valid email address."
        ]
    }
)

email_change_confirm_invalid_new_email = OpenApiExample(
    name='email_change_confirm_invalid_new_email',
    summary='Can not use New Email if already used',
    value={
        "new_email": [
            "Can't use this email"
        ]
    }
)

email_change_confirm_bad_request_examples = [
    email_change_confirm_empty_input,
    email_change_confirm_invalid_input,
    email_change_confirm_invalid_new_email,
    invalid_otp,
    expired_otp
]