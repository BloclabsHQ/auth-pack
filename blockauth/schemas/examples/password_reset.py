from drf_spectacular.utils import OpenApiExample

password_reset_empty_input = OpenApiExample(
    name='password_reset_empty_input',
    summary='Empty input',
    value={
        "identifier": [
            "This field is required."
        ],
        "code": [
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

password_reset_invalid_password = OpenApiExample(
    name='password_reset_invalid_password',
    summary='Invalid password',
    value={
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

password_reset_unmatched_password = OpenApiExample(
    name='password_reset_unmatched_password',
    summary='Unmatched passwords',
    value={
        "detail": [
            "Passwords do not match."
        ]
    }
)

password_reset_400_examples = [
    password_reset_empty_input,
    password_reset_invalid_password,
    password_reset_unmatched_password
]