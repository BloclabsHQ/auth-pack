from drf_spectacular.utils import OpenApiParameter
from blockauth.schemas.factory import CustomOpenApiResponse
from blockauth.schemas.examples.social_auth import social_authorization_code, social_invalid_auth_config, social_user_info_missing

"""Google"""

google_auth_login_schema ={
    'responses': {
        301: CustomOpenApiResponse(status=301),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400, examples=[social_invalid_auth_config])
    }
}

google_auth_callback_schema ={
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code from Facebook',
            required=True,
            type=str
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(status=200),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400,
            examples=[
                social_authorization_code,
                social_invalid_auth_config,
                social_user_info_missing
            ]
        )
    }
}


"""Facebook"""

facebook_auth_login_schema ={
    'responses': {
        301: CustomOpenApiResponse(status=301),
        500: CustomOpenApiResponse(status=500),
        400: CustomOpenApiResponse(status=400,
            examples=[
                social_invalid_auth_config
            ]
        )
    }
}

facebook_auth_callback_schema ={
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code from Facebook',
            required=True,
            type=str
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(status=200,
            response={
                'type': 'object',
                'properties': {
                    'access': {'type': 'string'},
                    'refresh': {'type': 'string'}
                }
            }
        ),
        500: CustomOpenApiResponse(status=500),
        400:CustomOpenApiResponse(status=400,
            examples=[
                social_authorization_code,
                social_invalid_auth_config,
                social_user_info_missing
            ]
        )
    }
}


"""LinkedIn"""

linkedin_auth_login_schema ={
    'responses': {
        301: CustomOpenApiResponse(status=301),
        500: CustomOpenApiResponse(status=500),
        400:CustomOpenApiResponse(status=400,
            examples=[
                social_invalid_auth_config
            ]
        )
    }
}

linkedin_auth_callback_schema ={
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code from Facebook',
            required=True,
            type=str
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(status=200,
            response={
                'type': 'object',
                'properties': {
                    'access': {'type': 'string'},
                    'refresh': {'type': 'string'}
                }
            }
        ),
        400:CustomOpenApiResponse(status=400,
            examples=[
                social_authorization_code,
                social_invalid_auth_config,
                social_user_info_missing
            ]
        ),
        500: CustomOpenApiResponse(status=500)
    }
}