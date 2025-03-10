from drf_spectacular.utils import OpenApiResponse

class CustomOpenApiResponse(OpenApiResponse):
    def __init__(self, status, description=None, response=None, examples=None):
        resp = self.__factory(status, description, response, examples)
        super().__init__(
            description=resp.get('description'),
            response=resp.get('response'),
            examples=resp.get('examples')
        )

    def __factory(self, status_code, description=None, response=None, examples=None):
        if status_code == 200:
            return {
                'description': description or 'Success',
                'response': response or {
                    'type': 'object',
                    'properties': {
                        'message': {'type': 'string'}
                    }
                },
                'examples': examples
            }
        elif status_code == 301:
            return {'description': description or 'Redirect', 'examples': examples}
        elif status_code == 400:
            return {
                'description': description or 'Invalid request',
                'response': response or {
                    "type": "object",
                    "properties": {
                        "error_code": {"type": "string"},
                        "detail": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                        },
                    },
                },
                'examples': examples
            }
        elif status_code == 401:
            return {
                'description': description or 'Unauthorized',
                'response': response or {
                    'type': 'object',
                    'properties': {
                        'detail': {'type': 'string'}
                    }
                },
                'examples': examples
            }
        elif status_code == 429:
            return {
                'description': description or 'Too many requests',
                'response': response or {
                    'type': 'object',
                    'properties': {
                        'detail': {'type': 'string'}
                    }
                },
                'examples': examples
            }
        elif status_code == 500:
            return {
                'description': description or 'Server error',
                'response': response or {
                    'type': 'object',
                    'properties': {
                        'detail': {'type': 'string'}
                    }
                },
                'examples': examples
            }
        else:
            raise ValueError('Invalid status code')
