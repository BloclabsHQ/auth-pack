import logging
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from blockauth.utils.config import get_config, get_block_auth_user_model
from blockauth.utils.token import AUTH_TOKEN_CLASS

logger = logging.getLogger(__name__)

_HTTP_HEADER_ENCODING = 'iso-8859-1'


def _get_authorization_header(request):
    auth_header_name = get_config('AUTH_HEADER_NAME')
    auth_header = request.META.get(auth_header_name, b'')
    if isinstance(auth_header, str):
        auth_header = auth_header.encode(_HTTP_HEADER_ENCODING)
    return auth_header.decode()

class JWTAuthentication(BaseAuthentication):
    """
    Custom JWT authentication class that verifies the token.
    """
    _HEADER_PREFIX = 'bearer'
    _TOKEN_CLASS = AUTH_TOKEN_CLASS

    def authenticate(self, request):
        auth_header = _get_authorization_header(request).split()
        if not auth_header:
            return None

        if len(auth_header) == 1:
            raise AuthenticationFailed('Invalid authorization header. No credentials provided')
        elif len(auth_header) > 2 or auth_header[0].lower() != self._HEADER_PREFIX:
            raise AuthenticationFailed(
                f'Invalid token header. Authorization header format must be | {self._HEADER_PREFIX} <token> | format'
            )

        _, validated_token = auth_header
        payload = self._TOKEN_CLASS().decode_token(validated_token)
        if payload["type"] != "access":
            raise AuthenticationFailed("Invalid token type. Only access tokens are allowed")
        return self._get_user(payload), validated_token

    def _get_user(self, payload):
        user_model = get_block_auth_user_model()
        try:
            user_id_field = get_config('USER_ID_FIELD')
            user_id = payload["user_id"]
            user = user_model.objects.get(**{user_id_field: user_id})
        except KeyError:
            raise AuthenticationFailed("Token contained no recognizable user id field")
        except user_model.DoesNotExist:
            raise AuthenticationFailed('User not found')
        except Exception as e:
            logger.error(f'Error occurred while authenticating user: {e}')
            raise AuthenticationFailed(f'Authentication failed')
        return user

    def authenticate_header(self, request):
        return self._HEADER_PREFIX