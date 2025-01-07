import logging
from datetime import datetime

import jwt
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from blockauth.utils.config import get_config

logger = logging.getLogger(__name__)


class AbstractToken:
    def generate_token(self, user_id: dict, token_type: str, token_lifetime: datetime):
        raise NotImplementedError

    def decode_token(self, token):
        raise NotImplementedError


class Token(AbstractToken):
    def __init__(self, secret_key=get_config('SECRET_KEY'), algorithm=get_config('ALGORITHM')):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def generate_token(self, user_id: int, token_type: str, token_lifetime: datetime):
        payload = {
            "user_id": user_id,
            "exp": timezone.now() + token_lifetime,
            "iat": timezone.now(),
            "type": token_type
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.error("Token has expired.")
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            logger.error("Invalid token.")
            raise AuthenticationFailed("Invalid token.")
        except jwt.InvalidSignatureError:
            logger.error("Invalid signature.")
            raise AuthenticationFailed("Invalid signature.")

def generate_auth_token(token_class: AbstractToken, user_id: str):
    access_token = token_class.generate_token(**{
        "user_id": user_id,
        "token_type": "access",
        "token_lifetime": get_config('ACCESS_TOKEN_LIFETIME')
    }),

    refresh_token = token_class.generate_token(**{
        "user_id": user_id,
        "token_type": "refresh",
        "token_lifetime": get_config('REFRESH_TOKEN_LIFETIME')
    })
    return access_token, refresh_token



AUTH_TOKEN_CLASS = Token