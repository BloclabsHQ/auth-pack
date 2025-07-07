import logging
from abc import ABC, abstractmethod

from blockauth.models.otp import OTP
from blockauth.utils.config import get_config
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.generics import sanitize_log_context

logger = logging.getLogger(__name__)


"""
================================
BELOW IS THE NOTIFICATION MODULE
================================
"""
class NotificationEvent:
    """
    This class contains the event of the notification.
    """
    OTP_REQUEST = "otp.request"
    SUCCESS_PASSWORD_RESET = "success.password_reset"
    SUCCESS_PASSWORD_CHANGE = "success.password_change"
    SUCCESS_EMAIL_CHANGE = "success.email_change"


class BaseNotification(ABC):
    """
    All trigger classes should extend BaseNotification.
    """

    @abstractmethod
    def notify(self, method: str, event: str, context: dict) -> None:
        """
        This method should be overridden in the child class to implement the notification logic.
        :param method: should be used to identify the method of communication (email, sms, etc.).
        :param event: should be used to identify the event of the communication.
        :param context: should contain the necessary information to send the email, sms, etc. by developers own logic.
        """
        pass


class DummyNotification(BaseNotification):
    def notify(self, method: str, event: str, context: dict) -> None:
        blockauth_logger.info(
            f"Notification sent using method: {method}, event: {event}", sanitize_log_context(context)
        )

"""
================================================================
BELOW ARE THE UTILITY FUNCTIONS THAT USE THE NOTIFICATION MODULE
================================================================
"""

def send_otp(data, subject):
    code = OTP.generate_otp(get_config('OTP_LENGTH'))
    OTP.objects.create(identifier=data['identifier'], code=code, subject=subject)

    # send OTP to user via email/sms etc
    method, identifier, verification_type = data['method'], data['identifier'], data['verification_type']
    context = {**data, 'code': code, 'otp_subject': subject}

    if verification_type == 'link' and get_config('CLIENT_APP_URL'):
        context['verification_url'] = f'{get_config('CLIENT_APP_URL')}/{subject}/verify?code={code}&identifier={identifier}'

    communication_class = get_config('DEFAULT_NOTIFICATION_CLASS')()
    blockauth_logger.info(
        f"Sending OTP via {method} for {subject}", sanitize_log_context(context)
    )
    communication_class.notify(method=method, event=NotificationEvent.OTP_REQUEST, context=context)