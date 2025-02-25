import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class CommunicationPurpose:
    """
    This class contains the purpose of the communication.
    """
    PASSWORDLESS_LOGIN = "passwordless_login"
    SIGN_UP = "sign_up"
    PASSWORD_CHANGE = "password_change"
    OTP_RESEND = "otp_resend"


class BaseCommunication(ABC):
    """
    All trigger classes should extend BaseCommunication.
    """

    @abstractmethod
    def communicate(self, purpose: str, context: dict) -> None:
        """
        This method should be overridden in the child class to implement the communicattion logic.
        :param purpose: should be used to identify the purpose of the communication.
        :param context: should contain the necessary information to send the email, sms, etc. by developers own logic.
        """
        pass


class DummyCommunication(BaseCommunication):
    def communicate(self, purpose: str, context: dict) -> None:
        logger.info(
            f"Communication class called with context: {context} for {purpose} purpose. Developers will write logic to fulfill the purpose"
        )