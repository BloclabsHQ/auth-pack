import logging
from abc import ABC, abstractmethod
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.generics import sanitize_log_context

logger = logging.getLogger(__name__)

class BaseTrigger(ABC):
    """
    All trigger classes should extend BaseTrigger.
    """

    @abstractmethod
    def trigger(self, context: dict) -> None:
        """
        This method should be overridden in the child class to implement the trigger logic.
        The context should contain the necessary information to help developers apply their own logic.
        """
        raise NotImplementedError("must be overridden.")


# pre signup trigger
class DummyPreSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called before the user signs up.
        """
        blockauth_logger.info(f"Pre signup trigger called with context")


# post signup trigger
class DummyPostSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user signs up.
        """
        blockauth_logger.info(f"Post signup trigger called with context")


# post login trigger
class DummyPostLoginTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user logs in.
        """
        blockauth_logger.info(f"Post login trigger called with context")

# post password change trigger
class DummyPostPasswordChangeTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user changes their password.
        """
        blockauth_logger.info(f"Post password change trigger called with context")


# post password reset trigger
class DummyPostPasswordResetTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user resets their password.
        """
        blockauth_logger.info(f"Post password reset trigger called with context")


# NOTE: For custom triggers, always use blockauth_logger and sanitize_log_context for any logging or print statements to avoid leaking sensitive data.