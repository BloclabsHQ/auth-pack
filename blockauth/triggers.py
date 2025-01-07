import logging
from abc import ABC, abstractmethod

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
        logger.info(f"Pre signup trigger called with context: {context}.")


# post signup trigger
class DummyPostSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user signs up.
        """
        logger.info(f"Post signup trigger called with context: {context}.")


# post login trigger
class DummyPostLoginTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        """
        This trigger will be called after the user logs in.
        """
        logger.info(f"Post login trigger called with context: {context}.")