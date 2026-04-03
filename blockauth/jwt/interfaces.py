from abc import ABC, abstractmethod
from typing import Any, Dict


class CustomClaimsProvider(ABC):
    """
    Interface for providing custom JWT claims.
    Any service can implement this to add custom data to tokens.
    """

    @abstractmethod
    def get_custom_claims(self, user) -> Dict[str, Any]:
        """
        Return custom claims to be added to the JWT token.

        Args:
            user: The user object for which to generate claims

        Returns:
            Dictionary of custom claims
        """

    @abstractmethod
    def validate_custom_claims(self, claims: Dict[str, Any]) -> bool:
        """
        Optional: Validate custom claims during token verification.

        Args:
            claims: The custom claims from the token

        Returns:
            True if claims are valid, False otherwise
        """
        return True
