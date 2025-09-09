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
    """
    Enhanced OTP sending with security features:
    1. Invalidates old OTPs before creating new ones
    2. Prevents multiple active OTPs per identifier
    3. Enhanced logging and monitoring
    """
    identifier = data['identifier']
    method = data['method']
    verification_type = data['verification_type']
    
    try:
        # Step 1: Invalidate any existing active OTPs for this identifier and subject
        invalidated_count = _invalidate_existing_otps(identifier, subject)
        
        if invalidated_count > 0:
            blockauth_logger.warning(
                f"Invalidated {invalidated_count} existing OTP(s) before generating new one",
                sanitize_log_context({
                    "identifier": identifier,
                    "subject": subject,
                    "invalidated_count": invalidated_count
                })
            )
        
        # Step 2: Generate new OTP
        code = OTP.generate_otp(get_config('OTP_LENGTH'))
        OTP.objects.create(identifier=identifier, code=code, subject=subject)
        
        # Step 3: Prepare context for notification
        context = {**data, 'code': code, 'otp_subject': subject}
        
        if verification_type == 'link' and get_config('CLIENT_APP_URL'):
            context['verification_url'] = f'{get_config('CLIENT_APP_URL')}/{subject}/verify?code={code}&identifier={identifier}'
        
        # Step 4: Send notification
        communication_class = get_config('DEFAULT_NOTIFICATION_CLASS')()
        blockauth_logger.success(
            f"OTP {verification_type} sent via {method} for {subject}",
            sanitize_log_context({
                "identifier": identifier,
                "subject": subject,
                "method": method,
                "verification_type": verification_type,
                "invalidated_old_otps": invalidated_count
            })
        )
        communication_class.notify(method=method, event=NotificationEvent.OTP_REQUEST, context=context)
        
    except Exception as e:
        blockauth_logger.error(
            f"OTP generation failed for {subject}",
            sanitize_log_context({
                "identifier": identifier,
                "subject": subject,
                "method": method,
                "verification_type": verification_type,
                "error": str(e)
            })
        )
        raise


def _invalidate_existing_otps(identifier: str, subject: str) -> int:
    """
    Invalidate any existing active OTPs for the given identifier and subject.
    
    This prevents multiple active OTPs which could lead to:
    - OTP confusion (user might use an older OTP)
    - Brute force attacks (attacker can generate multiple OTPs)
    - Resource abuse (spamming OTP generation)
    
    Args:
        identifier: Email or phone number
        subject: OTP subject (LOGIN, SIGNUP, etc.)
        
    Returns:
        int: Number of OTPs that were invalidated
    """
    try:
        # Find all active OTPs for this identifier and subject
        active_otps = OTP.objects.filter(
            identifier=identifier,
            subject=subject,
            is_used=False
        )
        
        # Count before invalidation for logging
        count = active_otps.count()
        
        if count > 0:
            # Mark as used instead of deleting to maintain audit trail
            active_otps.update(is_used=True)
            
            blockauth_logger.debug(
                f"Invalidated {count} existing OTP(s)",
                sanitize_log_context({
                    "identifier": identifier,
                    "subject": subject,
                    "invalidated_count": count
                })
            )
        
        return count
        
    except Exception as e:
        blockauth_logger.error(
            f"Failed to invalidate existing OTPs",
            sanitize_log_context({
                "identifier": identifier,
                "subject": subject,
                "error": str(e)
            })
        )
        # Don't raise exception - allow OTP generation to continue
        return 0