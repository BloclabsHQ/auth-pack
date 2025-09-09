import json
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, date
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.contrib.auth.password_validation import get_default_password_validators
from blockauth.models.user import AuthenticationType


def model_to_json(instance: models.Model, remove_fields: tuple = None) -> Dict[str, Any]:
    """
    Convert a Django model instance to a JSON-serializable dictionary.
    
    Args:
        instance: Django model instance
        remove_fields: Tuple of field names to exclude from the output
        
    Returns:
        Dictionary representation of the model instance
    """
    if remove_fields is None:
        remove_fields = ()
    
    data = {}
    for field in instance._meta.fields:
        if field.name not in remove_fields:
            value = getattr(instance, field.name)
            if isinstance(value, (datetime, date)):
                data[field.name] = value.isoformat()
            else:
                data[field.name] = value
    
    return data


def sanitize_log_context(data: Dict[str, Any], additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Sanitize sensitive data from logging context.
    
    Args:
        data: Original data dictionary
        additional_context: Additional context to include
        
    Returns:
        Sanitized dictionary safe for logging
    """
    from blockauth.constants import SENSITIVE_FIELDS, REDACTION_STRING
    
    sanitized = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_FIELDS:
            sanitized[key] = REDACTION_STRING
        else:
            sanitized[key] = value
    
    if additional_context:
        sanitized.update(additional_context)
    
    return sanitized


def get_authentication_types_display(authentication_types: List[str]) -> List[str]:
    """
    Get human-readable display names for authentication types.
    
    Args:
        authentication_types: List of authentication type codes
        
    Returns:
        List of human-readable authentication type names
    """
    if not authentication_types:
        return []
    
    display_names = []
    for auth_type in authentication_types:
        try:
            display_name = AuthenticationType(auth_type).label
            display_names.append(display_name)
        except ValueError:
            # If not a valid choice, use the original value
            display_names.append(auth_type)
    
    return display_names


def validate_authentication_type(auth_type: str) -> bool:
    """
    Validate if an authentication type is supported.
    
    Args:
        auth_type: Authentication type to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        AuthenticationType(auth_type)
        return True
    except ValueError:
        return False


def get_available_authentication_types() -> List[Dict[str, str]]:
    """
    Get all available authentication types with their codes and labels.
    
    Returns:
        List of dictionaries with 'code' and 'label' keys
    """
    return [
        {'code': choice[0], 'label': choice[1]} 
        for choice in AuthenticationType.choices
    ]


def get_password_help_text():
    """
    Retrieve help text from all password validators in settings.
    """
    validators = get_default_password_validators()
    help_texts = [validator.get_help_text() for validator in validators]
    return '\n\n'.join(help_texts)