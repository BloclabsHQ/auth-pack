import json

from django.contrib.auth.password_validation import get_default_password_validators
from django.core.serializers.json import DjangoJSONEncoder
from django.forms import model_to_dict

_DEFAULT_FIELDS_TO_REMOVE = ['password', 'groups', 'user_permissions']

def model_to_json(model_instance, remove_fields: tuple[str] = ()) -> dict:
    """
    Convert model instance to json/dict.
    :param model_instance: model instance
    :param remove_fields: fields to remove from the json/dict
    :return: json/dict
    """
    otp_data = model_to_dict(model_instance)
    dump = json.dumps(otp_data, cls=DjangoJSONEncoder)
    data = json.loads(dump)

    for field in _DEFAULT_FIELDS_TO_REMOVE:
        data.pop(field, None)

    if remove_fields:
        for field in remove_fields:
            data.pop(field, None)
    return data


def get_password_help_text():
    """
    Retrieve help text from all password validators in settings.
    """
    validators = get_default_password_validators()
    help_texts = [validator.get_help_text() for validator in validators]
    return '\n\n'.join(help_texts)