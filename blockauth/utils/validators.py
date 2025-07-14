import re

def is_valid_phone_number(phone):
    # Remove spaces, dashes, and parentheses
    phone = re.sub(r"[()\s-]", "", phone)
    pattern = re.compile(r"^\+?\d{10,15}$")

    if not pattern.match(phone):
        return False

    # only international phone numbers are allowed
    return phone.startswith("+") and 11 <= len(phone) <= 15


