import re

def is_valid_phone_number(phone):
    # Remove spaces, dashes, and parentheses
    phone = re.sub(r"[()\s-]", "", phone)
    pattern = re.compile(r"^\+?\d{10,15}$")

    if not pattern.match(phone):
        return False

    if phone.startswith("+"):
        # International number
        return 11 <= len(phone) <= 15
    else:
        # Local number
        return 9<= len(phone) <= 11

# todo: add unit tests for the followings & more case
# print(is_valid_phone_number("+123456789012"))  # True (Valid international)
# print(is_valid_phone_number("1234567890"))     # True (Valid local)
# print(is_valid_phone_number("12345"))          # False (Too short)
# print(is_valid_phone_number("+1-234-567-890a")) # False (Contains letters)
