import secrets
import string


def generate_random_chars(length: int = 6):
    # defaults to 6 digits if you don't pass a length
    alphabet = string.ascii_uppercase + string.digits  # 36 chars
    return "".join(secrets.choice(alphabet) for _ in range(length))
