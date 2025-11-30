from quizapp.models import UserMailValidator
from quizapp.utils import generate_random_chars
from django.utils.timezone import now
from datetime import timedelta
import secrets, hashlib


def hash_code(code: str, salt: bytes) -> str:
    return hashlib.sha256(salt + code.encode()).hexdigest()


def generate_code(email: str, expires_in_minutes=10, length=6) -> str:
    code = generate_random_chars(length)
    salt = secrets.token_bytes(16)
    otp_hash = hash_code(code, salt)
    otp_salt = salt.hex()
    otp_expires = now() + timedelta(minutes=expires_in_minutes)
    # If it has been generated before and it needs renewal or maybe the person didn't get it
    if UserMailValidator.objects.filter(email=email).exists():
        validator_instance = UserMailValidator.objects.get(email=email)
        validator_instance.otp_hash = otp_hash
        validator_instance.otp_salt = otp_salt
        validator_instance.otp_expires = otp_expires
        validator_instance.save()
    else:
        UserMailValidator.objects.create(
            email=email, otp_hash=otp_hash, otp_salt=otp_salt
        )
    return code


def verify_code(email: str, code: str) -> bool:
    if not UserMailValidator.objects.filter(email=email).exists():
        return False
    record = UserMailValidator.objects.get(email=email)
    if now() > record.otp_expires:
        return False
    computed = hash_code(code, bytes.fromhex(record.otp_salt))
    return secrets.compare_digest(record.otp_hash, computed)
