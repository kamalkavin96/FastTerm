import hashlib
import hmac
import secrets


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
    ).hex()
    return h, salt


def verify_password(password: str, pw_hash: str, pw_salt: str) -> bool:
    h, _ = hash_password(password, pw_salt)
    return hmac.compare_digest(h, pw_hash)