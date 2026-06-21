from utils.totp import totp_new_secret, verify_totp, generate_totp_qr
from repositories.user_repository import set_totp_secret


def enable_totp(username: str) -> dict:
    secret = totp_new_secret()
    set_totp_secret(username, secret)
    qr_data, uri = generate_totp_qr(username, secret)
    return {"secret": secret, "otpauth_uri": uri, "qr_code": qr_data}


def disable_totp(username: str):
    set_totp_secret(username, None)


def check_totp(secret: str, code: str) -> bool:
    return verify_totp(secret, code)