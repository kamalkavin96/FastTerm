from core.auth import is_locked_out, record_auth_failure, record_auth_success
from repositories.user_repository import get_user_row
from utils.password import verify_password
from utils.totp import verify_totp


def check_login(username: str, password: str, totp: str | None, ip: str):
    remaining = is_locked_out(ip)
    if remaining > 0:
        return False, f"Too many failed attempts. Try again in {int(remaining)}s.", None

    row = get_user_row(username)
    if not row or not verify_password(password, row["pw_hash"], row["pw_salt"]):
        record_auth_failure(ip)
        return False, "Authentication failed.", None

    if row["totp_secret"]:
        if not totp:
            return False, "TOTP_REQUIRED", None
        if not verify_totp(row["totp_secret"], totp):
            record_auth_failure(ip)
            return False, "Invalid authenticator code.", None

    record_auth_success(ip)
    return True, "ok", row