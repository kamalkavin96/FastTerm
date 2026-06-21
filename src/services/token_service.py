import base64
import hashlib
import hmac
import secrets
import time

from core.config import SERVER_SECRET
from core.constants import TOKEN_TTL_SECONDS
from repositories.token_repository import is_token_revoked


def issue_token(username: str, is_admin: bool) -> str:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"{username}|{int(is_admin)}|{exp}"
    sig = hmac.new(
        SERVER_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return base64.urlsafe_b64encode((payload + "|" + sig).encode()).decode()


def verify_token(token: str):
    if not token or is_token_revoked(token):
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, is_admin, exp, sig = raw.split("|")
        expected = hmac.new(
            SERVER_SECRET.encode(),
            f"{username}|{is_admin}|{exp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < time.time():
            return None
        return {"username": username, "is_admin": bool(int(is_admin))}
    except Exception:
        return None