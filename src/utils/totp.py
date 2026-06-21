import base64
import hashlib
import hmac
import io
import re
import secrets
import struct
import time

import qrcode


def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def totp_code(
    secret_b32: str,
    for_time: float | None = None,
    digits: int = 6,
    period: int = 30,
) -> str:
    pad = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(pad.upper())
    t = int((for_time if for_time is not None else time.time()) // period)
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 0x0F
    code = (struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def verify_totp(
    secret_b32: str, code: str, window: int = 1, period: int = 30
) -> bool:
    if not code or not re.match(r"^\d{6}$", code):
        return False
    now = time.time()
    for i in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret_b32, now + i * period), code):
            return True
    return False


def generate_totp_qr(username: str, secret: str) -> tuple[str, str]:
    """Return (base64-PNG data URI, otpauth URI)."""
    uri = (
        f"otpauth://totp/WebTerminal:{username}"
        f"?secret={secret}&issuer=WebTerminal"
    )
    qr = qrcode.QRCode(version=1, box_size=6, border=3)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}", uri