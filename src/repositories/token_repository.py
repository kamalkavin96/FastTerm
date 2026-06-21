import time
from core.database import get_db


def is_token_revoked(token: str) -> bool:
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE token=?", (token,)
        ).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False


def revoke_token(token: str):
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens(token,revoked_at) VALUES (?,?)",
        (token, time.time()),
    )
    conn.commit()
    conn.close()


def count_revoked_tokens() -> int:
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) c FROM revoked_tokens").fetchone()["c"]
    conn.close()
    return n