import time
from core.database import get_db
from utils.password import hash_password


def get_user_row(username: str):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return row


def create_user(username: str, password: str, is_admin: bool = False):
    h, s = hash_password(password)
    conn = get_db()
    conn.execute(
        "INSERT INTO users(username,pw_hash,pw_salt,is_admin,created_at) VALUES (?,?,?,?,?)",
        (username, h, s, int(is_admin), time.time()),
    )
    conn.commit()
    conn.close()


def delete_user(username: str):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()


def list_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT username,is_admin,totp_secret IS NOT NULL as has_totp,created_at FROM users ORDER BY username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_password(username: str, pw_hash: str, pw_salt: str):
    conn = get_db()
    conn.execute(
        "UPDATE users SET pw_hash=?,pw_salt=? WHERE username=?",
        (pw_hash, pw_salt, username),
    )
    conn.commit()
    conn.close()


def set_totp_secret(username: str, secret: str | None):
    conn = get_db()
    conn.execute(
        "UPDATE users SET totp_secret=? WHERE username=?", (secret, username)
    )
    conn.commit()
    conn.close()


def count_users() -> int:
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    return n


def count_totp_users() -> int:
    conn = get_db()
    n = conn.execute(
        "SELECT COUNT(*) c FROM users WHERE totp_secret IS NOT NULL"
    ).fetchone()["c"]
    conn.close()
    return n