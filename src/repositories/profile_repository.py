import time
from core.database import get_db


def list_profiles(user_id: int):
    conn = get_db()
    rows = conn.execute(
        "SELECT id,name,host,port,ssh_username FROM profiles WHERE user_id=? ORDER BY name",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_profile(profile_id: int, user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM profiles WHERE id=? AND user_id=?", (profile_id, user_id)
    ).fetchone()
    conn.close()
    return row


def create_profile(
    user_id: int, name: str, host: str, port: int, ssh_username: str
) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO profiles(user_id,name,host,port,ssh_username,created_at) VALUES (?,?,?,?,?,?)",
        (user_id, name.strip()[:128], host.strip()[:255], int(port), ssh_username.strip()[:128], time.time()),
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return pid


def delete_profile(profile_id: int, user_id: int):
    conn = get_db()
    conn.execute(
        "DELETE FROM profiles WHERE id=? AND user_id=?", (profile_id, user_id)
    )
    conn.commit()
    conn.close()