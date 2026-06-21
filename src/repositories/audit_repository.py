import time
import logging
from core.database import get_db

log = logging.getLogger("terminal")


def insert_audit(username: str, event: str, ip: str, detail: str = ""):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log(username,event,ip,detail,created_at) VALUES (?,?,?,?,?)",
            (username, event, ip, detail, time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        log.exception("Audit log insert failed")


def fetch_audit(limit: int = 100):
    conn = get_db()
    rows = conn.execute(
        "SELECT username,event,ip,detail,created_at FROM audit_log ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]