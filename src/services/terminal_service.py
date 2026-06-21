import uuid
from core.auth import METRICS

ACTIVE_SESSIONS: dict[str, dict] = {}


def register_session(username: str, ip: str, sid: str, profile_name: str | None) -> str:
    import time
    conn_id = str(uuid.uuid4())
    ACTIVE_SESSIONS[conn_id] = {
        "id": conn_id,
        "username": username,
        "ip": ip,
        "sid": sid,
        "target": profile_name or "local",
        "connected_at": time.time(),
        "_kill": False,
    }
    METRICS["sessions_opened_total"] += 1
    return conn_id


def unregister_session(conn_id: str):
    ACTIVE_SESSIONS.pop(conn_id, None)


def get_session(conn_id: str) -> dict | None:
    return ACTIVE_SESSIONS.get(conn_id)


def list_sessions() -> list:
    return list(ACTIVE_SESSIONS.values())


def kill_session(conn_id: str) -> bool:
    sess = ACTIVE_SESSIONS.get(conn_id)
    if not sess:
        return False
    sess["_kill"] = True
    return True