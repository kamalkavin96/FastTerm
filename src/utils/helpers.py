import json
from fastapi import Request, WebSocket


def client_ip_req(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def client_ip_ws(websocket: WebSocket) -> str:
    fwd = websocket.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    try:
        return websocket.client.host
    except Exception:
        return "unknown"


def is_resize(raw: str):
    if not raw.startswith("{"):
        return None
    try:
        msg = json.loads(raw)
        if msg.get("type") == "resize":
            return int(msg["rows"]), int(msg["cols"])
    except Exception:
        pass
    return None


def is_ctrl_type(raw: str):
    if not raw.startswith("{"):
        return None
    try:
        return json.loads(raw).get("type")
    except Exception:
        return None