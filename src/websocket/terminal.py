import asyncio
import json
import logging
import os
import signal

from fastapi import WebSocket, WebSocketDisconnect

from core.auth import METRICS
from core.config import TMUX_BIN
from core.constants import SID_RE, HEARTBEAT_INTERVAL
from repositories.user_repository import get_user_row
from repositories.profile_repository import get_profile
from services.audit_service import audit
from services.terminal_service import register_session, unregister_session, get_session
from services.token_service import verify_token
from utils.helpers import client_ip_ws, is_resize, is_ctrl_type
from websocket.pty import spawn_shell, pump_pty_to_socket, set_winsize, terminate_process

log = logging.getLogger("terminal")


async def terminal_ws_handler(websocket: WebSocket):
    await websocket.accept()

    token = websocket.query_params.get("token", "")
    auth = verify_token(token)
    if not auth:
        try:
            await websocket.close(code=4401)
        except Exception:
            pass
        return

    user_row = get_user_row(auth["username"])
    if not user_row:
        try:
            await websocket.close(code=4401)
        except Exception:
            pass
        return

    sid = websocket.query_params.get("sid", "")
    if not SID_RE.match(sid):
        sid = ""

    profile_id_raw = websocket.query_params.get("profile_id")
    ssh_target = None
    profile_name = None

    if profile_id_raw:
        try:
            pid = int(profile_id_raw)
            prow = get_profile(pid, user_row["id"])
            if prow:
                ssh_target = {
                    "host": prow["host"],
                    "port": prow["port"],
                    "ssh_username": prow["ssh_username"],
                }
                profile_name = prow["name"]
        except (ValueError, TypeError):
            pass

    using_tmux = bool(TMUX_BIN and sid)
    master_fd, proc = spawn_shell(24, 80, sid=sid or None, ssh_target=ssh_target)

    ip = client_ip_ws(websocket)
    conn_id = register_session(user_row["username"], ip, sid, profile_name)
    audit(user_row["username"], "session_open", ip, profile_name or "local")

    reader_task = asyncio.create_task(pump_pty_to_socket(master_fd, proc, websocket))
    last_hb = asyncio.get_event_loop().time()

    try:
        while True:
            sess = get_session(conn_id)
            if sess and sess.get("_kill"):
                await websocket.send_text(
                    "\r\n\x1b[31mSession terminated by administrator.\x1b[0m\r\n"
                )
                break

            now = asyncio.get_event_loop().time()
            if now - last_hb > HEARTBEAT_INTERVAL:
                try:
                    await websocket.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
                last_hb = now

            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=25.0)
            except asyncio.TimeoutError:
                continue

            ctrl = is_ctrl_type(raw)
            if ctrl in ("ping", "pong"):
                last_hb = asyncio.get_event_loop().time()
                continue

            dim = is_resize(raw)
            if dim is not None:
                rows, cols = dim
                set_winsize(master_fd, rows, cols)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGWINCH)
                except ProcessLookupError:
                    pass
                continue

            try:
                encoded = raw.encode("utf-8", errors="replace")
                os.write(master_fd, encoded)
                METRICS["bytes_in_total"] += len(encoded)
            except BlockingIOError:
                pass
            except OSError:
                break

    except WebSocketDisconnect:
        log.info("Client disconnected")
    except Exception:
        log.exception("WebSocket error")
    finally:
        unregister_session(conn_id)
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        audit(user_row["username"], "session_close", ip, profile_name or "local")
        await asyncio.get_event_loop().run_in_executor(
            None, terminate_process, proc, not using_tmux
        )