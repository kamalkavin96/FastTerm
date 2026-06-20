from fastapi.responses import HTMLResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn
import logging
import subprocess
import shutil
import select
import termios
import fcntl
import struct
import signal
import json
import asyncio
import time
import hmac
import re
import os
from dotenv import load_dotenv
load_dotenv()


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("terminal")

TERMINAL_USERNAME = os.getenv("TERMINAL_USERNAME", "")
TERMINAL_PASSWORD = os.getenv("TERMINAL_PASSWORD", "")

MAX_AUTH_FIELD_LEN = 256      # guard against unbounded paste/garbage input
AUTH_TIMEOUT_SECONDS = 60     # drop idle/never-finished logins
PTY_READ_CHUNK = 65536
PTY_IDLE_POLL_SECONDS = 5.0

# --- Tier 1: auth rate limiting -------------------------------------------
MAX_AUTH_FAILURES = 5
LOCKOUT_SECONDS = 5 * 60
_auth_failures: dict[str, list[float]] = {}   # ip -> [failure timestamps]
_lockout_until: dict[str, float] = {}         # ip -> unlock timestamp

# --- Tier 1: tmux-backed session persistence -------------------------------
# A session id (sid), generated client-side and kept in localStorage, names
# a tmux session. Reattaching with the same sid resumes the same shell even
# after the browser tab closes or the network drops, since the tmux *server*
# keeps running independently of the websocket-facing client process.
SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TMUX_BIN = shutil.which("tmux")

app = FastAPI()


@app.get("/terminal")
async def home():
    with open("templates/terminal.html", "rb") as f:
        html = f.read().decode("utf-8", errors="replace")
    return HTMLResponse(html)


def is_resize(raw: str):
    """Return (rows, cols) if raw is a resize control message, else None."""
    if not raw.startswith("{"):
        return None
    try:
        msg = json.loads(raw)
        if msg.get("type") == "resize":
            return int(msg["rows"]), int(msg["cols"])
    except Exception:
        pass
    return None


def set_winsize(fd: int, rows: int, cols: int):
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except OSError:
        pass


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def client_ip(websocket: WebSocket) -> str:
    try:
        fwd = websocket.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    except Exception:
        pass
    try:
        return websocket.client.host
    except Exception:
        return "unknown"


def is_locked_out(ip: str) -> float:
    """Return seconds remaining in lockout, or 0 if not locked out."""
    until = _lockout_until.get(ip)
    if until is None:
        return 0.0
    remaining = until - time.time()
    if remaining <= 0:
        _lockout_until.pop(ip, None)
        _auth_failures.pop(ip, None)
        return 0.0
    return remaining


def record_auth_failure(ip: str):
    now = time.time()
    fails = _auth_failures.setdefault(ip, [])
    fails.append(now)
    # keep only failures within the lockout window
    cutoff = now - LOCKOUT_SECONDS
    fails[:] = [t for t in fails if t > cutoff]
    if len(fails) >= MAX_AUTH_FAILURES:
        _lockout_until[ip] = now + LOCKOUT_SECONDS
        log.warning(
            "IP %s locked out after %d failed auth attempts", ip, len(fails))


def record_auth_success(ip: str):
    _auth_failures.pop(ip, None)
    _lockout_until.pop(ip, None)


async def recv_capture_resize(websocket: WebSocket, dims: dict) -> str:
    """Return the next text frame that isn't a resize control message.
    Resize messages seen along the way are recorded into `dims` rather
    than being silently dropped, so the size the browser reports during
    the auth prompts can be used as the PTY's initial size (avoiding a
    cramped default 24x80 render for full-screen TUI apps)."""
    while True:
        data = await websocket.receive_text()
        dim = is_resize(data)
        if dim is not None:
            dims["rows"], dims["cols"] = dim
            continue
        return data


async def authenticate(websocket: WebSocket, dims: dict) -> bool:
    """Prompt for username/password over the socket, char-by-char, with
    backspace support. Returns True iff credentials are valid."""

    ip = client_ip(websocket)
    remaining = is_locked_out(ip)
    if remaining > 0:
        await websocket.send_text(
            f"\r\n\x1b[31mToo many failed attempts. Try again in {int(remaining)}s.\x1b[0m\r\n"
        )
        return False

    async def read_field(prompt: str, mask: bool) -> str:
        value = ""
        await websocket.send_text(prompt)
        while True:
            data = await asyncio.wait_for(
                recv_capture_resize(websocket, dims), timeout=AUTH_TIMEOUT_SECONDS
            )
            # Pasted input can arrive as a multi-character chunk; walk it
            # char-by-char so backspaces and a trailing newline behave the
            # same as individually typed keystrokes.
            for ch in data:
                if ch in ("\r", "\n"):
                    return value
                if ch == "\x7f":
                    if value:
                        value = value[:-1]
                        if not mask:
                            await websocket.send_text("\b \b")
                    continue
                if len(value) >= MAX_AUTH_FIELD_LEN:
                    continue
                value += ch
                await websocket.send_text("*" if mask else ch)

    try:
        username = await read_field("Username: ", mask=False)
        password = await read_field("\r\nPassword: ", mask=True)
    except asyncio.TimeoutError:
        try:
            await websocket.send_text("\r\n\x1b[31mLogin timed out.\x1b[0m\r\n")
        except Exception:
            pass
        return False
    except WebSocketDisconnect:
        raise

    if not TERMINAL_USERNAME or not TERMINAL_PASSWORD:
        log.error("TERMINAL_USERNAME / TERMINAL_PASSWORD not configured")
        await websocket.send_text("\r\n\x1b[31mServer auth is not configured.\x1b[0m\r\n")
        return False

    ok = constant_time_eq(username, TERMINAL_USERNAME) and constant_time_eq(
        password, TERMINAL_PASSWORD
    )
    if not ok:
        record_auth_failure(ip)
        left = MAX_AUTH_FAILURES - len(_auth_failures.get(ip, []))
        hint = f" ({left} attempt(s) left)" if 0 < left < MAX_AUTH_FAILURES else ""
        await websocket.send_text(f"\r\n\x1b[31mAuthentication failed.{hint}\x1b[0m\r\n")
        return False

    record_auth_success(ip)
    await websocket.send_text("\r\n\x1b[32mAuthentication successful.\x1b[0m\r\n")
    return True


def spawn_shell(rows: int = 24, cols: int = 80, sid: str | None = None):
    """Open a PTY and spawn an interactive shell attached to it.

    If tmux is available and a valid sid was supplied, the shell is a tmux
    client that attaches to (or creates) a tmux session named after the sid.
    Because the tmux *server* process is independent of this client, the
    session survives the browser tab closing or the websocket dropping --
    reconnecting with the same sid resumes exactly where it left off.
    Returns (master_fd, proc)."""
    master_fd, slave_fd = os.openpty()

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env.setdefault("LANG", "en_US.UTF-8")

    if TMUX_BIN and sid and SID_RE.match(sid):
        tmux_session = f"web-{sid}"
        cmd = [TMUX_BIN, "new-session", "-A", "-s", tmux_session]
    else:
        cmd = ["/bin/bash", "--login"]

    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        env=env,
        preexec_fn=os.setsid,
    )
    os.close(slave_fd)
    set_winsize(master_fd, rows, cols)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    return master_fd, proc


def _wait_readable(fd: int, proc: subprocess.Popen):
    """Block (in a worker thread) until fd has data or the process exits."""
    while True:
        r, _, _ = select.select([fd], [], [], PTY_IDLE_POLL_SECONDS)
        if r or proc.poll() is not None:
            return


async def pump_pty_to_socket(master_fd: int, proc: subprocess.Popen, websocket: WebSocket):
    """Forward PTY output to the websocket until the process exits or the
    socket goes away."""
    loop = asyncio.get_event_loop()
    try:
        while True:
            await loop.run_in_executor(None, _wait_readable, master_fd, proc)
            try:
                data = os.read(master_fd, PTY_READ_CHUNK)
            except OSError:
                break
            if not data:
                break
            try:
                await websocket.send_text(data.decode("utf-8", errors="replace"))
            except Exception:
                break
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception("PTY reader error")


def terminate_process(proc: subprocess.Popen, kill_session: bool):
    """Best-effort, non-blocking-ish shutdown of the shell's process group.

    When the shell is a tmux client (kill_session=False), we only want to
    end the *client* attached to this websocket -- not the tmux server --
    so the session can be reattached later. SIGHUP on the client process
    group detaches tmux cleanly without killing the underlying session.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return

    sigs = (signal.SIGHUP, signal.SIGTERM,
            signal.SIGKILL) if kill_session else (signal.SIGHUP,)
    for sig in sigs:
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue

    if kill_session:
        try:
            os.killpg(pgid, signal.SIGKILL)
            proc.wait(timeout=2)
        except Exception:
            pass


@app.websocket("/terminal/ws")
async def terminal(websocket: WebSocket):
    await websocket.accept()

    sid = websocket.query_params.get("sid", "")
    if not SID_RE.match(sid):
        sid = ""
    using_tmux = bool(TMUX_BIN and sid)

    dims = {"rows": 24, "cols": 80}
    try:
        authed = await authenticate(websocket, dims)
    except WebSocketDisconnect:
        log.info("Client disconnected during auth")
        return

    if not authed:
        try:
            await websocket.close()
        except Exception:
            pass
        return

    master_fd, proc = spawn_shell(
        dims["rows"], dims["cols"], sid=sid if using_tmux else None)
    reader_task = asyncio.create_task(
        pump_pty_to_socket(master_fd, proc, websocket))

    try:
        while True:
            raw = await websocket.receive_text()

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
                os.write(master_fd, raw.encode("utf-8", errors="replace"))
            except BlockingIOError:
                # PTY input buffer momentarily full; drop and continue rather
                # than blocking the event loop.
                pass
            except OSError:
                break

    except WebSocketDisconnect:
        log.info("Client disconnected")
    except Exception:
        log.exception("WebSocket error")
    finally:
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        # If this was a tmux-backed session, only detach (don't kill it) so
        # the user can resume later with the same sid.
        await asyncio.get_event_loop().run_in_executor(
            None, terminate_process, proc, not using_tmux
        )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
