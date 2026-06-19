from fastapi.responses import HTMLResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn
import logging
import subprocess
import select
import termios
import fcntl
import struct
import signal
import json
import asyncio
import hmac
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
        await websocket.send_text("\r\n\x1b[31mAuthentication failed.\x1b[0m\r\n")
        return False

    await websocket.send_text("\r\n\x1b[32mAuthentication successful.\x1b[0m\r\n")
    return True


def spawn_shell(rows: int = 24, cols: int = 80):
    """Open a PTY and spawn an interactive login shell attached to it.
    Returns (master_fd, proc)."""
    master_fd, slave_fd = os.openpty()

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env.setdefault("LANG", "en_US.UTF-8")

    proc = subprocess.Popen(
        ["/bin/bash", "--login"],
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


def terminate_process(proc: subprocess.Popen):
    """Best-effort, non-blocking-ish shutdown of the shell's process group."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    for sig in (signal.SIGHUP, signal.SIGTERM):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue
    try:
        os.killpg(pgid, signal.SIGKILL)
        proc.wait(timeout=2)
    except Exception:
        pass


@app.websocket("/terminal/ws")
async def terminal(websocket: WebSocket):
    await websocket.accept()

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

    master_fd, proc = spawn_shell(dims["rows"], dims["cols"])
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
        await asyncio.get_event_loop().run_in_executor(None, terminate_process, proc)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
