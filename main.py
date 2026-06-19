from dotenv import load_dotenv
load_dotenv()

import os
import asyncio
import json
import signal
import struct
import fcntl
import termios
import select
import subprocess

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

TERMINAL_USERNAME = os.getenv("TERMINAL_USERNAME")
TERMINAL_PASSWORD = os.getenv("TERMINAL_PASSWORD")

app = FastAPI()


@app.get("/terminal")
async def home():
    with open("templates/terminal.html", "rb") as f:
        html = f.read().decode("utf-8", errors="replace")
    return HTMLResponse(html)


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


async def recv_non_resize(websocket: WebSocket):
    """Return next non-resize text frame. Raises WebSocketDisconnect naturally."""
    while True:
        data = await websocket.receive_text()
        if is_resize(data) is None:
            return data


def set_winsize(fd: int, rows: int, cols: int):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


@app.websocket("/terminal/ws")
async def terminal(websocket: WebSocket):
    await websocket.accept()

    # Auth
    username = ""
    password = ""

    try:
        await websocket.send_text("Username: ")
        while True:
            data = await recv_non_resize(websocket)
            if data in ("\r", "\n", "\r\n"):
                break
            if data == "\x7f":
                if username:
                    username = username[:-1]
                    await websocket.send_text("\b \b")
                continue
            username += data
            await websocket.send_text(data)

        await websocket.send_text("\r\nPassword: ")
        while True:
            data = await recv_non_resize(websocket)
            if data in ("\r", "\n", "\r\n"):
                break
            if data == "\x7f":
                if password:
                    password = password[:-1]
                continue
            password += data
            await websocket.send_text("*")

    except WebSocketDisconnect:
        print("Client disconnected during auth")
        return

    # Validate credentials
    if username != TERMINAL_USERNAME or password != TERMINAL_PASSWORD:
        try:
            await websocket.send_text("\r\n\x1b[31mAuthentication failed.\x1b[0m\r\n")
            await websocket.close()
        except Exception:
            pass
        return

    try:
        await websocket.send_text("\r\n\x1b[32mAuthentication successful.\x1b[0m\r\n")
    except WebSocketDisconnect:
        print("Client disconnected after auth success")
        return

    # Open PTY and spawn bash
    master_fd, slave_fd = os.openpty()

    env = os.environ.copy()
    env["TERM"]      = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["LANG"]      = "en_US.UTF-8"

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
    set_winsize(master_fd, 24, 80)

    fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    loop = asyncio.get_event_loop()

    def _wait_readable(fd):
        while True:
            r, _, _ = select.select([fd], [], [], 5.0)
            if r:
                return
            if proc.poll() is not None:
                return

    async def read_pty():
        try:
            while True:
                await loop.run_in_executor(None, _wait_readable, master_fd)
                try:
                    data = os.read(master_fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                await websocket.send_text(data.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"PTY reader error: {e}")

    reader_task = asyncio.create_task(read_pty())

    try:
        while True:
            raw = await websocket.receive_text()

            
            dim = is_resize(raw)
            print(dim)



            if dim is not None:
                rows, cols = dim
                set_winsize(master_fd, rows, cols)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGWINCH)
                except Exception:
                    pass
                continue

            try:
                os.write(master_fd, raw.encode("utf-8", errors="replace"))
            except OSError:
                break

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        reader_task.cancel()
        try:
            os.close(master_fd)
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)