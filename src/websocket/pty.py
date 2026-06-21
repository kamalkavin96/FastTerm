import asyncio
import fcntl
import json
import logging
import os
import select
import signal
import struct
import subprocess
import termios

from fastapi import WebSocket
from core.auth import METRICS
from core.config import TMUX_BIN, SSH_BIN
from core.constants import PTY_READ_CHUNK, PTY_IDLE_POLL_SECONDS, PTY_BATCH_MS, SID_RE

log = logging.getLogger("terminal")


def set_winsize(fd: int, rows: int, cols: int):
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except OSError:
        pass


def spawn_shell(
    rows: int = 24,
    cols: int = 80,
    sid: str | None = None,
    ssh_target: dict | None = None,
):
    master_fd, slave_fd = os.openpty()
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env.setdefault("LANG", "en_US.UTF-8")

    valid_sid = bool(sid and SID_RE.match(sid))

    if ssh_target and SSH_BIN:
        ssh_cmd = [
            SSH_BIN,
            "-p", str(int(ssh_target["port"])),
            f"{ssh_target['ssh_username']}@{ssh_target['host']}",
        ]
        if TMUX_BIN and valid_sid:
            cmd = [TMUX_BIN, "new-session", "-A", "-s", f"web-ssh-{sid}"] + ssh_cmd
        else:
            cmd = ssh_cmd
    elif TMUX_BIN and valid_sid:
        cmd = [TMUX_BIN, "new-session", "-A", "-s", f"web-{sid}"]
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
    while True:
        r, _, _ = select.select([fd], [], [], PTY_IDLE_POLL_SECONDS)
        if r or proc.poll() is not None:
            return


async def pump_pty_to_socket(
    master_fd: int, proc: subprocess.Popen, websocket: WebSocket
):
    loop = asyncio.get_event_loop()
    buf = bytearray()
    last_flush = loop.time()

    async def flush():
        nonlocal buf, last_flush
        if buf:
            try:
                await websocket.send_text(buf.decode("utf-8", errors="replace"))
            except Exception:
                pass
            buf = bytearray()
        last_flush = loop.time()

    try:
        while True:
            await loop.run_in_executor(None, _wait_readable, master_fd, proc)
            try:
                data = os.read(master_fd, PTY_READ_CHUNK)
            except OSError:
                break
            if not data:
                break
            METRICS["bytes_out_total"] += len(data)
            buf.extend(data)

            more_pending, _, _ = select.select([master_fd], [], [], 0)
            now = loop.time()
            if not more_pending or now - last_flush >= PTY_BATCH_MS or len(buf) > 32768:
                await flush()
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception("PTY reader error")
    finally:
        await flush()


def terminate_process(proc: subprocess.Popen, kill_session: bool):
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    sigs = (
        (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL)
        if kill_session
        else (signal.SIGHUP,)
    )
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