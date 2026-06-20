from dotenv import load_dotenv
load_dotenv()

import os
import re
import time
import uuid
import base64
import hmac
import struct
import secrets
import sqlite3
import asyncio
import json
import signal
import fcntl
import termios
import select
import shutil
import hashlib
import subprocess
import logging

import uvicorn
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, Header,
    HTTPException, UploadFile, File, Form
)
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("terminal")

# TERMINAL_USERNAME/PASSWORD are used ONLY to bootstrap the first admin
# account in the database on first run. They are never used for runtime
# authentication -- all login happens through the session/token system
# below. Once a real admin account exists, you can unset these.
TERMINAL_USERNAME = os.getenv("TERMINAL_USERNAME", "")
TERMINAL_PASSWORD = os.getenv("TERMINAL_PASSWORD", "")

PTY_READ_CHUNK = 65536
PTY_IDLE_POLL_SECONDS = 5.0

MAX_AUTH_FAILURES = 5
LOCKOUT_SECONDS = 5 * 60
_auth_failures: dict[str, list[float]] = {}
_lockout_until: dict[str, float] = {}

SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
TMUX_BIN = shutil.which("tmux")
SSH_BIN = shutil.which("ssh")

# ===========================================================================
# Storage: SQLite (no external DB service required)
# ===========================================================================
WEBTERM_DB = os.getenv("WEBTERM_DB", os.path.join(os.path.dirname(__file__), "webterm.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(WEBTERM_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        pw_salt TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        totp_secret TEXT,
        created_at REAL NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS profiles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 22,
        ssh_username TEXT NOT NULL,
        created_at REAL NOT NULL
    )""")
    conn.commit()
    n = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if n == 0 and TERMINAL_USERNAME and TERMINAL_PASSWORD:
        h, s = hash_password(TERMINAL_PASSWORD)
        conn.execute(
            "INSERT INTO users(username,pw_hash,pw_salt,is_admin,created_at) VALUES (?,?,?,1,?)",
            (TERMINAL_USERNAME, h, s, time.time()),
        )
        conn.commit()
        log.info("Bootstrapped initial admin user '%s'. You can unset "
                  "TERMINAL_USERNAME/PASSWORD now -- they are not used again.", TERMINAL_USERNAME)
    elif n == 0:
        log.warning("No users exist and TERMINAL_USERNAME/PASSWORD are unset -- "
                    "no one can log in until a user row is created directly in the DB.")
    conn.close()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return h, salt


def verify_password(password: str, pw_hash: str, pw_salt: str) -> bool:
    h, _ = hash_password(password, pw_salt)
    return hmac.compare_digest(h, pw_hash)


def get_user_row(username: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row


# ===========================================================================
# TOTP (RFC 6238) -- pure stdlib
# ===========================================================================
def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def totp_code(secret_b32: str, for_time: float | None = None, digits: int = 6, period: int = 30) -> str:
    pad = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(pad.upper())
    t = int((for_time if for_time is not None else time.time()) // period)
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1, period: int = 30) -> bool:
    if not code or not re.match(r"^\d{6}$", code):
        return False
    now = time.time()
    for i in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret_b32, now + i * period), code):
            return True
    return False


# ===========================================================================
# Signed bearer tokens (session-only auth -- this is THE auth mechanism now,
# for the page, the REST API, and the terminal websocket alike)
# ===========================================================================
SERVER_SECRET = os.getenv("WEBTERM_SECRET") or secrets.token_hex(32)
if not os.getenv("WEBTERM_SECRET"):
    log.warning("WEBTERM_SECRET not set -- using a random per-process secret. "
                "All sessions are invalidated on restart. Set WEBTERM_SECRET "
                "in production so logins survive restarts/redeploys.")
TOKEN_TTL_SECONDS = 12 * 3600

# In-memory revocation list, checked on every token verification so Logout
# takes effect immediately even though tokens are otherwise stateless.
# Production note: for a multi-process/multi-host deployment this should be
# a shared store (Redis, DB table) instead of an in-process set.
REVOKED_TOKENS: set[str] = set()


def issue_token(username: str, is_admin: bool) -> str:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"{username}|{int(is_admin)}|{exp}"
    sig = hmac.new(SERVER_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode((payload + "|" + sig).encode()).decode()


def verify_token(token: str):
    if not token or token in REVOKED_TOKENS:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, is_admin, exp, sig = raw.split("|")
        expected = hmac.new(SERVER_SECRET.encode(), f"{username}|{is_admin}|{exp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < time.time():
            return None
        return {"username": username, "is_admin": bool(int(is_admin))}
    except Exception:
        return None


async def get_current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    info = verify_token(authorization[7:])
    if not info:
        raise HTTPException(401, "Invalid or expired session")
    return info


async def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "Admin privileges required")
    return user


# ===========================================================================
# In-memory active-session registry + metrics
# ===========================================================================
ACTIVE_SESSIONS: dict[str, dict] = {}
METRICS = {
    "sessions_opened_total": 0,
    "auth_failures_total": 0,
    "bytes_in_total": 0,
    "bytes_out_total": 0,
}

app = FastAPI()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline security headers for production deployments."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.get("/terminal")
async def home():
    with open("templates/terminal.html", "rb") as f:
        html = f.read().decode("utf-8", errors="replace")
    return HTMLResponse(html)


@app.get("/admin")
async def admin_page():
    with open("templates/admin.html", "rb") as f:
        html = f.read().decode("utf-8", errors="replace")
    return HTMLResponse(html)


@app.get("/metrics")
async def metrics():
    lines = [
        "# HELP webterm_sessions_opened_total Total PTY sessions opened since start",
        "# TYPE webterm_sessions_opened_total counter",
        f"webterm_sessions_opened_total {METRICS['sessions_opened_total']}",
        "# HELP webterm_sessions_active Currently active PTY sessions",
        "# TYPE webterm_sessions_active gauge",
        f"webterm_sessions_active {len(ACTIVE_SESSIONS)}",
        "# HELP webterm_auth_failures_total Total failed login attempts",
        "# TYPE webterm_auth_failures_total counter",
        f"webterm_auth_failures_total {METRICS['auth_failures_total']}",
        "# HELP webterm_bytes_in_total Total bytes written into PTYs (keystrokes)",
        "# TYPE webterm_bytes_in_total counter",
        f"webterm_bytes_in_total {METRICS['bytes_in_total']}",
        "# HELP webterm_bytes_out_total Total bytes read from PTYs (output)",
        "# TYPE webterm_bytes_out_total counter",
        f"webterm_bytes_out_total {METRICS['bytes_out_total']}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")


# ===========================================================================
# REST API
# ===========================================================================
class LoginRequest(BaseModel):
    username: str
    password: str
    totp: str | None = None


class ProfileRequest(BaseModel):
    name: str
    host: str
    port: int = 22
    ssh_username: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False


def client_ip_req(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_locked_out(ip: str) -> float:
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
    METRICS["auth_failures_total"] += 1
    fails = _auth_failures.setdefault(ip, [])
    fails.append(now)
    cutoff = now - LOCKOUT_SECONDS
    fails[:] = [t for t in fails if t > cutoff]
    if len(fails) >= MAX_AUTH_FAILURES:
        _lockout_until[ip] = now + LOCKOUT_SECONDS
        log.warning("IP %s locked out after %d failed auth attempts", ip, len(fails))


def record_auth_success(ip: str):
    _auth_failures.pop(ip, None)
    _lockout_until.pop(ip, None)


def check_login(username: str, password: str, totp: str | None, ip: str):
    remaining = is_locked_out(ip)
    if remaining > 0:
        return False, f"Too many failed attempts. Try again in {int(remaining)}s.", None

    row = get_user_row(username)
    if not row or not verify_password(password, row["pw_hash"], row["pw_salt"]):
        record_auth_failure(ip)
        return False, "Authentication failed.", None

    if row["totp_secret"]:
        if not totp:
            return False, "TOTP_REQUIRED", None
        if not verify_totp(row["totp_secret"], totp):
            record_auth_failure(ip)
            return False, "Invalid authenticator code.", None

    record_auth_success(ip)
    return True, "ok", row


@app.post("/api/login")
async def api_login(req: LoginRequest, request: Request):
    ip = client_ip_req(request)
    ok, reason, row = check_login(req.username, req.password, req.totp, ip)
    if not ok:
        raise HTTPException(401, reason)
    token = issue_token(row["username"], bool(row["is_admin"]))
    return {"token": token, "is_admin": bool(row["is_admin"]), "username": row["username"]}


@app.post("/api/logout")
async def api_logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        REVOKED_TOKENS.add(authorization[7:])
    return {"ok": True}


@app.get("/api/me")
async def api_me(user=Depends(get_current_user)):
    return user


@app.post("/api/me/totp/enable")
async def totp_enable(user=Depends(get_current_user)):
    secret = totp_new_secret()
    conn = get_db()
    conn.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, user["username"]))
    conn.commit()
    conn.close()
    uri = f"otpauth://totp/WebTerminal:{user['username']}?secret={secret}&issuer=WebTerminal"
    return {"secret": secret, "otpauth_uri": uri}


@app.post("/api/me/totp/disable")
async def totp_disable(user=Depends(get_current_user)):
    conn = get_db()
    conn.execute("UPDATE users SET totp_secret=NULL WHERE username=?", (user["username"],))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/profiles")
async def list_profiles(user=Depends(get_current_user)):
    row = get_user_row(user["username"])
    conn = get_db()
    rows = conn.execute(
        "SELECT id,name,host,port,ssh_username FROM profiles WHERE user_id=? ORDER BY name", (row["id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/profiles")
async def create_profile(p: ProfileRequest, user=Depends(get_current_user)):
    if not SSH_BIN:
        raise HTTPException(400, "ssh binary not found on the server")
    row = get_user_row(user["username"])
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO profiles(user_id,name,host,port,ssh_username,created_at) VALUES (?,?,?,?,?,?)",
        (row["id"], p.name.strip()[:128], p.host.strip()[:255], int(p.port), p.ssh_username.strip()[:128], time.time()),
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return {"id": pid}


@app.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: int, user=Depends(get_current_user)):
    row = get_user_row(user["username"])
    conn = get_db()
    conn.execute("DELETE FROM profiles WHERE id=? AND user_id=?", (profile_id, row["id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/admin/sessions")
async def admin_sessions(_=Depends(require_admin)):
    return list(ACTIVE_SESSIONS.values())


@app.get("/api/admin/users")
async def admin_users(_=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute(
        "SELECT username,is_admin,totp_secret IS NOT NULL as has_totp,created_at FROM users ORDER BY username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/admin/users")
async def admin_create_user(req: CreateUserRequest, _=Depends(require_admin)):
    if not USERNAME_RE.match(req.username):
        raise HTTPException(400, "Invalid username")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    h, s = hash_password(req.password)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users(username,pw_hash,pw_salt,is_admin,created_at) VALUES (?,?,?,?,?)",
            (req.username, h, s, int(req.is_admin), time.time()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")
    finally:
        conn.close()
    return {"ok": True}


@app.delete("/api/admin/users/{username}")
async def admin_delete_user(username: str, admin=Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(400, "Cannot delete your own account while logged in as it")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"ok": True}


# --- File manager: sandboxed per-user directory on the server's local disk.
# Browse/upload/download/mkdir/delete with path-traversal protection. This is
# NOT a remote SFTP client against your SSH targets (that needs paramiko/
# asyncssh, a dependency intentionally left out -- see project notes).
FILES_ROOT = os.path.abspath(os.getenv("WEBTERM_FILES_ROOT", os.path.join(os.path.dirname(__file__), "webterm-files")))
os.makedirs(FILES_ROOT, exist_ok=True)


def user_root(username: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", username)
    path = os.path.join(FILES_ROOT, safe)
    os.makedirs(path, exist_ok=True)
    return path


def safe_join(root: str, rel: str) -> str:
    rel = (rel or "").lstrip("/")
    target = os.path.abspath(os.path.join(root, rel))
    if target != root and not target.startswith(root + os.sep):
        raise HTTPException(400, "Invalid path")
    return target


@app.get("/api/files")
async def list_files(path: str = "", user=Depends(get_current_user)):
    root = user_root(user["username"])
    target = safe_join(root, path)
    if not os.path.isdir(target):
        raise HTTPException(404, "Not a directory")
    entries = []
    for name in sorted(os.listdir(target)):
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
            entries.append({"name": name, "is_dir": os.path.isdir(full), "size": st.st_size, "mtime": st.st_mtime})
        except OSError:
            continue
    return {"path": path, "entries": entries}


@app.get("/api/files/download")
async def download_file(path: str, token: str = "", authorization: str = Header(default="")):
    # Browsers can't set Authorization headers on plain navigations/<a> clicks,
    # so downloads also accept a short-lived token via query string.
    auth = verify_token(token) if token else None
    if not auth and authorization.startswith("Bearer "):
        auth = verify_token(authorization[7:])
    if not auth:
        raise HTTPException(401, "Invalid or expired session")
    root = user_root(auth["username"])
    target = safe_join(root, path)
    if not os.path.isfile(target):
        raise HTTPException(404, "File not found")
    return FileResponse(target, filename=os.path.basename(target))


@app.post("/api/files/upload")
async def upload_file(path: str = Form(""), file: UploadFile = File(...), user=Depends(get_current_user)):
    root = user_root(user["username"])
    target_dir = safe_join(root, path)
    os.makedirs(target_dir, exist_ok=True)
    dest = safe_join(target_dir, os.path.basename(file.filename))
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    return {"ok": True}


@app.post("/api/files/mkdir")
async def mkdir(path: str = Form(...), user=Depends(get_current_user)):
    root = user_root(user["username"])
    target = safe_join(root, path)
    os.makedirs(target, exist_ok=True)
    return {"ok": True}


@app.delete("/api/files")
async def delete_file(path: str, user=Depends(get_current_user)):
    root = user_root(user["username"])
    target = safe_join(root, path)
    if target == root:
        raise HTTPException(400, "Cannot delete root")
    if os.path.isdir(target):
        try:
            os.rmdir(target)
        except OSError:
            raise HTTPException(400, "Directory not empty")
    elif os.path.isfile(target):
        os.remove(target)
    else:
        raise HTTPException(404, "Not found")
    return {"ok": True}


# ===========================================================================
# Terminal/PTY plumbing
# ===========================================================================
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


def set_winsize(fd: int, rows: int, cols: int):
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except OSError:
        pass


def client_ip(websocket: WebSocket) -> str:
    fwd = websocket.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    try:
        return websocket.client.host
    except Exception:
        return "unknown"


def spawn_shell(rows: int = 24, cols: int = 80, sid: str | None = None, ssh_target: dict | None = None):
    """Open a PTY and spawn a shell attached to it.

    - Local mode: tmux-wrapped bash, when tmux + sid present, so the session
      survives a dropped websocket/tab close.
    - SSH mode: tmux-wrapped `ssh user@host -p port`. The remote system's own
      login prompt (password or key passphrase) happens interactively inside
      this PTY exactly like a normal terminal SSH session -- this app never
      sees or stores that credential.
    Returns (master_fd, proc).
    """
    master_fd, slave_fd = os.openpty()

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env.setdefault("LANG", "en_US.UTF-8")

    valid_sid = bool(sid and SID_RE.match(sid))

    if ssh_target and SSH_BIN:
        ssh_cmd = [SSH_BIN, "-p", str(int(ssh_target["port"])), f"{ssh_target['ssh_username']}@{ssh_target['host']}"]
        if TMUX_BIN and valid_sid:
            cmd = [TMUX_BIN, "new-session", "-A", "-s", f"web-ssh-{sid}"] + ssh_cmd
        else:
            cmd = ssh_cmd
    elif TMUX_BIN and valid_sid:
        cmd = [TMUX_BIN, "new-session", "-A", "-s", f"web-{sid}"]
    else:
        cmd = ["/bin/bash", "--login"]

    proc = subprocess.Popen(
        cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        close_fds=True, env=env, preexec_fn=os.setsid,
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


async def pump_pty_to_socket(master_fd: int, proc: subprocess.Popen, websocket: WebSocket):
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
            METRICS["bytes_out_total"] += len(data)
            try:
                await websocket.send_text(data.decode("utf-8", errors="replace"))
            except Exception:
                break
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception("PTY reader error")


def terminate_process(proc: subprocess.Popen, kill_session: bool):
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    sigs = (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL) if kill_session else (signal.SIGHUP,)
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

    token = websocket.query_params.get("token", "")
    auth = verify_token(token)
    if not auth:
        # No in-band login prompt anymore -- the session token (obtained via
        # POST /api/login before the page ever opens a socket) is the only
        # way in. Reject immediately; nothing is spawned.
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
            conn = get_db()
            prow = conn.execute("SELECT * FROM profiles WHERE id=? AND user_id=?", (pid, user_row["id"])).fetchone()
            conn.close()
            if prow:
                ssh_target = {"host": prow["host"], "port": prow["port"], "ssh_username": prow["ssh_username"]}
                profile_name = prow["name"]
        except (ValueError, TypeError):
            pass

    using_tmux = bool(TMUX_BIN and sid)
    master_fd, proc = spawn_shell(24, 80, sid=sid or None, ssh_target=ssh_target)

    conn_id = str(uuid.uuid4())
    ACTIVE_SESSIONS[conn_id] = {
        "username": user_row["username"], "ip": client_ip(websocket), "sid": sid,
        "target": profile_name or "local", "connected_at": time.time(),
    }
    METRICS["sessions_opened_total"] += 1

    reader_task = asyncio.create_task(pump_pty_to_socket(master_fd, proc, websocket))

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
        ACTIVE_SESSIONS.pop(conn_id, None)
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        await asyncio.get_event_loop().run_in_executor(None, terminate_process, proc, not using_tmux)


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)