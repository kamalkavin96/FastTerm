import os
import secrets
import shutil
import logging

log = logging.getLogger("terminal")

TERMINAL_USERNAME = os.getenv("TERMINAL_USERNAME", "")
TERMINAL_PASSWORD = os.getenv("TERMINAL_PASSWORD", "")
BASE_PATH = os.getenv("BASE_PATH", "")
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "")

if SQLITE_DB_PATH != "":
    os.makedirs(SQLITE_DB_PATH, exist_ok=True)
    SQLITE_DB_PATH = SQLITE_DB_PATH + "/"

WEBTERM_DB = os.getenv("WEBTERM_DB", os.path.join(SQLITE_DB_PATH + "webterm.db"),)

WEBTERM_MAX_UPLOAD_MB = int(os.getenv("WEBTERM_MAX_UPLOAD_MB", "100"))

FILES_ROOT = os.path.abspath(os.getenv("WEBTERM_FILES_ROOT", os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "webterm-files"),))

os.makedirs(FILES_ROOT, exist_ok=True)

SERVER_SECRET = os.getenv("WEBTERM_SECRET") or secrets.token_hex(32)
if not os.getenv("WEBTERM_SECRET"):
    log.warning("WEBTERM_SECRET not set -- sessions invalidated on restart.")

TMUX_BIN = shutil.which("tmux")
SSH_BIN = shutil.which("ssh")
