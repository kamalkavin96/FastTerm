import sqlite3
import logging
import time
from core.config import WEBTERM_DB, TERMINAL_USERNAME, TERMINAL_PASSWORD
from utils.password import hash_password

log = logging.getLogger("terminal")


def get_db() -> sqlite3.Connection:
    print(WEBTERM_DB)
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
    conn.execute("""CREATE TABLE IF NOT EXISTS revoked_tokens(
        token TEXT PRIMARY KEY NOT NULL,
        revoked_at REAL NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        event TEXT NOT NULL,
        ip TEXT NOT NULL,
        detail TEXT,
        created_at REAL NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS session_stats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        sid TEXT NOT NULL,
        target TEXT NOT NULL,
        ip TEXT NOT NULL,
        started_at REAL NOT NULL,
        ended_at REAL,
        bytes_in INTEGER NOT NULL DEFAULT 0,
        bytes_out INTEGER NOT NULL DEFAULT 0
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
        log.info("Bootstrapped initial admin user '%s'.", TERMINAL_USERNAME)
    elif n == 0:
        log.warning("No users exist and TERMINAL_USERNAME/PASSWORD are unset.")
    conn.close()
