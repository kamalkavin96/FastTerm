import logging
import time
from core.constants import MAX_AUTH_FAILURES, LOCKOUT_SECONDS

log = logging.getLogger("terminal")

_auth_failures: dict[str, list[float]] = {}
_lockout_until: dict[str, float] = {}

METRICS = {
    "sessions_opened_total": 0,
    "auth_failures_total": 0,
    "bytes_in_total": 0,
    "bytes_out_total": 0,
}


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
        log.warning(
            "IP %s locked out after %d failed auth attempts", ip, len(fails)
        )


def record_auth_success(ip: str):
    _auth_failures.pop(ip, None)
    _lockout_until.pop(ip, None)


def get_lockout_state():
    """Return current lockout dict for metrics."""
    return _lockout_until