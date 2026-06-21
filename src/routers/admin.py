from fastapi import APIRouter, Depends, HTTPException

from core.auth import METRICS, get_lockout_state
from core.security import require_admin
from models.user import CreateUserRequest
from repositories.token_repository import count_revoked_tokens
from repositories.user_repository import count_users, count_totp_users
from services.audit_service import get_audit_log
from services.terminal_service import list_sessions, kill_session
from services.user_service import admin_create_user, admin_delete_user, admin_list_users
import time

router = APIRouter(prefix="/api/admin")


@router.get("/sessions")
async def admin_sessions(_=Depends(require_admin)):
    return list_sessions()


@router.delete("/sessions/{conn_id}")
async def admin_kill_session(conn_id: str, _=Depends(require_admin)):
    if not kill_session(conn_id):
        raise HTTPException(404, "Session not found")
    return {"ok": True}


@router.get("/users")
async def admin_users(_=Depends(require_admin)):
    return admin_list_users()


@router.post("/users")
async def admin_create(req: CreateUserRequest, _=Depends(require_admin)):
    admin_create_user(req.username, req.password, req.is_admin)
    return {"ok": True}


@router.delete("/users/{username}")
async def admin_delete(username: str, admin=Depends(require_admin)):
    admin_delete_user(username, admin["username"])
    return {"ok": True}


@router.get("/audit")
async def admin_audit(_=Depends(require_admin), limit: int = 100):
    return get_audit_log(limit)


@router.get("/metrics")
async def admin_metrics(_=Depends(require_admin)):
    lockout_state = get_lockout_state()
    locked_count = len([ip for ip, until in lockout_state.items() if until > time.time()])
    return {
        **METRICS,
        "active_sessions": len(list_sessions()),
        "locked_ips": locked_count,
        "revoked_tokens": count_revoked_tokens(),
        "totp_enabled_users": count_totp_users(),
        "total_users": count_users(),
    }