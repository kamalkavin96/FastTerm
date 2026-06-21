from fastapi import APIRouter, Depends, Header, HTTPException, Request

from core.security import get_current_user
from models.auth import LoginRequest, ChangePasswordRequest
from repositories.token_repository import revoke_token
from repositories.user_repository import get_user_row
from services.auth_service import check_login
from services.audit_service import audit
from services.token_service import issue_token, verify_token
from services.totp_service import enable_totp, disable_totp
from services.user_service import change_password
from utils.helpers import client_ip_req

router = APIRouter(prefix="/api")


@router.post("/login")
async def api_login(req: LoginRequest, request: Request):
    ip = client_ip_req(request)
    ok, reason, row = check_login(req.username, req.password, req.totp, ip)
    if not ok:
        raise HTTPException(401, reason)
    token = issue_token(row["username"], bool(row["is_admin"]))
    audit(row["username"], "login", ip)
    return {"token": token, "is_admin": bool(row["is_admin"]), "username": row["username"]}


@router.post("/logout")
async def api_logout(request: Request, authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        t = authorization[7:]
        info = verify_token(t)
        revoke_token(t)
        if info:
            audit(info["username"], "logout", client_ip_req(request))
    return {"ok": True}


@router.get("/me")
async def api_me(user=Depends(get_current_user)):
    row = get_user_row(user["username"])
    return {
        "username": user["username"],
        "is_admin": user["is_admin"],
        "has_totp": bool(row["totp_secret"]) if row else False,
    }


@router.post("/me/password")
async def api_change_password(
    req: ChangePasswordRequest,
    user=Depends(get_current_user),
):
    change_password(user["username"], req.current_password, req.new_password)
    return {"ok": True}


@router.post("/me/totp/enable")
async def api_totp_enable(user=Depends(get_current_user)):
    return enable_totp(user["username"])


@router.post("/me/totp/disable")
async def api_totp_disable(user=Depends(get_current_user)):
    disable_totp(user["username"])
    return {"ok": True}