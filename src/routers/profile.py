from fastapi import APIRouter, Depends, HTTPException

from core.config import SSH_BIN
from core.security import get_current_user
from models.profile import ProfileRequest
from repositories.profile_repository import (
    list_profiles,
    create_profile,
    delete_profile,
)
from repositories.user_repository import get_user_row

router = APIRouter(prefix="/api/profiles")


@router.get("")
async def api_list_profiles(user=Depends(get_current_user)):
    row = get_user_row(user["username"])
    return list_profiles(row["id"])


@router.post("")
async def api_create_profile(p: ProfileRequest, user=Depends(get_current_user)):
    if not SSH_BIN:
        raise HTTPException(400, "ssh binary not found on the server")
    row = get_user_row(user["username"])
    pid = create_profile(row["id"], p.name, p.host, p.port, p.ssh_username)
    return {"id": pid}


@router.delete("/{profile_id}")
async def api_delete_profile(profile_id: int, user=Depends(get_current_user)):
    row = get_user_row(user["username"])
    delete_profile(profile_id, row["id"])
    return {"ok": True}