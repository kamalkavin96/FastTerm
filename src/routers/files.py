import os
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse

from core.security import get_current_user
from models.file import RenameFileRequest
from services.file_service import (
    list_files,
    get_download_path,
    get_preview,
    upload_file,
    make_dir,
    rename_file,
    delete_file,
)
from services.token_service import verify_token

router = APIRouter(prefix="/api/files")


def _resolve_auth(token: str, authorization: str):
    auth = verify_token(token) if token else None
    if not auth and authorization.startswith("Bearer "):
        auth = verify_token(authorization[7:])
    if not auth:
        raise HTTPException(401, "Invalid or expired session")
    return auth


@router.get("")
async def api_list_files(path: str = "", user=Depends(get_current_user)):
    return list_files(user["username"], path)


@router.get("/download")
async def api_download_file(
    path: str,
    token: str = "",
    authorization: str = Header(default=""),
):
    auth = _resolve_auth(token, authorization)
    target = get_download_path(auth["username"], path)
    return FileResponse(target, filename=os.path.basename(target))


@router.get("/preview")
async def api_preview_file(
    path: str,
    token: str = "",
    authorization: str = Header(default=""),
):
    auth = _resolve_auth(token, authorization)
    return get_preview(auth["username"], path)


@router.post("/upload")
async def api_upload_file(
    path: str = Form(""),
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    return await upload_file(user["username"], path, file)


@router.post("/mkdir")
async def api_mkdir(path: str = Form(...), user=Depends(get_current_user)):
    return make_dir(user["username"], path)


@router.post("/rename")
async def api_rename_file(req: RenameFileRequest, user=Depends(get_current_user)):
    return rename_file(user["username"], req.old_path, req.new_name)


@router.delete("")
async def api_delete_file(path: str, user=Depends(get_current_user)):
    return delete_file(user["username"], path)