import os
from fastapi import HTTPException, UploadFile
from core.config import WEBTERM_MAX_UPLOAD_MB
from utils.file_utils import user_root, safe_join


def list_files(username: str, path: str = "") -> dict:
    root = user_root(username)
    target = safe_join(root, path)
    if not os.path.isdir(target):
        raise HTTPException(404, "Not a directory")
    entries = []
    for name in sorted(os.listdir(target)):
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
            entries.append({
                "name": name,
                "is_dir": os.path.isdir(full),
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
        except OSError:
            continue
    return {"path": path, "entries": entries}


def get_download_path(username: str, path: str) -> str:
    root = user_root(username)
    target = safe_join(root, path)
    if not os.path.isfile(target):
        raise HTTPException(404, "File not found")
    return target


def get_preview(username: str, path: str) -> dict:
    root = user_root(username)
    target = safe_join(root, path)
    if not os.path.isfile(target):
        raise HTTPException(404, "File not found")
    size = os.path.getsize(target)
    if size > 512 * 1024:
        raise HTTPException(400, "File too large to preview (max 512 KB)")
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(8192)
        return {"content": content, "truncated": size > 8192}
    except Exception:
        raise HTTPException(400, "Cannot preview this file type")


async def upload_file(username: str, path: str, file: UploadFile) -> dict:
    root = user_root(username)
    target_dir = safe_join(root, path)
    os.makedirs(target_dir, exist_ok=True)
    dest = safe_join(target_dir, os.path.basename(file.filename))
    size = 0
    max_bytes = WEBTERM_MAX_UPLOAD_MB * 1024 * 1024
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                out.close()
                os.remove(dest)
                raise HTTPException(400, f"File exceeds {WEBTERM_MAX_UPLOAD_MB} MB limit")
            out.write(chunk)
    return {"ok": True, "size": size}


def make_dir(username: str, path: str) -> dict:
    root = user_root(username)
    target = safe_join(root, path)
    os.makedirs(target, exist_ok=True)
    return {"ok": True}


def rename_file(username: str, old_path: str, new_name: str) -> dict:
    root = user_root(username)
    src = safe_join(root, old_path)
    parent = os.path.dirname(src)
    new_name_base = os.path.basename(new_name)
    if not new_name_base or "/" in new_name_base or "\\" in new_name_base:
        raise HTTPException(400, "Invalid name")
    dst = safe_join(root, os.path.join(os.path.relpath(parent, root), new_name_base))
    if not os.path.exists(src):
        raise HTTPException(404, "Not found")
    if os.path.exists(dst):
        raise HTTPException(400, "A file with that name already exists")
    os.rename(src, dst)
    return {"ok": True}


def delete_file(username: str, path: str) -> dict:
    root = user_root(username)
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