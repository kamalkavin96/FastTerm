import os
import re
from fastapi import HTTPException
from core.config import FILES_ROOT


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