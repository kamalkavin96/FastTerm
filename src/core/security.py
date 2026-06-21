from fastapi import Depends, Header, HTTPException
from services.token_service import verify_token


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