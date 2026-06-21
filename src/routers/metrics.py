from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from core.auth import METRICS
from core.security import get_current_user
from services.terminal_service import list_sessions

router = APIRouter()


@router.get("/metrics")
async def metrics(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "Admin only")
    lines = [
        f"webterm_sessions_opened_total {METRICS['sessions_opened_total']}",
        f"webterm_sessions_active {len(list_sessions())}",
        f"webterm_auth_failures_total {METRICS['auth_failures_total']}",
        f"webterm_bytes_in_total {METRICS['bytes_in_total']}",
        f"webterm_bytes_out_total {METRICS['bytes_out_total']}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")