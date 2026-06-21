from fastapi import APIRouter, WebSocket
from websocket.terminal import terminal_ws_handler

router = APIRouter()


@router.websocket("/ws")
async def ws_terminal(websocket: WebSocket):
    await terminal_ws_handler(websocket)