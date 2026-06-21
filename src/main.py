import logging
import uvicorn
from fastapi import FastAPI
from core.config import BASE_PATH
from core.database import init_db
from core.middleware import SecurityHeadersMiddleware
from fastapi.staticfiles import StaticFiles
from routers import home, auth, profile, admin, files, metrics, terminal
from pathlib import Path

from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
# app.mount("/static", StaticFiles(directory="src/static"), name="static")

app.mount(
    "/static",
    StaticFiles(directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), "src\static")),
    name="static"
)

prefix = BASE_PATH
print("BASE_PATH:", BASE_PATH)

app.include_router(home.router, prefix=prefix)
app.include_router(auth.router, prefix=prefix)
app.include_router(profile.router, prefix=prefix)
app.include_router(admin.router, prefix=prefix)
app.include_router(files.router, prefix=prefix)
app.include_router(metrics.router, prefix=prefix)
app.include_router(terminal.router, prefix=prefix)

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
