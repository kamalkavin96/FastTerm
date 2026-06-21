from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())


from routers import home, auth, profile, admin, files, metrics, terminal
from core.middleware import SecurityHeadersMiddleware
from core.database import init_db
from core.config import BASE_PATH
from fastapi import FastAPI
import uvicorn
import logging



logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)

prefix = BASE_PATH


print(BASE_PATH)

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
