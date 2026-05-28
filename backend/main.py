from __future__ import annotations
import asyncio
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocket
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

load_dotenv()  # load .env before any os.getenv() calls in auth.py / metasploit.py

from .core.rate_limit import limiter  # noqa: E402 — must come after load_dotenv()

from .database.session import init_db
from .core.dependency_checker import run_dependency_check
from .core.job_queue import start_worker, stop_worker
from .api.routes import (
    jobs_router, results_router, tools_router, settings_router, reports_router, azure_router,
)
from .api.websocket import job_log_ws, tool_install_ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("autopwn")

FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
_scanner_proc = None


async def _start_go_scanner():
    global _scanner_proc
    scanner_bin = Path(__file__).parent.parent / "scanner" / "bin" / "scanner"
    if not scanner_bin.exists():
        logger.warning(f"Go scanner binary not found at {scanner_bin}. Skipping.")
        return
    try:
        _scanner_proc = await asyncio.create_subprocess_exec(
            str(scanner_bin), "--port", "8001",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Poll health endpoint
        import httpx
        for _ in range(20):
            await asyncio.sleep(0.5)
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get("http://127.0.0.1:8001/health", timeout=1)
                    if r.status_code == 200:
                        logger.info("Go scanner service ready on :8001")
                        return
            except Exception:
                pass
        logger.warning("Go scanner did not respond to health check in time")
    except Exception as e:
        logger.warning(f"Could not start Go scanner: {e}")


async def _stop_go_scanner():
    global _scanner_proc
    if _scanner_proc and _scanner_proc.returncode is None:
        _scanner_proc.terminate()
        try:
            await asyncio.wait_for(_scanner_proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            _scanner_proc.kill()
        logger.info("Go scanner stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AutoPwn starting up...")
    await init_db()
    logger.info("Database initialized")

    await _start_go_scanner()

    logger.info("Running dependency check...")
    await run_dependency_check()

    start_worker()
    logger.info("Job queue worker started")

    yield

    logger.info("AutoPwn shutting down...")
    stop_worker()
    await _stop_go_scanner()


app = FastAPI(
    title="AutoPwn",
    description="Automated HTB penetration testing framework",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routes
app.include_router(jobs_router)
app.include_router(results_router)
app.include_router(tools_router)
app.include_router(settings_router)
app.include_router(reports_router)
app.include_router(azure_router)


# WebSocket endpoints
@app.websocket("/ws/jobs/{job_id}/logs")
async def ws_job_logs(websocket: WebSocket, job_id: str):
    await job_log_ws(websocket, job_id)


@app.websocket("/ws/tools/{tool_name}/install")
async def ws_tool_install(websocket: WebSocket, tool_name: str):
    await tool_install_ws(websocket, tool_name)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# Serve built React frontend (production)
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


if __name__ == "__main__":
    import os
    # Default to loopback only. Set AUTOPWN_HOST=0.0.0.0 if you really need LAN access
    # (e.g. running on a Kali VM accessed from the host).
    host = os.getenv("AUTOPWN_HOST", "127.0.0.1")
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=8000,
        reload=False,
        log_level="info",
    )
