import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from logger import log_event

DB_PATH = os.environ.get("SIEM_DB_PATH", "/app/logs/siem.db")
DETECTOR_IP = os.environ.get("DETECTOR_IP", "10.5.0.30")
blocked_ips = set()
network_paused = False

# Paths that must keep working while traffic is paused (detector + control plane).
ALLOW_WHEN_PAUSED = frozenset(
    {
        "/sync-blocklist",
        "/unblock",
        "/control/pause",
        "/control/resume",
        "/control/status",
        "/control/reset-cache",
    }
)


def db_conn() -> sqlite3.Connection:
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database table blocks."""
    with db_conn() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, action TEXT, reason TEXT)"
        )


def refresh_block_cache() -> None:
    """Refresh the block cache from the database when the server starts."""
    blocked_ips.clear()
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT b.source_ip, b.action FROM blocks b JOIN (SELECT source_ip, MAX(id) AS max_id FROM blocks GROUP BY source_ip) latest ON b.id = latest.max_id"
        ).fetchall()
    for row in rows:
        if row["action"] == "block":
            blocked_ips.add(row["source_ip"])


def write_block_event(source_ip: str, action: str, reason: str) -> None:
    """Write a block event to the database."""
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO blocks (timestamp, source_ip, action, reason) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), source_ip, action, reason),
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Run on startup to initialize the database and refresh the block cache."""
    init_db()
    refresh_block_cache()
    yield


app = FastAPI(title="Secure Server", lifespan=lifespan)


def require_detector_caller(request: Request) -> None:
    if request.client and request.client.host != DETECTOR_IP:
        raise HTTPException(status_code=403, detail="Unauthorized Call")


@app.middleware("http")
async def filter_servers_by_ip(request: Request, next_step):
    """
    Every incoming HTTP request is checked.
    If client's IP is on blocklist, the request is rejected before it reaches the app.
    """
    client_ip = request.client.host
    if client_ip in blocked_ips:
        raise HTTPException(status_code=403, detail="Access Denied (blocked): IP not allowed")
    response = await next_step(request)
    return response


@app.middleware("http")
async def pause_traffic(request: Request, next_step):
    """Registered after the blocklist so pause is evaluated first on incoming requests."""
    if network_paused and request.url.path not in ALLOW_WHEN_PAUSED:
        return JSONResponse(status_code=503, content={"detail": "Network traffic paused"})
    response = await next_step(request)
    return response

@app.post("/process")
async def process_data(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint that processes user data.
    Background task and log_event function (.logger.py) are called to log the event to the database and detector.
    """
    client_ip = request.client.host
    actor_type = request.headers.get("X-Actor-Type", "unknown")
    data = await request.json()
    payload = json.dumps(data, ensure_ascii=False)
    # Add as backgroundtask, so client does not have to wait
    background_tasks.add_task(
        log_event, 
        client_ip, 
        request.method, 
        "/process", 
        200, 
        payload,
        request.headers.get("User-Agent", "unknown"),
        actor_type,
    )
    return {"status": "success", "message": "Data processed"}

@app.post("/sync-blocklist")
async def update_blocklist(request: Request):
    """
    Endpoint that is called by detector to update blocklist.
    Only allows the IP of the detector.
    """
    require_detector_caller(request)
    
    data = await request.json()
    new_block_ip = data.get("block_ip")
    reason = data.get("reason", "detector_request")
    if new_block_ip:
        if new_block_ip in blocked_ips:
            return {"status": "ok", "duplicate": True, "current_blocklist": list(blocked_ips)}
        blocked_ips.add(new_block_ip)
        write_block_event(new_block_ip, "block", reason)
        return {"status": "updated", "current_blocklist": list(blocked_ips)}
    raise HTTPException(status_code=400, detail="Missing block_ip")


@app.post("/unblock")
async def unblock_ip(request: Request):
    """Endpoint that is called by detector (on behalf of dashboard) to unblock an IP."""
    require_detector_caller(request)
    data = await request.json()
    ip = data.get("ip")
    reason = data.get("reason", "manual_unblock")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing ip")
    blocked_ips.discard(ip)
    write_block_event(ip, "unblock", reason)
    return {"status": "updated", "current_blocklist": list(blocked_ips)}


@app.post("/control/pause")
async def control_pause(request: Request) -> dict:
    require_detector_caller(request)
    global network_paused
    network_paused = True
    return {"status": "paused"}


@app.post("/control/resume")
async def control_resume(request: Request) -> dict:
    require_detector_caller(request)
    global network_paused
    network_paused = False
    return {"status": "resumed"}


@app.get("/control/status")
async def control_status(request: Request) -> dict:
    require_detector_caller(request)
    return {"paused": network_paused}


@app.post("/control/reset-cache")
async def control_reset_cache(request: Request) -> dict:
    """Reload blocklist from DB after shared DB was cleared (detector reset)."""
    require_detector_caller(request)
    blocked_ips.clear()
    refresh_block_cache()
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
