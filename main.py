import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict
import base64

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LUFFY-Gateway")

app = FastAPI(title="LUFFY PANEL", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
daily_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

SESSION_COOKIE = "luffy_session"
SESSION_TTL = 60 * 60 * 24 * 7
DATA_FILE = "luffy_data.json"

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

def load_data():
    global LINKS, stats, hourly_traffic, daily_traffic
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                LINKS = data.get("links", {})
                saved_stats = data.get("stats", {})
                stats["total_bytes"] = saved_stats.get("total_bytes", 0)
                stats["total_requests"] = saved_stats.get("total_requests", 0)
                hourly_traffic = defaultdict(int, data.get("hourly_traffic", {}))
                daily_traffic = defaultdict(int, data.get("daily_traffic", {}))
                logger.info("LUFFY data loaded.")
        except Exception as e:
            logger.error(f"Error loading data: {e}")

async def save_data_loop():
    while True:
        await asyncio.sleep(60)
        async with LINKS_LOCK:
            data_to_save = {
                "links": LINKS,
                "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]},
                "hourly_traffic": dict(hourly_traffic),
                "daily_traffic": dict(daily_traffic),
            }
        try:
            await asyncio.to_thread(write_json, data_to_save)
        except Exception as e:
            logger.error(f"Error saving data: {e}")

def write_json(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    load_data()
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"LUFFY PANEL started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())
    asyncio.create_task(save_data_loop())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()
    data_to_save = {
        "links": LINKS,
        "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]},
        "hourly_traffic": dict(hourly_traffic),
        "daily_traffic": dict(daily_traffic),
    }
    write_json(data_to_save)

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "LUFFY") -> str:
    domain = get_domain()
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{domain}:443?{query}#{quote(remark)}"

def generate_subscription_content(uid: str, link_data: dict) -> str:
    """Generate base64-encoded subscription content for a single link"""
    vless_link = generate_vless_link(uid, remark=f"LUFFY-{link_data['label']}")
    content = vless_link + "\n"
    return base64.b64encode(content.encode()).decode()

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True, "note": "", "expires_at": None}

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)

@app.get("/")
async def root():
    return {"service": "LUFFY PANEL", "version": "4.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription endpoint ──
@app.get("/sub/{uid}")
async def subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(status_code=404, detail="Not found")
    if not link.get("active", True):
        raise HTTPException(status_code=403, detail="Link disabled")
    
    # Check expiry
    if link.get("expires_at"):
        try:
            exp = datetime.fromisoformat(link["expires_at"])
            if datetime.now() > exp:
                raise HTTPException(status_code=403, detail="Link expired")
        except (ValueError, TypeError):
            pass

    content = generate_subscription_content(uid, link)
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="luffy-{uid[:8]}.txt"',
            "Profile-Update-Interval": "12",
            "Subscription-UserInfo": f"upload=0; download={link.get('used_bytes',0)}; total={link.get('limit_bytes',0)}; expire=0",
        }
    )

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    active_links = sum(1 for l in LINKS.values() if l.get("active"))
    total_used = sum(l.get("used_bytes", 0) for l in LINKS.values())
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_bytes": stats["total_bytes"],
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "active_links": active_links,
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_used_mb": round(psutil.virtual_memory().used / (1024 * 1024), 1),
        "memory_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 1),
        "hourly_traffic": dict(hourly_traffic),
        "daily_traffic": dict(daily_traffic),
        "total_used_bytes": total_used,
        "connections": [
            {"id": cid, "uuid": info.get("uuid", ""), "bytes": info.get("bytes", 0), "connected_at": info.get("connected_at", "")}
            for cid, info in connections.items()
        ]
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    note = str(body.get("note") or "")[:200]
    expires_at = body.get("expires_at") or None
    uid = generate_uuid(label + secrets.token_hex(4))
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "note": note,
            "expires_at": expires_at,
        }
    domain = get_domain()
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "active": True,
        "note": note,
        "expires_at": expires_at,
        "created_at": LINKS[uid]["created_at"],
        "vless_link": generate_vless_link(uid, remark=f"LUFFY-{label}"),
        "sub_link": f"https://{domain}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    domain = get_domain()
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid,
                "label": data["label"],
                "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"],
                "active": data["active"],
                "note": data.get("note", ""),
                "expires_at": data.get("expires_at"),
                "created_at": data["created_at"],
                "vless_link": generate_vless_link(uid, remark=f"LUFFY-{data['label']}"),
                "sub_link": f"https://{domain}/sub/{uid}",
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "note" in body:
            LINKS[uid]["note"] = str(body["note"])[:200]
        if "expires_at" in body:
            LINKS[uid]["expires_at"] = body["expires_at"] or None
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        # Check expiry
        if link.get("expires_at"):
            try:
                exp = datetime.fromisoformat(link["expires_at"])
                if datetime.now() > exp:
                    return False
            except (ValueError, TypeError):
                pass
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hour_key = datetime.now().strftime("%H:00")
            day_key = datetime.now().strftime("%Y-%m-%d")
            hourly_traffic[hour_key] += size
            daily_traffic[day_key] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hour_key = datetime.now().strftime("%H:00")
            day_key = datetime.now().strftime("%Y-%m-%d")
            hourly_traffic[hour_key] += size
            daily_traffic[day_key] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {"uuid": uuid, "connected_at": datetime.now().isoformat(), "bytes": 0}
    connection_sockets[conn_id] = websocket
    writer = None
    try:
        if not await check_quota(uuid, 0):
            await websocket.close(code=1008, reason="quota exceeded or link deleted"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hour_key = datetime.now().strftime("%H:00")
        day_key = datetime.now().strftime("%Y-%m-%d")
        hourly_traffic[hour_key] += size
        daily_traffic[day_key] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[hour_key] += p_size
            daily_traffic[day_key] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        connections.pop(conn_id, None)
        connection_sockets.pop(conn_id, None)


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY — Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700;900&family=Inter:wght@300;400;500;600;700;800&family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

:root {
  --gold: #c9a84c;
  --gold2: #f0d060;
  --gold3: #e8c050;
  --gold-dim: #8a6a20;
  --gold-glow: rgba(201,168,76,0.35);
  --black: #050508;
  --dark: #0a0a0f;
  --dark2: #111118;
  --dark3: #18181f;
  --glass: rgba(201,168,76,0.06);
  --glass2: rgba(255,255,255,0.04);
  --border: rgba(201,168,76,0.2);
  --border2: rgba(201,168,76,0.35);
  --text: rgba(255,255,255,0.95);
  --text2: rgba(220,200,150,0.7);
  --text3: rgba(180,160,100,0.4);
  --error: #ff6b6b;
}

html,body{height:100%;font-family:'Inter','Vazirmatn',sans-serif;background:var(--black);color:var(--text);overflow:hidden}

/* BG */
.bg{position:fixed;inset:0;z-index:0}
.bg-grad{
  position:absolute;inset:0;
  background:
    radial-gradient(ellipse 60% 50% at 20% 20%, rgba(201,168,76,0.12) 0%, transparent 60%),
    radial-gradient(ellipse 50% 60% at 80% 80%, rgba(201,168,76,0.08) 0%, transparent 60%),
    radial-gradient(ellipse 80% 40% at 50% 100%, rgba(201,168,76,0.06) 0%, transparent 50%),
    #050508;
}
.bg-grid{
  position:absolute;inset:0;
  background-image:
    linear-gradient(rgba(201,168,76,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(201,168,76,0.04) 1px, transparent 1px);
  background-size:48px 48px;
}
.bg-vignette{
  position:absolute;inset:0;
  background:radial-gradient(ellipse at center, transparent 30%, rgba(5,5,8,0.8) 100%);
}

/* Floating particles */
.particles{position:absolute;inset:0;overflow:hidden}
.p{
  position:absolute;width:2px;height:2px;border-radius:50%;
  background:var(--gold);opacity:0;
  animation:rise var(--d,8s) ease-in infinite;
  animation-delay:var(--dl,0s);
}
@keyframes rise{
  0%{transform:translateY(100vh) translateX(0);opacity:0}
  10%{opacity:0.6}
  90%{opacity:0.2}
  100%{transform:translateY(-10vh) translateX(var(--dx,20px));opacity:0}
}

/* Wrap */
.wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}

/* Card */
.card{
  width:100%;max-width:420px;
  background:rgba(10,10,15,0.85);
  backdrop-filter:blur(30px) saturate(150%);
  -webkit-backdrop-filter:blur(30px) saturate(150%);
  border:1px solid var(--border);
  border-radius:24px;
  padding:48px 40px 40px;
  box-shadow:
    0 0 0 1px rgba(201,168,76,0.08),
    0 0 60px rgba(201,168,76,0.08),
    0 40px 80px rgba(0,0,0,0.6),
    inset 0 1px 0 rgba(201,168,76,0.15);
  animation:cardIn .7s cubic-bezier(0.34,1.56,0.64,1) forwards;
  position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;top:0;left:10%;right:10%;height:1px;
  background:linear-gradient(90deg,transparent,var(--gold),transparent);
}
@keyframes cardIn{from{opacity:0;transform:translateY(40px) scale(0.94)}to{opacity:1;transform:translateY(0) scale(1)}}

/* Logo */
.logo-wrap{text-align:center;margin-bottom:38px}
.logo-emblem{
  position:relative;display:inline-flex;align-items:center;justify-content:center;
  width:90px;height:90px;margin-bottom:18px;
}
.logo-hex{
  position:absolute;inset:0;
  background:linear-gradient(135deg, rgba(201,168,76,0.15), rgba(201,168,76,0.05));
  border:1px solid var(--border2);
  border-radius:20px;
  transform:rotate(45deg);
  box-shadow:0 0 30px rgba(201,168,76,0.15), inset 0 1px 0 rgba(201,168,76,0.2);
  animation:hexPulse 3s ease-in-out infinite;
}
@keyframes hexPulse{0%,100%{box-shadow:0 0 30px rgba(201,168,76,0.15),inset 0 1px 0 rgba(201,168,76,0.2)}50%{box-shadow:0 0 50px rgba(201,168,76,0.3),inset 0 1px 0 rgba(201,168,76,0.3)}}
.logo-inner{position:relative;z-index:1}
.logo-inner svg{width:42px;height:42px;filter:drop-shadow(0 0 8px rgba(201,168,76,0.6))}
.logo-title{
  font-family:'Cinzel',serif;
  font-size:30px;font-weight:700;
  background:linear-gradient(135deg, #f0d060 0%, #c9a84c 40%, #e8c050 70%, #a07828 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  letter-spacing:0.15em;
  text-shadow:none;
}
.logo-sub{font-size:10px;color:var(--text3);font-weight:600;letter-spacing:0.25em;text-transform:uppercase;margin-top:6px}
.logo-divider{
  width:80px;height:1px;margin:14px auto 0;
  background:linear-gradient(90deg,transparent,var(--gold),transparent);
}

/* Form */
.field{margin-bottom:18px}
.field label{display:block;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px}
.input-wrap{position:relative}
.input-wrap .ico{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--gold-dim);pointer-events:none;transition:color .2s}
.field input{
  width:100%;padding:13px 42px 13px 42px;
  background:rgba(201,168,76,0.05);
  border:1px solid rgba(201,168,76,0.15);
  border-radius:12px;color:var(--text);
  font-size:14px;font-family:inherit;outline:none;
  transition:all .25s;
}
.field input:focus{
  background:rgba(201,168,76,0.08);
  border-color:var(--gold);
  box-shadow:0 0 0 3px rgba(201,168,76,0.12),0 0 20px rgba(201,168,76,0.08);
}
.field input:focus ~ .ico,.input-wrap:focus-within .ico{color:var(--gold)}
.field input::placeholder{color:var(--text3)}
.eye-btn{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--text3);padding:4px;display:flex;align-items:center;transition:color .2s;z-index:1}
.eye-btn:hover{color:var(--gold)}

/* Submit */
.btn-submit{
  width:100%;padding:14px;
  background:linear-gradient(135deg, #c9a84c, #f0d060, #c9a84c);
  background-size:200% 100%;
  border:none;border-radius:12px;
  color:#0a0a0f;font-size:15px;font-weight:700;font-family:inherit;
  cursor:pointer;letter-spacing:0.08em;
  position:relative;overflow:hidden;
  transition:all .3s;
  box-shadow:0 4px 24px rgba(201,168,76,0.3);
  margin-top:8px;
  font-family:'Cinzel',serif;
}
.btn-submit:hover{
  background-position:100% 0;
  transform:translateY(-2px);
  box-shadow:0 8px 36px rgba(201,168,76,0.5);
}
.btn-submit:active{transform:translateY(0)}
.btn-submit.loading{pointer-events:none;opacity:0.7}
.btn-submit .spinner{display:none;width:18px;height:18px;border:2px solid rgba(0,0,0,0.3);border-top-color:#0a0a0f;border-radius:50%;animation:spin .7s linear infinite;margin:0 auto}
.btn-submit.loading .spinner{display:block}
.btn-submit.loading .btn-text{display:none}
@keyframes spin{to{transform:rotate(360deg)}}

/* Error */
.err{background:rgba(255,107,107,0.08);border:1px solid rgba(255,107,107,0.25);border-radius:10px;padding:10px 14px;font-size:13px;color:var(--error);text-align:center;font-weight:500;margin-bottom:16px;display:none;animation:shake .4s}
.err.show{display:block}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}

/* Footer */
.card-footer{margin-top:24px;text-align:center}
.footer-line{height:1px;background:linear-gradient(90deg,transparent,rgba(201,168,76,0.15),transparent);margin-bottom:14px}
.footer-note{font-size:10px;color:var(--text3);letter-spacing:0.1em;text-transform:uppercase}

/* Lang toolbar */
.toolbar{position:fixed;top:16px;right:16px;display:flex;gap:6px;z-index:10}
.tb-btn{height:32px;padding:0 12px;background:rgba(201,168,76,0.07);backdrop-filter:blur(12px);border:1px solid rgba(201,168,76,0.15);border-radius:8px;color:var(--text3);font-size:10px;font-weight:700;font-family:inherit;letter-spacing:0.08em;cursor:pointer;transition:all .2s}
.tb-btn:hover{border-color:var(--gold);color:var(--gold)}
</style>
</head>
<body>
<div class="bg">
  <div class="bg-grad"></div>
  <div class="bg-grid"></div>
  <div class="bg-vignette"></div>
  <div class="particles" id="pts"></div>
</div>

<div class="toolbar">
  <button class="tb-btn" onclick="cycleLang()" id="lang-btn">EN</button>
</div>

<div class="wrap">
  <div class="card">
    <div class="logo-wrap">
      <div class="logo-emblem">
        <div class="logo-hex"></div>
        <div class="logo-inner">
          <svg viewBox="0 0 56 56" fill="none">
            <path d="M14 11h10v26h18v10H14V11z" fill="url(#g1)"/>
            <defs><linearGradient id="g1" x1="14" y1="11" x2="42" y2="47" gradientUnits="userSpaceOnUse"><stop stop-color="#f0d060"/><stop offset="1" stop-color="#c9a84c"/></linearGradient></defs>
          </svg>
        </div>
      </div>
      <div class="logo-title">LUFFY</div>
      <div class="logo-sub">Gateway Panel v4.0</div>
      <div class="logo-divider"></div>
    </div>

    <div class="err" id="err-box"></div>

    <div class="field">
      <label data-en="Master Password" data-fa="رمز عبور">Master Password</label>
      <div class="input-wrap">
        <svg class="ico" xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <input type="password" id="pw" placeholder="Enter master password" autocomplete="current-password">
        <button type="button" class="eye-btn" onclick="toggleEye()">
          <svg id="eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
    </div>

    <button class="btn-submit" id="submit-btn" onclick="doLogin()">
      <span class="btn-text" data-en="ENTER PANEL" data-fa="ورود">ENTER PANEL</span>
      <div class="spinner"></div>
    </button>

    <div class="card-footer">
      <div class="footer-line"></div>
      <div class="footer-note">VLESS · WebSocket · TLS · Encrypted</div>
    </div>
  </div>
</div>

<script>
let lang = localStorage.getItem('ll') || 'en';

// Particles
const pts = document.getElementById('pts');
for(let i=0;i<25;i++){
  const p = document.createElement('div');
  p.className='p';
  p.style.cssText=`left:${Math.random()*100}%;--d:${6+Math.random()*10}s;--dl:${Math.random()*8}s;--dx:${(Math.random()-0.5)*60}px;opacity:0`;
  pts.appendChild(p);
}

function setLang(l){
  lang=l;localStorage.setItem('ll',l);
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);if(v)el.textContent=v;
  });
  document.getElementById('lang-btn').textContent=l.toUpperCase();
}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function toggleEye(){
  const i=document.getElementById('pw');
  const icon=document.getElementById('eye-icon');
  if(i.type==='password'){
    i.type='text';
    icon.innerHTML='<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
  }else{
    i.type='password';
    icon.innerHTML='<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  }
}

document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

async function doLogin(){
  const err=document.getElementById('err-box');
  const btn=document.getElementById('submit-btn');
  err.classList.remove('show');
  btn.classList.add('loading');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Invalid password')}
    location.href='/dashboard';
  }catch(e){
    err.textContent=e.message;err.classList.add('show');btn.classList.remove('loading');
  }
}
setLang(lang);
</script>
</body>
</html>
"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700;900&family=Inter:wght@300;400;500;600;700;800;900&family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

:root{
  --gold:#c9a84c;
  --gold2:#f0d060;
  --gold3:#e8c050;
  --gold4:#dbb84a;
  --gold-dim:#8a6a20;
  --gold-glow:rgba(201,168,76,0.3);
  --black:#050508;
  --dark:#090910;
  --dark2:#0f0f18;
  --dark3:#161620;
  --dark4:#1c1c28;
  --glass:rgba(201,168,76,0.05);
  --glass2:rgba(201,168,76,0.08);
  --glass3:rgba(201,168,76,0.12);
  --border:rgba(201,168,76,0.15);
  --border2:rgba(201,168,76,0.25);
  --border3:rgba(201,168,76,0.4);
  --text:rgba(255,255,255,0.95);
  --text2:rgba(220,200,150,0.7);
  --text3:rgba(180,160,100,0.4);
  --text4:rgba(150,130,80,0.3);
  --red:#ff6b6b;
  --green:#4ade80;
  --yellow:#fbbf24;
  --blue:#60a5fa;
  --sidebar-w:240px;
}

html,body{height:100%;font-family:'Inter','Vazirmatn',sans-serif;background:var(--black);color:var(--text);overflow-x:hidden}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(201,168,76,0.2);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:rgba(201,168,76,0.35)}

/* ── BG ── */
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none}
.bg-grad{position:absolute;inset:0;background:radial-gradient(ellipse 50% 60% at 10% 0%, rgba(201,168,76,0.1) 0%,transparent 55%),radial-gradient(ellipse 40% 50% at 90% 100%, rgba(201,168,76,0.07) 0%,transparent 55%),#050508}
.bg-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(201,168,76,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(201,168,76,0.03) 1px,transparent 1px);background-size:52px 52px}
.bg-vignette{position:absolute;inset:0;background:radial-gradient(ellipse at center,transparent 20%,rgba(5,5,8,0.7) 100%)}

/* ── Sidebar ── */
.sidebar{
  position:fixed;left:0;top:0;bottom:0;width:var(--sidebar-w);
  background:rgba(9,9,16,0.92);
  backdrop-filter:blur(24px) saturate(160%);
  -webkit-backdrop-filter:blur(24px) saturate(160%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:100;
  transition:transform .3s cubic-bezier(0.4,0,0.2,1);
}
.sidebar::before{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--gold),transparent);
}

.sb-brand{padding:22px 18px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.sb-logo{display:flex;align-items:center;gap:12px}
.sb-logo-icon{
  width:40px;height:40px;border-radius:10px;
  background:linear-gradient(135deg,rgba(201,168,76,0.2),rgba(201,168,76,0.08));
  border:1px solid var(--border2);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 20px rgba(201,168,76,0.15);
  flex-shrink:0;
}
.sb-logo-icon svg{width:22px;height:22px;filter:drop-shadow(0 0 4px rgba(201,168,76,0.5))}
.sb-title{font-family:'Cinzel',serif;font-size:18px;font-weight:700;background:linear-gradient(135deg,#f0d060,#c9a84c);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:0.1em}
.sb-ver{font-size:9px;font-weight:600;color:var(--text3);letter-spacing:0.12em;text-transform:uppercase}
.sb-icon-btn{width:28px;height:28px;border-radius:7px;background:var(--glass);border:1px solid var(--border);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.sb-icon-btn:hover{background:var(--glass2);border-color:var(--gold);color:var(--gold)}

.sb-nav{flex:1;padding:12px 10px;overflow-y:auto}
.nav-section{font-size:9px;font-weight:700;color:var(--text4);text-transform:uppercase;letter-spacing:0.15em;padding:14px 10px 6px}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;margin:2px 0;
  border-radius:10px;color:var(--text3);font-size:13px;font-weight:500;
  cursor:pointer;transition:all .2s;border:none;background:none;width:100%;
  text-align:left;position:relative;overflow:hidden;
}
body[dir="rtl"] .nav-item{text-align:right}
.nav-item::before{content:'';position:absolute;inset:0;border-radius:10px;background:linear-gradient(135deg,rgba(201,168,76,0.12),transparent);opacity:0;transition:opacity .2s}
.nav-item:hover{color:var(--text2);background:var(--glass)}
.nav-item.active{color:var(--gold2);background:rgba(201,168,76,0.1);border:1px solid rgba(201,168,76,0.15)}
.nav-item.active::before{opacity:1}
.nav-icon{width:16px;height:16px;flex-shrink:0;opacity:0.6}
.nav-item.active .nav-icon{opacity:1;filter:drop-shadow(0 0 4px rgba(201,168,76,0.5))}
.nav-dot{width:5px;height:5px;border-radius:50%;background:var(--text4);margin-left:auto;transition:all .2s;flex-shrink:0}
body[dir="rtl"] .nav-dot{margin-left:0;margin-right:auto}
.nav-item.active .nav-dot{background:var(--gold);box-shadow:0 0 6px rgba(201,168,76,0.7)}
.nav-badge{margin-left:auto;background:rgba(201,168,76,0.15);color:var(--gold2);font-size:10px;padding:2px 7px;border-radius:5px;font-weight:700;border:1px solid rgba(201,168,76,0.2)}
body[dir="rtl"] .nav-badge{margin-left:0;margin-right:auto}

.sb-footer{padding:10px 10px 16px;border-top:1px solid var(--border)}
.lang-row{display:flex;gap:5px;margin-bottom:8px}
.lang-btn{flex:1;padding:7px;border-radius:8px;background:var(--glass);border:1px solid var(--border);color:var(--text3);font-size:10px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .2s;letter-spacing:0.06em}
.lang-btn.active{background:linear-gradient(135deg,rgba(201,168,76,0.25),rgba(201,168,76,0.1));border-color:var(--gold);color:var(--gold2)}
.lang-btn:hover:not(.active){border-color:var(--gold);color:var(--gold)}
.logout-btn{width:100%;padding:9px;border-radius:9px;background:var(--glass);border:1px solid var(--border);color:var(--text3);font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.logout-btn:hover{background:rgba(255,107,107,0.08);border-color:rgba(255,107,107,0.25);color:var(--red)}

/* online dot */
.online-dot{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 6px rgba(74,222,128,0.7);display:inline-block;animation:pdot 2s ease-in-out infinite}
@keyframes pdot{0%,100%{opacity:1}50%{opacity:0.3}}

/* ── Main ── */
.main{margin-left:var(--sidebar-w);padding:24px 26px 60px;min-height:100vh;position:relative;z-index:1}

/* ── Pages ── */
.page{display:none}.page.active{display:block}

/* ── Page Header ── */
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.ph-left .pt{font-size:22px;font-weight:800;letter-spacing:-0.02em;background:linear-gradient(135deg,#fff 0%,rgba(201,168,76,0.8) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.ph-left .ps{font-size:11px;color:var(--text3);margin-top:3px;font-weight:500;letter-spacing:0.04em}
.ph-right{display:flex;gap:8px;align-items:center}

/* ── Gold Card ── */
.gc{
  background:rgba(9,9,16,0.8);
  backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);
  border:1px solid var(--border);
  border-radius:16px;padding:20px;
  position:relative;overflow:hidden;
  transition:all .25s;
}
.gc::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,rgba(201,168,76,0.3),transparent)}
.gc:hover{border-color:var(--border2);box-shadow:0 0 30px rgba(201,168,76,0.06),0 12px 40px rgba(0,0,0,0.4)}

/* ── Stat Cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.sc{
  background:rgba(9,9,16,0.85);
  backdrop-filter:blur(16px);
  border:1px solid var(--border);
  border-radius:16px;padding:20px;
  position:relative;overflow:hidden;
  transition:all .3s;cursor:default;
}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(201,168,76,0.25),transparent)}
.sc::after{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 80% 20%,rgba(201,168,76,0.04),transparent 60%);pointer-events:none}
.sc:hover{transform:translateY(-3px);border-color:var(--border2);box-shadow:0 0 30px rgba(201,168,76,0.1),0 20px 50px rgba(0,0,0,0.4)}
.sc-icon{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:14px;border:1px solid rgba(201,168,76,0.15)}
.sc-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:7px}
.sc-val{font-size:28px;font-weight:800;letter-spacing:-0.03em;line-height:1;color:var(--gold2)}
.sc-unit{font-size:14px;font-weight:400;color:var(--text3)}
.sc-sub{font-size:11px;color:var(--text3);margin-top:6px;font-weight:500}

/* ── Charts ── */
.chart-wrap{height:200px;position:relative}

/* ── Tabs ── */
.tabs{display:flex;gap:3px;background:rgba(201,168,76,0.05);padding:3px;border-radius:10px;border:1px solid var(--border);width:fit-content}
.tab-btn{padding:6px 14px;border-radius:8px;font-family:inherit;font-size:11px;font-weight:600;border:none;background:none;color:var(--text3);cursor:pointer;transition:all .2s;letter-spacing:0.04em}
.tab-btn.active{background:linear-gradient(135deg,rgba(201,168,76,0.25),rgba(201,168,76,0.1));color:var(--gold2);border:1px solid rgba(201,168,76,0.2);box-shadow:0 0 12px rgba(201,168,76,0.1)}
.tab-btn:hover:not(.active){background:var(--glass);color:var(--text2)}

/* ── Table ── */
.tb-wrap{overflow-x:auto}
.tb{width:100%;border-collapse:collapse}
.tb th{text-align:left;font-size:9px;font-weight:700;color:var(--text3);padding:10px 16px;text-transform:uppercase;letter-spacing:0.1em;border-bottom:1px solid var(--border);white-space:nowrap}
body[dir="rtl"] .tb th{text-align:right}
.tb td{padding:13px 16px;border-bottom:1px solid rgba(201,168,76,0.06);font-size:13px;vertical-align:middle}
.tb tr:last-child td{border-bottom:none}
.tb tbody tr{transition:background .15s}
.tb tbody tr:hover td{background:rgba(201,168,76,0.03)}

/* ── Tags ── */
.tag{display:inline-flex;align-items:center;padding:3px 9px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase}
.tag-vless{background:rgba(201,168,76,0.1);color:var(--gold2);border:1px solid rgba(201,168,76,0.2)}
.tag-on{background:rgba(74,222,128,0.08);color:#86efac;border:1px solid rgba(74,222,128,0.2)}
.tag-off{background:rgba(255,107,107,0.08);color:#fca5a5;border:1px solid rgba(255,107,107,0.15)}

/* ── Usage Bar ── */
.ub{display:flex;align-items:center;gap:8px;min-width:160px}
.ub-text{font-size:11px;font-weight:600;color:var(--text);white-space:nowrap}
.ub-lim{font-size:11px;color:var(--text3);white-space:nowrap}
.ub-bar{flex:1;height:4px;background:rgba(201,168,76,0.08);border-radius:2px;min-width:40px;overflow:hidden}
.ub-fill{height:100%;border-radius:2px;transition:width .4s cubic-bezier(0.4,0,0.2,1)}

/* ── Toggle ── */
.tog{width:38px;height:21px;border-radius:11px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.1);position:relative;cursor:pointer;transition:all .25s;flex-shrink:0}
.tog::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;background:rgba(255,255,255,0.3);top:2px;left:2px;transition:all .25s}
.tog.on{background:rgba(201,168,76,0.2);border-color:rgba(201,168,76,0.4)}
.tog.on::after{left:19px;background:var(--gold2);box-shadow:0 0 8px rgba(201,168,76,0.6)}

/* ── Buttons ── */
.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:9px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,rgba(201,168,76,0.9),rgba(240,208,96,0.9));color:#0a0a0f;box-shadow:0 2px 16px rgba(201,168,76,0.25)}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-1px);box-shadow:0 4px 24px rgba(201,168,76,0.4)}
.btn-ghost{background:var(--glass);border:1px solid var(--border);color:var(--text2)}
.btn-ghost:hover{border-color:var(--gold);color:var(--gold);background:var(--glass2)}
.btn-danger{background:rgba(255,107,107,0.08);border:1px solid rgba(255,107,107,0.15);color:var(--red)}
.btn-danger:hover{background:rgba(255,107,107,0.15)}
.btn-copy{background:rgba(201,168,76,0.08);border:1px solid rgba(201,168,76,0.15);color:var(--gold2)}
.btn-copy:hover{background:rgba(201,168,76,0.15);transform:translateY(-1px)}
.btn-qr{background:rgba(74,222,128,0.06);border:1px solid rgba(74,222,128,0.15);color:#86efac}
.btn-qr:hover{background:rgba(74,222,128,0.12);transform:translateY(-1px)}
.btn-sub{background:rgba(96,165,250,0.08);border:1px solid rgba(96,165,250,0.15);color:#93c5fd}
.btn-sub:hover{background:rgba(96,165,250,0.15);transform:translateY(-1px)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}
.btn-xs{padding:4px 9px;font-size:10px;border-radius:7px}

/* ── Actions ── */
.act-group{display:flex;gap:4px;align-items:center;flex-wrap:nowrap}

/* ── Toast ── */
#toast{
  position:fixed;bottom:24px;left:50%;
  transform:translateX(-50%) translateY(20px);
  background:rgba(9,9,16,0.97);
  backdrop-filter:blur(20px);
  border-radius:12px;padding:11px 22px;
  font-size:13px;font-weight:500;
  opacity:0;transition:all .3s cubic-bezier(0.34,1.56,0.64,1);
  z-index:9999;display:flex;align-items:center;gap:8px;
  box-shadow:0 8px 40px rgba(0,0,0,0.5);
  pointer-events:none;
}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.ok{border:1px solid rgba(201,168,76,0.3);color:var(--gold2)}
#toast.err{border:1px solid rgba(255,107,107,0.25);color:var(--red)}
#toast.info{border:1px solid rgba(96,165,250,0.25);color:#93c5fd}

/* ── Modal ── */
.moverlay{position:fixed;inset:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(10px);z-index:200;display:none;align-items:center;justify-content:center;padding:20px}
.moverlay.open{display:flex}
.modal{
  background:rgba(9,9,16,0.97);
  backdrop-filter:blur(30px);
  border:1px solid var(--border2);
  border-radius:20px;padding:28px;
  width:100%;max-width:500px;
  position:relative;
  box-shadow:0 0 60px rgba(201,168,76,0.08),0 30px 70px rgba(0,0,0,0.6);
  animation:mIn .35s cubic-bezier(0.34,1.56,0.64,1) forwards;
}
.modal::before{content:'';position:absolute;top:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,var(--gold),transparent)}
@keyframes mIn{from{opacity:0;transform:scale(0.88) translateY(20px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal-close{position:absolute;top:14px;right:14px;width:28px;height:28px;border-radius:7px;background:var(--glass);border:1px solid var(--border);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;transition:all .2s}
body[dir="rtl"] .modal-close{right:auto;left:14px}
.modal-close:hover{background:rgba(255,107,107,0.1);border-color:rgba(255,107,107,0.3);color:var(--red)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:22px;letter-spacing:-0.01em;color:var(--gold2)}

/* ── Form ── */
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.fl{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em}
.fi,.fs{padding:10px 13px;border-radius:10px;background:rgba(201,168,76,0.04);border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);transition:all .2s}
.fi:focus,.fs:focus{border-color:var(--gold);background:rgba(201,168,76,0.07);box-shadow:0 0 0 3px rgba(201,168,76,0.1)}
.fi::placeholder{color:var(--text4)}
.fs{cursor:pointer}.fs option{background:#0f0f18;color:var(--text)}
.form-row{display:flex;gap:10px;align-items:flex-end}
.form-row .fg{flex:1;margin-bottom:0}

/* ── Detail card ── */
.dc{padding:11px 14px;background:rgba(201,168,76,0.04);border:1px solid var(--border);border-radius:10px}
.dc-lbl{font-size:9px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:5px}
.dc-val{font-size:12px;color:var(--text2);word-break:break-all;font-family:'JetBrains Mono',monospace;line-height:1.7}

/* ── QR ── */
.qr-box{text-align:center;padding:24px;background:rgba(201,168,76,0.03);border:1px solid var(--border);border-radius:14px;margin-top:16px;transition:all .3s}
.qr-box:hover{border-color:var(--border2);box-shadow:0 0 30px rgba(201,168,76,0.08)}
.qr-box img{max-width:200px;border-radius:10px;background:#fff;padding:8px}

/* ── System bars ── */
.sys-bar{height:6px;background:rgba(201,168,76,0.08);border-radius:3px;overflow:hidden;margin-top:10px;position:relative}
.sys-fill{height:100%;border-radius:3px;transition:width .6s cubic-bezier(0.4,0,0.2,1)}

/* ── Status list ── */
.sl-item{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(201,168,76,0.06)}
.sl-item:last-child{border-bottom:none}
.sl-key{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:8px}
.sl-val{color:var(--text);font-weight:600;font-size:13px}

/* ── Connections ── */
.conn-item{display:flex;align-items:center;justify-content:space-between;padding:11px 15px;border-radius:10px;background:var(--glass);border:1px solid var(--border);margin-bottom:6px;font-size:12px;transition:all .2s}
.conn-item:hover{border-color:var(--border2)}
.conn-id{color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:10px}
.conn-bytes{color:var(--gold2);font-weight:600}

/* ── Search bar ── */
.search-wrap{position:relative;flex:1;min-width:180px}
.search-wrap svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.search-inp{width:100%;padding:9px 12px 9px 35px;background:rgba(201,168,76,0.04);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:all .2s}
.search-inp:focus{border-color:var(--gold);background:rgba(201,168,76,0.07)}
.search-inp::placeholder{color:var(--text3)}

/* ── Filter chips ── */
.chips{display:flex;gap:3px;background:rgba(201,168,76,0.04);padding:3px;border-radius:9px;border:1px solid var(--border)}
.chip{padding:5px 12px;border-radius:7px;font-size:11px;font-weight:600;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:linear-gradient(135deg,rgba(201,168,76,0.2),rgba(201,168,76,0.08));color:var(--gold2);border:1px solid rgba(201,168,76,0.2)}
.chip:hover:not(.active){background:var(--glass);color:var(--text2)}

/* ── Empty state ── */
.empty{text-align:center;padding:52px 16px;color:var(--text3)}
.empty-icon{margin-bottom:14px;opacity:0.2}
.empty-msg{font-size:13px;font-weight:500}

/* ── Live badge ── */
.live-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(74,222,128,0.07);border:1px solid rgba(74,222,128,0.15);border-radius:6px;padding:3px 9px;font-size:10px;font-weight:700;color:#86efac;letter-spacing:0.06em}

/* ── Mobile header ── */
.mob-header{display:none;position:fixed;top:0;left:0;right:0;height:50px;background:rgba(5,5,8,0.9);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 16px}
.ham{width:36px;height:36px;border-radius:9px;background:var(--glass);border:1px solid var(--border);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:16px}
.sb-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:99}
.sb-overlay.open{display:block}

/* ── Grid helpers ── */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.mb12{margin-bottom:12px}.mb16{margin-bottom:16px}

/* ── PW strength ── */
.pw-strength{height:3px;border-radius:2px;margin-top:6px;transition:all .3s;background:var(--border)}
.pw-strength.w{background:var(--red);width:25%}
.pw-strength.m{background:var(--yellow);width:60%}
.pw-strength.s{background:var(--green);width:100%}

/* ── Sub link card in detail ── */
.sub-card{
  background:linear-gradient(135deg,rgba(96,165,250,0.07),rgba(96,165,250,0.03));
  border:1px solid rgba(96,165,250,0.15);
  border-radius:10px;padding:12px 14px;margin-bottom:10px;
}
.sub-card .sub-label{font-size:9px;font-weight:700;color:rgba(96,165,250,0.6);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:5px}
.sub-card .sub-val{font-size:11px;color:#93c5fd;font-family:'JetBrains Mono',monospace;line-height:1.7;word-break:break-all}

/* expiry */
.expiry-badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;padding:2px 8px;border-radius:5px;font-weight:600}
.expiry-ok{background:rgba(74,222,128,0.08);color:#86efac;border:1px solid rgba(74,222,128,0.15)}
.expiry-warn{background:rgba(251,191,36,0.08);color:#fcd34d;border:1px solid rgba(251,191,36,0.15)}
.expiry-exp{background:rgba(255,107,107,0.08);color:#fca5a5;border:1px solid rgba(255,107,107,0.15)}

@media(max-width:900px){.stats-grid{grid-template-columns:repeat(2,1fr)}.g2{grid-template-columns:1fr}}
@media(max-width:680px){
  .sidebar{transform:translateX(-100%);z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:4px 0 40px rgba(0,0,0,0.7)}
  .main{margin-left:0;padding-top:60px;padding-left:14px;padding-right:14px}
  .mob-header{display:flex}
  .stats-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:400px){.stats-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="bg-fixed">
  <div class="bg-grad"></div>
  <div class="bg-grid"></div>
  <div class="bg-vignette"></div>
</div>

<div id="toast"></div>

<div class="mob-header">
  <div style="font-family:'Cinzel',serif;font-weight:700;font-size:16px;background:linear-gradient(135deg,#f0d060,#c9a84c);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:0.1em">LUFFY</div>
  <button class="ham" onclick="toggleSidebar()">&#9776;</button>
</div>
<div class="sb-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>

<aside class="sidebar" id="sidebar">
  <div class="sb-brand">
    <div class="sb-logo">
      <div class="sb-logo-icon">
        <svg viewBox="0 0 44 44" fill="none">
          <path d="M11 9h9v22h15v9H11V9z" fill="url(#sb-g)"/>
          <defs><linearGradient id="sb-g" x1="11" y1="9" x2="35" y2="40" gradientUnits="userSpaceOnUse"><stop stop-color="#f0d060"/><stop offset="1" stop-color="#c9a84c"/></linearGradient></defs>
        </svg>
      </div>
      <div>
        <div class="sb-title">LUFFY</div>
        <div class="sb-ver">Panel v4.0</div>
      </div>
    </div>
    <button class="sb-icon-btn" onclick="toggleTheme()" title="Settings">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
    </button>
  </div>

  <nav class="sb-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      <span class="online-dot" style="margin-left:auto"></span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
    </button>
    <button class="nav-item" data-page="connections">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
      <span data-en="Connections" data-fa="اتصالات">Connections</span>
      <span class="nav-dot"></span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span data-en="Security" data-fa="امنیت">Security</span>
    </button>
  </nav>

  <div class="sb-footer">
    <div class="lang-row">
      <button class="lang-btn active" id="lb-en" onclick="setLang('en')">EN</button>
      <button class="lang-btn" id="lb-fa" onclick="setLang('fa')">FA</button>
    </div>
    <button class="logout-btn" onclick="doLogout()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
  </div>
</aside>

<main class="main">

  <!-- ─── DASHBOARD ─── -->
  <section class="page active" id="page-dashboard">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Overview" data-fa="نمای کلی">Overview</div>
        <div class="ps" id="last-upd">Auto-refresh every 10s</div>
      </div>
      <div class="ph-right">
        <span class="live-badge"><span class="online-dot" style="margin:0"></span>&nbsp;LIVE</span>
        <button class="btn btn-ghost btn-sm" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary btn-sm" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>

    <div class="stats-grid mb12">
      <div class="sc">
        <div class="sc-icon" style="background:rgba(201,168,76,0.08)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#c9a84c" stroke-width="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="sc-label">Total Traffic</div>
        <div class="sc-val" id="s-traffic">--<span class="sc-unit"> MB</span></div>
        <div class="sc-sub" id="s-traffic-sub">All time</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(74,222,128,0.08)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
        </div>
        <div class="sc-label">Active Links</div>
        <div class="sc-val" id="s-links">--</div>
        <div class="sc-sub" id="s-links-sub">of -- total</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(251,191,36,0.08)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="sc-label">Uptime</div>
        <div class="sc-val" id="s-uptime" style="font-size:19px">--</div>
        <div class="sc-sub">Since last restart</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(96,165,250,0.08)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
        </div>
        <div class="sc-label">Live Connections</div>
        <div class="sc-val" id="s-conns">--</div>
        <div class="sc-sub">Right now</div>
      </div>
    </div>

    <div class="g2 mb12">
      <div class="gc">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
          <div style="font-size:13px;font-weight:700;color:var(--text2)">CPU Usage</div>
          <span id="s-cpu-val" style="font-size:22px;font-weight:800;color:var(--gold2)">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-fill" id="s-cpu-bar" style="width:0%;background:linear-gradient(90deg,#c9a84c,#f0d060)"></div></div>
      </div>
      <div class="gc">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
          <div style="font-size:13px;font-weight:700;color:var(--text2)">Memory</div>
          <span id="s-mem-val" style="font-size:22px;font-weight:800;color:#86efac">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-fill" id="s-mem-bar" style="width:0%;background:linear-gradient(90deg,#4ade80,#86efac)"></div></div>
        <div style="font-size:11px;color:var(--text3);margin-top:8px" id="s-mem-detail">-- / -- MB</div>
      </div>
    </div>

    <div class="gc mb12">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <div style="font-size:13px;font-weight:700;color:var(--text2)">Traffic Chart</div>
        <div class="tabs">
          <button class="tab-btn active" onclick="switchChart('hourly',this)">Hourly</button>
          <button class="tab-btn" onclick="switchChart('daily',this)">Daily</button>
        </div>
      </div>
      <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
    </div>

    <div class="gc">
      <div style="font-size:13px;font-weight:700;color:var(--text2);margin-bottom:14px">Server Info</div>
      <div class="sl-item"><span class="sl-key"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> Domain</span><span class="sl-val" id="s-domain" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--gold2)">--</span></div>
      <div class="sl-item"><span class="sl-key"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.5"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20"/></svg> Total Requests</span><span class="sl-val" id="s-reqs">--</span></div>
      <div class="sl-item" style="border:none"><span class="sl-key"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg> Errors</span><span class="sl-val" id="s-errs" style="color:var(--red)">--</span></div>
    </div>
  </section>

  <!-- ─── INBOUNDS ─── -->
  <section class="page" id="page-inbounds">
    <div class="ph">
      <div class="ph-left">
        <div class="pt">Inbounds</div>
        <div class="ps">VLESS / WebSocket / TLS · Subscription Ready</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span data-en="New Inbound" data-fa="اینباند جدید">New Inbound</span>
      </button>
    </div>

    <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap">
      <div class="search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input class="search-inp" id="srch" placeholder="Search by name or UUID..." oninput="filterLinks()">
      </div>
      <div class="chips">
        <button class="chip active" onclick="setFilter('all',this)">All</button>
        <button class="chip" onclick="setFilter('active',this)">Active</button>
        <button class="chip" onclick="setFilter('off',this)">Disabled</button>
        <button class="chip" onclick="setFilter('limited',this)">Limited</button>
      </div>
    </div>

    <div class="gc" style="padding:0;overflow:hidden">
      <div class="tb-wrap">
        <table class="tb">
          <thead><tr>
            <th>#</th>
            <th>Name</th>
            <th>Type</th>
            <th>Traffic</th>
            <th>Expiry</th>
            <th>Status</th>
            <th>Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/></svg></div>
        <div class="empty-msg">No inbounds found</div>
      </div>
    </div>
  </section>

  <!-- ─── TRAFFIC ─── -->
  <section class="page" id="page-traffic">
    <div class="ph">
      <div class="ph-left">
        <div class="pt">Traffic Analytics</div>
        <div class="ps">Detailed usage breakdown</div>
      </div>
    </div>
    <div class="g2 mb12">
      <div class="gc">
        <div style="font-size:13px;font-weight:700;color:var(--text2);margin-bottom:14px">Overview</div>
        <div class="sl-item"><span class="sl-key">Total Traffic</span><span class="sl-val" id="t-total">-- MB</span></div>
        <div class="sl-item"><span class="sl-key">Today</span><span class="sl-val" id="t-today">-- MB</span></div>
        <div class="sl-item"><span class="sl-key">Requests</span><span class="sl-val" id="t-reqs">--</span></div>
        <div class="sl-item" style="border:none"><span class="sl-key">Uptime</span><span class="sl-val" id="t-uptime">--</span></div>
      </div>
      <div class="gc">
        <div style="font-size:13px;font-weight:700;color:var(--text2);margin-bottom:14px">Top Users by Usage</div>
        <div id="top-users-list" style="display:flex;flex-direction:column;gap:10px"></div>
      </div>
    </div>
    <div class="gc">
      <div style="font-size:13px;font-weight:700;color:var(--text2);margin-bottom:14px">Daily Traffic (Last 14 days)</div>
      <div class="chart-wrap"><canvas id="dailyChart"></canvas></div>
    </div>
  </section>

  <!-- ─── CONNECTIONS ─── -->
  <section class="page" id="page-connections">
    <div class="ph">
      <div class="ph-left">
        <div class="pt">Live Connections</div>
        <div class="ps" id="conn-count-sub">-- active tunnels</div>
      </div>
      <span class="live-badge"><span class="online-dot" style="margin:0"></span>&nbsp;LIVE</span>
    </div>
    <div id="conn-list"></div>
  </section>

  <!-- ─── SECURITY ─── -->
  <section class="page" id="page-security">
    <div class="ph">
      <div class="ph-left">
        <div class="pt">Security</div>
        <div class="ps">Password & session management</div>
      </div>
    </div>
    <div style="max-width:420px">
      <div class="gc mb12">
        <div style="font-size:13px;font-weight:700;color:var(--text2);margin-bottom:18px">Change Master Password</div>
        <div class="fg">
          <label class="fl">Current Password</label>
          <input class="fi" type="password" id="cur-pw" placeholder="Enter current password">
        </div>
        <div class="fg">
          <label class="fl">New Password</label>
          <input class="fi" type="password" id="new-pw" placeholder="Min 4 characters" oninput="checkPwStrength(this.value)">
          <div class="pw-strength" id="pw-str"></div>
        </div>
        <div class="fg" style="margin-bottom:0">
          <label class="fl">Confirm Password</label>
          <input class="fi" type="password" id="conf-pw" placeholder="Repeat new password">
        </div>
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="width:100%;justify-content:center;padding:13px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Update Password
      </button>
    </div>
  </section>
</main>

<!-- ─── Modals ─── -->

<!-- Add Modal -->
<div class="moverlay" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-modal')">✕</button>
    <div class="modal-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px;color:var(--gold)"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      New Inbound
    </div>
    <div class="fg">
      <label class="fl">Name / Remark</label>
      <input class="fi" id="new-lbl" placeholder="e.g. VIP User">
    </div>
    <div class="form-row">
      <div class="fg">
        <label class="fl">Traffic Limit</label>
        <input class="fi" id="new-lim" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="fg" style="min-width:90px;max-width:100px">
        <label class="fl">Unit</label>
        <select class="fs" id="new-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="fg">
      <label class="fl">Expiry Date (optional)</label>
      <input class="fi" id="new-exp" type="date" placeholder="Leave empty for no expiry">
    </div>
    <div class="fg">
      <label class="fl">Note (optional)</label>
      <input class="fi" id="new-note" placeholder="e.g. Expires in 30 days">
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;padding:12px;margin-top:6px">
      Create Inbound
    </button>
  </div>
</div>

<!-- Detail Modal -->
<div class="moverlay" id="detail-modal" onclick="if(event.target===this)closeModal('detail-modal')">
  <div class="modal" style="max-width:540px">
    <button class="modal-close" onclick="closeModal('detail-modal')">✕</button>
    <div class="modal-title" id="dtl-title">Details</div>
    <div id="dtl-content"></div>
  </div>
</div>

<!-- QR Modal -->
<div class="moverlay" id="qr-modal" onclick="if(event.target===this)closeModal('qr-modal')">
  <div class="modal" style="max-width:360px">
    <button class="modal-close" onclick="closeModal('qr-modal')">✕</button>
    <div class="modal-title" id="qr-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR Code"></div>
    <div style="display:flex;gap:8px;margin-top:16px">
      <button class="btn btn-primary" style="flex:1;justify-content:center" onclick="dlQR()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download
      </button>
      <button class="btn btn-ghost" style="flex:1;justify-content:center" onclick="closeModal('qr-modal')">Close</button>
    </div>
  </div>
</div>

<script>
let lang = localStorage.getItem('ll') || 'en';
let allLinks = [];
let filterMode = 'all';
let statsData = {};
let chartMode = 'hourly';
let trafficChart = null;
let dailyChart = null;
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

// ── Nav ──
$$('.nav-item').forEach(el => el.addEventListener('click', () => {
  if(el.dataset.page) switchPage(el.dataset.page);
}));
function switchPage(id) {
  $$('.page').forEach(p => p.classList.remove('active'));
  $(`#page-${id}`)?.classList.add('active');
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === id));
  $('#sidebar')?.classList.remove('open');
  $('#sb-overlay')?.classList.remove('open');
}
function toggleSidebar() {
  $('#sidebar').classList.toggle('open');
  $('#sb-overlay').classList.toggle('open');
}
function toggleTheme() {}

// ── Lang ──
function setLang(l) {
  lang = l; localStorage.setItem('ll', l);
  document.body.dir = l === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el => {
    const v = el.getAttribute('data-' + l); if(v) el.textContent = v;
  });
  $('#lb-en').classList.toggle('active', l === 'en');
  $('#lb-fa').classList.toggle('active', l === 'fa');
}

// ── Toast ──
function toast(msg, type = 'ok') {
  const t = $('#toast');
  t.textContent = msg; t.className = 'show ' + type;
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 3200);
}

// ── Modal ──
function openModal(id) { $(`#${id}`).classList.add('open'); }
function closeModal(id) { $(`#${id}`).classList.remove('open'); }

// ── Logout ──
async function doLogout() {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/login';
}

// ── Helpers ──
function fmtBytes(b) {
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtLimit(b) {
  if (!b || b === 0) return '∞';
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  return (b / 1048576).toFixed(0) + ' MB';
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function expiryBadge(exp) {
  if (!exp) return '<span class="expiry-badge expiry-ok">No Expiry</span>';
  try {
    const d = new Date(exp);
    const now = new Date();
    const diff = Math.ceil((d - now) / 86400000);
    if (diff < 0) return '<span class="expiry-badge expiry-exp">Expired</span>';
    if (diff <= 3) return `<span class="expiry-badge expiry-warn">${diff}d left</span>`;
    return `<span class="expiry-badge expiry-ok">${diff}d left</span>`;
  } catch { return ''; }
}

// ── Stats ──
async function loadStats() {
  try {
    const r = await fetch('/stats');
    if (!r.ok) return;
    statsData = await r.json();
    const mb = statsData.total_traffic_mb;
    const gb = (mb / 1024).toFixed(2);
    $('#s-traffic').innerHTML = mb > 1024 ? `${gb}<span class="sc-unit"> GB</span>` : `${mb}<span class="sc-unit"> MB</span>`;
    $('#s-links').textContent = statsData.active_links ?? statsData.links_count;
    $('#s-links-sub').textContent = `of ${statsData.links_count} total`;
    $('#s-uptime').textContent = statsData.uptime;
    $('#s-conns').textContent = statsData.active_connections;
    $('#s-domain').textContent = statsData.domain;
    $('#s-reqs').textContent = (statsData.total_requests || 0).toLocaleString();
    $('#s-errs').textContent = (statsData.total_errors || 0).toLocaleString();
    $('#last-upd').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    $('#links-badge').textContent = statsData.links_count;

    const cpu = statsData.cpu_percent || 0;
    const cpuC = cpu > 80 ? 'linear-gradient(90deg,#ff6b6b,#fca5a5)' : cpu > 50 ? 'linear-gradient(90deg,#fbbf24,#fcd34d)' : 'linear-gradient(90deg,#c9a84c,#f0d060)';
    $('#s-cpu-val').textContent = cpu.toFixed(1) + '%';
    $('#s-cpu-bar').style.cssText = `width:${cpu}%;background:${cpuC}`;

    const mem = statsData.memory_percent || 0;
    const memC = mem > 80 ? 'linear-gradient(90deg,#ff6b6b,#fca5a5)' : mem > 50 ? 'linear-gradient(90deg,#fbbf24,#fcd34d)' : 'linear-gradient(90deg,#4ade80,#86efac)';
    $('#s-mem-val').textContent = mem.toFixed(1) + '%';
    $('#s-mem-bar').style.cssText = `width:${mem}%;background:${memC}`;
    if (statsData.memory_used_mb) $('#s-mem-detail').textContent = `${statsData.memory_used_mb} / ${statsData.memory_total_mb} MB`;

    // Traffic page
    const todayKey = new Date().toISOString().split('T')[0];
    const todayBytes = (statsData.daily_traffic || {})[todayKey] || 0;
    if ($('#t-total')) {
      $('#t-total').textContent = fmtBytes(statsData.total_bytes || (mb * 1024 * 1024));
      $('#t-today').textContent = fmtBytes(todayBytes);
      $('#t-reqs').textContent = (statsData.total_requests || 0).toLocaleString();
      $('#t-uptime').textContent = statsData.uptime;
    }

    // Connections
    const conns = statsData.connections || [];
    $('#conn-count-sub').textContent = `${conns.length} active tunnel${conns.length !== 1 ? 's' : ''}`;
    const connList = $('#conn-list');
    if (conns.length === 0) {
      connList.innerHTML = `<div class="gc"><div class="empty"><div class="empty-icon"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg></div><div class="empty-msg">No active connections right now</div></div></div>`;
    } else {
      connList.innerHTML = conns.map(c => `
        <div class="conn-item">
          <div><div class="conn-id">${esc(c.id)}</div><div style="font-size:11px;color:var(--text2);margin-top:2px">${esc(c.uuid.slice(0,20))}…</div></div>
          <div style="text-align:right"><div class="conn-bytes">${fmtBytes(c.bytes)}</div><div style="font-size:10px;color:var(--text3)">${esc(c.connected_at?.slice(11,19)||'')}</div></div>
        </div>`).join('');
    }

    // Top users
    const topList = $('#top-users-list');
    if (topList && allLinks.length) {
      const sorted = [...allLinks].sort((a,b) => b.used_bytes - a.used_bytes).slice(0,5);
      topList.innerHTML = sorted.map(l => {
        const pct = l.limit_bytes > 0 ? Math.min(100,(l.used_bytes/l.limit_bytes)*100) : 0;
        const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--gold)';
        return `<div style="display:flex;flex-direction:column;gap:5px">
          <div style="display:flex;justify-content:space-between;font-size:12px">
            <span style="font-weight:600;color:var(--text)">${esc(l.label)}</span>
            <span style="color:var(--gold2)">${fmtBytes(l.used_bytes)}</span>
          </div>
          <div class="ub-bar"><div class="ub-fill" style="width:${pct}%;background:${col}"></div></div>
        </div>`;
      }).join('');
    }

    updateChart();
  } catch(e) {}
}

// ── Links ──
async function loadLinks() {
  try {
    const r = await fetch('/api/links');
    if (!r.ok) return;
    allLinks = (await r.json()).links || [];
    filterLinks();
  } catch(e) {}
}

function setFilter(f, el) {
  filterMode = f;
  $$('.chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  filterLinks();
}
function filterLinks() {
  const q = ($('#srch')?.value || '').toLowerCase();
  let list = [...allLinks];
  if (filterMode === 'active') list = list.filter(l => l.active);
  if (filterMode === 'off') list = list.filter(l => !l.active);
  if (filterMode === 'limited') list = list.filter(l => l.limit_bytes > 0);
  if (q) list = list.filter(l => l.label.toLowerCase().includes(q) || l.uuid.toLowerCase().includes(q));
  renderLinks(list);
}

function renderLinks(links) {
  const tbody = $('#links-tbody');
  const empty = $('#links-empty');
  if (!links.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  let idx = links.length;
  tbody.innerHTML = links.map(l => {
    const u = l.used_bytes, lim = l.limit_bytes;
    const pct = lim > 0 ? Math.min(100,(u/lim)*100) : 0;
    const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--gold)';
    const i = idx--;
    const expBadge = expiryBadge(l.expires_at);
    return `<tr>
      <td style="color:var(--text3);font-size:10px;font-family:'JetBrains Mono',monospace">${i}</td>
      <td>
        <div style="font-weight:600;color:var(--text)">${esc(l.label)}</div>
        ${l.note ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">${esc(l.note)}</div>` : ''}
      </td>
      <td><span class="tag tag-vless">VLESS</span></td>
      <td>
        <div class="ub">
          <span class="ub-text">${fmtBytes(u)}</span>
          <div class="ub-bar"><div class="ub-fill" style="width:${pct}%;background:${col}"></div></div>
          <span class="ub-lim">${fmtLimit(lim)}</span>
        </div>
      </td>
      <td>${expBadge}</td>
      <td><span class="tag ${l.active ? 'tag-on' : 'tag-off'}">${l.active ? 'ON' : 'OFF'}</span></td>
      <td>
        <div class="act-group">
          <div class="tog ${l.active ? 'on' : ''}" data-uid="${l.uuid}" onclick="toggleLink(this)" title="Toggle"></div>
          <button class="btn btn-ghost btn-xs" onclick="showDetail('${l.uuid}')" title="Details">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </button>
          <button class="btn btn-copy btn-xs" onclick="copyText('${esc(l.vless_link)}')" title="Copy VLESS">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>
          <button class="btn btn-sub btn-xs" onclick="copySub('${esc(l.sub_link)}')" title="Copy Subscription">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
          </button>
          <button class="btn btn-qr btn-xs" onclick="showQR('${esc(l.vless_link)}','${esc(l.label)}')" title="QR Code">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h.01M14 17h3v3M17 14h3"/></svg>
          </button>
          <button class="btn btn-danger btn-xs" onclick="deleteLink('${l.uuid}')" title="Delete">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
          </button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function toggleLink(el) {
  const uid = el.dataset.uid;
  const link = allLinks.find(l => l.uuid === uid);
  if (!link) return;
  const newActive = !link.active;
  try {
    await fetch(`/api/links/${uid}`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({active:newActive}) });
    link.active = newActive;
    filterLinks(); loadStats();
    toast(newActive ? '✓ Link enabled' : '✓ Link disabled');
  } catch(e) { toast('Error', 'err'); }
}

async function quickCreate(lim, unit) {
  const names = ['Alpha','Beta','Gamma','Delta','Sigma','Omega','Nova','Apex','Zeta','Titan','Lyra','Orion'];
  const name = names[Math.floor(Math.random()*names.length)] + '-' + Math.floor(Math.random()*100);
  try {
    const r = await fetch('/api/links', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({label:name,limit_value:lim,limit_unit:unit}) });
    if (!r.ok) throw new Error();
    toast(`✓ Created: ${name}`);
    await loadLinks(); await loadStats();
  } catch(e) { toast('Error creating link', 'err'); }
}

function showAddModal() {
  $('#new-lbl').value = ''; $('#new-lim').value = '';
  $('#new-note').value = ''; $('#new-exp').value = '';
  openModal('add-modal');
}

async function createLink() {
  const label = ($('#new-lbl').value.trim() || 'New Link');
  const val = parseFloat($('#new-lim').value) || 0;
  const unit = $('#new-unit').value;
  const note = $('#new-note').value.trim();
  const exp = $('#new-exp').value || null;
  const expires_at = exp ? new Date(exp + 'T23:59:59').toISOString() : null;
  try {
    const r = await fetch('/api/links', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({label,limit_value:val,limit_unit:unit,note,expires_at}) });
    if (!r.ok) throw new Error();
    toast('✓ Inbound created');
    closeModal('add-modal');
    await loadLinks(); await loadStats();
  } catch(e) { toast('Error', 'err'); }
}

async function deleteLink(uid) {
  if (!confirm('Delete this inbound permanently?')) return;
  try {
    await fetch(`/api/links/${uid}`, {method:'DELETE'});
    toast('✓ Deleted');
    await loadLinks(); await loadStats();
  } catch(e) { toast('Error', 'err'); }
}

function showDetail(uid) {
  const l = allLinks.find(x => x.uuid === uid);
  if (!l) return;
  const pct = l.limit_bytes > 0 ? Math.min(100,(l.used_bytes/l.limit_bytes)*100) : 0;
  const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--gold)';
  const created = l.created_at ? new Date(l.created_at).toLocaleString() : '--';
  const expBadge = expiryBadge(l.expires_at);
  $('#dtl-title').textContent = l.label;
  $('#dtl-content').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:12px">
      <div class="dc"><div class="dc-lbl">Protocol</div><span class="tag tag-vless" style="margin-top:4px;display:inline-flex">VLESS</span></div>
      <div class="dc"><div class="dc-lbl">Status</div><span class="tag ${l.active?'tag-on':'tag-off'}" style="margin-top:4px;display:inline-flex">${l.active?'Active':'Disabled'}</span></div>
      <div class="dc"><div class="dc-lbl">Expiry</div><div style="margin-top:4px">${expBadge}</div></div>
    </div>
    <div class="dc mb12"><div class="dc-lbl">UUID</div><div class="dc-val">${esc(l.uuid)}</div></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px">
      <div class="dc"><div class="dc-lbl">Used</div><div class="dc-val" style="font-size:13px;color:var(--text);font-family:inherit">${fmtBytes(l.used_bytes)}</div></div>
      <div class="dc"><div class="dc-lbl">Limit</div><div class="dc-val" style="font-size:13px;color:var(--text);font-family:inherit">${fmtLimit(l.limit_bytes)}</div></div>
      <div class="dc"><div class="dc-lbl">Usage</div><div class="dc-val" style="font-size:13px;color:${col};font-family:inherit">${pct.toFixed(1)}%</div></div>
    </div>
    <div class="ub-bar" style="height:5px;margin-bottom:14px;background:rgba(201,168,76,0.08)"><div class="ub-fill" style="width:${pct}%;background:${col}"></div></div>
    ${l.note ? `<div class="dc mb12"><div class="dc-lbl">Note</div><div class="dc-val" style="font-family:inherit">${esc(l.note)}</div></div>` : ''}
    <div class="dc mb12"><div class="dc-lbl">Created</div><div class="dc-val" style="font-family:inherit;font-size:11px">${created}</div></div>
    <div class="sub-card mb12">
      <div class="sub-label">⚡ Subscription Link</div>
      <div class="sub-val">${esc(l.sub_link)}</div>
    </div>
    <div class="dc mb12"><div class="dc-lbl">VLESS Link</div><div class="dc-val" style="font-size:10px;line-height:1.8">${esc(l.vless_link)}</div></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px">
      <button class="btn btn-sub btn-sm" onclick="copySub('${esc(l.sub_link)}')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
        Copy Sub Link
      </button>
      <button class="btn btn-copy btn-sm" onclick="copyText('${esc(l.vless_link)}')">Copy VLESS</button>
      <button class="btn btn-qr btn-sm" onclick="showQR('${esc(l.sub_link)}','Sub: ${esc(l.label)}')">Sub QR</button>
      <button class="btn btn-ghost btn-sm" onclick="resetUsage('${l.uuid}');closeModal('detail-modal')">Reset Traffic</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${l.uuid}');closeModal('detail-modal')">Delete</button>
    </div>`;
  openModal('detail-modal');
}

async function resetUsage(uid) {
  try {
    await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});
    toast('✓ Traffic reset'); await loadLinks();
  } catch(e) { toast('Error','err'); }
}

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => toast('✓ Copied to clipboard')).catch(() => toast('Copy failed','err'));
}

function copySub(url) {
  navigator.clipboard.writeText(url).then(() => toast('✓ Subscription link copied','info')).catch(() => toast('Copy failed','err'));
}

function showQR(txt, label) {
  if (!txt) return;
  $('#qr-title').textContent = label ? `QR — ${label}` : 'QR Code';
  $('#qr-img').src = 'https://api.qrserver.com/v1/create-qr-code/?size=280x280&color=c9a84c&bgcolor=050508&data=' + encodeURIComponent(txt);
  openModal('qr-modal');
}

function dlQR() {
  const img = $('#qr-img'); if (!img.src) return;
  const a = document.createElement('a'); a.href = img.src; a.download = 'luffy-qr.png'; a.click();
}

// ── Password ──
function checkPwStrength(v) {
  const el = $('#pw-str');
  if (!v) { el.className = 'pw-strength'; return; }
  const strong = v.length >= 8 && /[A-Z]/.test(v) && /[0-9]/.test(v);
  const medium = v.length >= 6;
  el.className = 'pw-strength ' + (strong ? 's' : medium ? 'm' : 'w');
}

async function changePassword() {
  const cur = $('#cur-pw').value, nw = $('#new-pw').value, conf = $('#conf-pw').value;
  if (!cur || !nw) return toast('Fill all fields','err');
  if (nw !== conf) return toast('Passwords do not match','err');
  if (nw.length < 4) return toast('Min 4 characters','err');
  try {
    const r = await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
    if (!r.ok) { const d = await r.json().catch(()=>({})); throw new Error(d.detail||'Error'); }
    toast('✓ Password updated');
    $('#cur-pw').value='';$('#new-pw').value='';$('#conf-pw').value='';$('#pw-str').className='pw-strength';
  } catch(e) { toast(e.message,'err'); }
}

// ── Charts ──
function initCharts() {
  const goldGrad = (ctx) => {
    const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 200);
    g.addColorStop(0, 'rgba(201,168,76,0.5)');
    g.addColorStop(1, 'rgba(201,168,76,0.02)');
    return g;
  };
  const baseOpts = {
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{
      backgroundColor:'rgba(9,9,16,0.97)',
      titleColor:'rgba(201,168,76,0.7)',
      bodyColor:'rgba(255,255,255,0.9)',
      borderColor:'rgba(201,168,76,0.2)',
      borderWidth:1,padding:12,cornerRadius:10,
      callbacks:{label:(c)=>' '+fmtBytes(c.raw)}
    }},
    scales:{
      x:{grid:{display:false},ticks:{color:'rgba(180,160,100,0.35)',font:{size:10,family:'Inter'}}},
      y:{grid:{color:'rgba(201,168,76,0.05)'},ticks:{color:'rgba(180,160,100,0.35)',font:{size:10},callback:v=>fmtBytes(v)},beginAtZero:true}
    }
  };

  const ctx1 = document.getElementById('trafficChart');
  if (ctx1) trafficChart = new Chart(ctx1, {
    type:'bar',
    data:{labels:[],datasets:[{label:'Traffic',data:[],backgroundColor:'rgba(201,168,76,0.25)',borderColor:'#c9a84c',borderWidth:1.5,borderRadius:5,borderSkipped:false,hoverBackgroundColor:'rgba(201,168,76,0.4)'}]},
    options:{...baseOpts}
  });

  const ctx2 = document.getElementById('dailyChart');
  if (ctx2) dailyChart = new Chart(ctx2, {
    type:'line',
    data:{labels:[],datasets:[{label:'Daily',data:[],borderColor:'#c9a84c',borderWidth:2,backgroundColor:(ctx)=>goldGrad(ctx),fill:true,tension:0.4,pointBackgroundColor:'#f0d060',pointRadius:4,pointHoverRadius:6}]},
    options:{...baseOpts}
  });
}

function switchChart(mode, el) {
  chartMode = mode;
  $$('.tab-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  updateChart();
}

function updateChart() {
  if (!trafficChart) return;
  const hourly = statsData.hourly_traffic || {};
  const daily = statsData.daily_traffic || {};
  if (chartMode === 'hourly') {
    const entries = Object.entries(hourly).sort((a,b)=>a[0].localeCompare(b[0])).slice(-16);
    trafficChart.data.labels = entries.map(e=>e[0]);
    trafficChart.data.datasets[0].data = entries.map(e=>e[1]);
  } else {
    const entries = Object.entries(daily).sort((a,b)=>a[0].localeCompare(b[0])).slice(-14);
    trafficChart.data.labels = entries.map(e=>e[0].slice(5));
    trafficChart.data.datasets[0].data = entries.map(e=>e[1]);
  }
  trafficChart.update('none');

  if (dailyChart) {
    const entries = Object.entries(daily).sort((a,b)=>a[0].localeCompare(b[0])).slice(-14);
    dailyChart.data.labels = entries.map(e=>e[0].slice(5));
    dailyChart.data.datasets[0].data = entries.map(e=>e[1]);
    dailyChart.update('none');
  }
}

// ── Init ──
setLang(lang);
initCharts();
loadStats();
loadLinks();
setInterval(loadStats, 10000);
setInterval(loadLinks, 30000);
</script>
</body>
</html>
"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
