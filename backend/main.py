"""
ForenSys Backend — FastAPI server
Collects real system telemetry every 3 seconds, runs threat detection,
and streams results to the Next.js frontend via WebSocket.

Run:  python main.py
      (or: uvicorn main:app --host 0.0.0.0 --port 8000 --reload)
"""

import asyncio
import json
import threading
import time
import os
import hashlib
import secrets
from typing import List

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import pymysql

# Load env variables
load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB", "forensys")

def get_db_connection():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def hash_password(password: str, salt: str) -> str:
    hasher = hashlib.sha256()
    hasher.update((password + salt).encode('utf-8'))
    return hasher.hexdigest()

def generate_salt() -> str:
    return secrets.token_hex(16)

class SetupAdminModel(BaseModel):
    name: str
    email: str
    password: str

class LoginModel(BaseModel):
    email: str
    password: str

class UpdateProfileModel(BaseModel):
    email: str
    name: str

from collectors.logs import get_recent_logs
from collectors.network import get_connections, get_listening_ports, get_arp_devices
from collectors.processes import get_processes
from collectors.system import get_system_metrics
from analyzers.ip_intel import load_blocklist, get_geolocation, is_private_ip, blocklist_size
from analyzers.threat_detector import ThreatDetector

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(title="ForenSys SOC Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared state ──────────────────────────────────────────────────────────────

detector = ThreatDetector()
_clients: List[WebSocket] = []
_latest_snapshot: dict = {}
# Accumulate all alerts across sessions (so frontend always sees history)
_all_alerts: List[dict] = []
# Cumulative network I/O baseline (for delta calculation)
_prev_net_io: dict = {}


# ── Background collection loop ────────────────────────────────────────────────

async def collect_loop() -> None:
    global _latest_snapshot, _prev_net_io

    while True:
        try:
            # 1. Collect raw data
            connections = get_connections()
            metrics = get_system_metrics()
            processes = get_processes()
            logs = get_recent_logs(minutes=3)
            listening = get_listening_ports()
            devices = get_arp_devices()

            # 2. Enrich public IPs with geolocation (cached, non-blocking enough)
            public_ips = {
                c["remote_ip"] for c in connections
                if c.get("remote_ip") and not is_private_ip(c["remote_ip"])
            }
            geo_map: dict = {}
            for ip in list(public_ips)[:20]:   # cap at 20 per cycle to avoid rate limiting
                geo_map[ip] = get_geolocation(ip)

            for conn in connections:
                rip = conn.get("remote_ip", "")
                if not rip:
                    conn["geo"] = {}
                elif is_private_ip(rip):
                    from analyzers.ip_intel import _LAN_GEO
                    conn["geo"] = _LAN_GEO
                else:
                    conn["geo"] = geo_map.get(rip, {"country": "Unknown", "country_code": "XX", "city": "Unknown", "org": "Unknown", "lat": None, "lon": None})

            # 3. Run threat detection
            new_alerts = detector.analyze(connections, processes, logs, listening)
            _all_alerts.extend(new_alerts)
            # Keep last 200 alerts
            if len(_all_alerts) > 200:
                del _all_alerts[:-200]

            # 4. Compute threat level from recent alert severities
            recent = _all_alerts[-50:] if _all_alerts else []
            threat_level = _compute_threat_level(recent)

            # 5. Build snapshot
            snapshot = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "metrics": {
                    **metrics,
                    "threat_level": threat_level,
                    "alerts_total": len(_all_alerts),
                    "blocklist_size": blocklist_size(),
                },
                "connections": connections,
                "processes": processes,
                "logs": logs,
                "new_alerts": new_alerts,
                "all_alerts": _all_alerts[-100:],   # send last 100
                "devices": devices,
                "listening_ports": listening,
            }

            _latest_snapshot = snapshot

            # 6. Broadcast to all WebSocket clients
            if _clients:
                payload = json.dumps(snapshot, default=str)
                dead = []
                for ws in _clients:
                    try:
                        await ws.send_text(payload)
                    except Exception:
                        dead.append(ws)
                for ws in dead:
                    _clients.remove(ws)

        except Exception as e:
            print(f"[collect_loop] Error: {e}")

        await asyncio.sleep(3)


def _compute_threat_level(alerts: List[dict]) -> str:
    if not alerts:
        return "low"
    sevs = [a["severity"] for a in alerts]
    if sevs.count("critical") >= 2 or sevs.count("critical") + sevs.count("high") >= 5:
        return "critical"
    if "critical" in sevs or sevs.count("high") >= 3:
        return "high"
    if "high" in sevs or sevs.count("medium") >= 3:
        return "medium"
    return "low"


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    # Load blocklist in background thread (don't block startup)
    t = threading.Thread(target=load_blocklist, daemon=True)
    t.start()
    # Start collection loop
    asyncio.create_task(collect_loop())
    print("[ForenSys] Backend started — collecting real data on port 8000")


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    _clients.append(ws)
    print(f"[ws] Client connected ({len(_clients)} total)")

    # Send latest snapshot immediately so the UI populates instantly
    if _latest_snapshot:
        await ws.send_text(json.dumps(_latest_snapshot, default=str))

    try:
        while True:
            # Keep connection alive; client sends pings
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in _clients:
            _clients.remove(ws)
        print(f"[ws] Client disconnected ({len(_clients)} remaining)")


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "clients": len(_clients),
        "alerts": len(_all_alerts),
        "blocklist_ips": blocklist_size(),
    }


@app.get("/api/metrics")
def api_metrics():
    return get_system_metrics()


@app.get("/api/connections")
def api_connections():
    return get_connections()


@app.get("/api/processes")
def api_processes():
    return get_processes()


@app.get("/api/logs")
def api_logs():
    return get_recent_logs()


@app.get("/api/alerts")
def api_alerts():
    return _all_alerts


@app.get("/api/devices")
def api_devices():
    return get_arp_devices()


# ── Reports persistence and endpoints ─────────────────────────────────────────

import os

REPORTS_FILE = os.path.join(os.path.dirname(__file__), "reports.json")

def load_reports() -> List[dict]:
    if not os.path.exists(REPORTS_FILE):
        return []
    try:
        with open(REPORTS_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading reports: {e}")
        return []

def save_reports(reports: List[dict]) -> None:
    try:
        with open(REPORTS_FILE, "w") as f:
            json.dump(reports, f, indent=2, default=str)
    except Exception as e:
        print(f"Error saving reports: {e}")

_all_reports = load_reports()


@app.get("/api/reports")
def api_get_reports():
    return _all_reports


@app.post("/api/reports")
def api_create_report(report: dict):
    _all_reports.insert(0, report)  # Insert newest first
    save_reports(_all_reports)
    return report


@app.delete("/api/reports/{report_id}")
def api_delete_report(report_id: str):
    global _all_reports
    _all_reports = [r for r in _all_reports if r.get("id") != report_id]
    save_reports(_all_reports)
    return {"status": "success"}


# ── Settings persistence and endpoints ────────────────────────────────────────

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

DEFAULT_SETTINGS = {
    "notifyOnCritical": True,
    "notifyOnHigh": True,
    "dailySummary": True,
    "criticalThreshold": 90,
    "highThreshold": 70,
    "mediumThreshold": 40,
    "profile": {
        "name": "",
        "email": "",
        "role": ""
    },
    "integrations": [
        {"name": "Emerging Threats Blocklist", "connected": True},
        {"name": "ipapi.co Geolocation", "connected": True},
        {"name": "psutil System Monitor", "connected": True},
        {"name": "macOS Log Stream", "connected": True},
        {"name": "AbuseIPDB (optional)", "connected": False}
    ]
}

def load_settings() -> dict:
    if not os.path.exists(SETTINGS_FILE):
        return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading settings: {e}")
        return DEFAULT_SETTINGS

def save_settings(settings: dict) -> None:
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Error saving settings: {e}")

_current_settings = load_settings()


@app.get("/api/settings")
def api_get_settings():
    return _current_settings


ALL_PERMISSIONS = [
    "view_alerts", "manage_alerts", "view_incidents", "manage_incidents",
    "view_forensics", "export_forensics", "view_analytics", "run_hunt",
    "manage_playbooks", "view_logs", "manage_settings", "manage_users"
]

DEFAULT_PERMISSIONS = {
    "admin": ALL_PERMISSIONS,
    "analyst": ["view_alerts", "manage_alerts", "view_incidents", "manage_incidents", "view_forensics", "view_analytics", "run_hunt", "view_logs"],
    "responder": ["view_alerts", "manage_alerts", "view_incidents", "manage_incidents", "manage_playbooks", "view_logs"],
    "viewer": ["view_alerts", "view_incidents", "view_analytics", "view_logs"]
}


def load_users() -> List[dict]:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users")
            users = cursor.fetchall()
            for u in users:
                try:
                    u["permissions"] = json.loads(u["permissions"])
                except Exception:
                    u["permissions"] = []
            return users
    except Exception as e:
        print(f"Error loading users from DB: {e}")
        return []
    finally:
        conn.close()


@app.post("/api/settings")
def api_save_settings(settings: dict):
    global _current_settings
    _current_settings = settings
    save_settings(_current_settings)
    
    # If a profile name change came in, we can update it in the database
    profile = settings.get("profile")
    if profile and profile.get("email") and profile.get("name"):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET name = %s WHERE email = %s", (profile["name"], profile["email"]))
        except Exception as e:
            print(f"Error syncing profile update to database: {e}")
        finally:
            conn.close()
            
    return _current_settings


@app.get("/api/users")
def api_get_users():
    return load_users()


@app.post("/api/users")
def api_save_user(user: dict):
    user_id = user.get("id")
    role = user.get("role", "viewer")
    department = user.get("department", "Security")
    status = user.get("status", "active")
    name = user.get("name", "")
    email = user.get("email", "")
    password = user.get("password", "") # Optional password field
    
    # Ensure permissions list
    permissions = user.get("permissions")
    if not permissions:
        permissions = DEFAULT_PERMISSIONS.get(role, DEFAULT_PERMISSIONS["viewer"])
    permissions_json = json.dumps(permissions)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_id:
                # Check if user exists
                cursor.execute("SELECT password_hash, salt FROM users WHERE id = %s", (user_id,))
                existing = cursor.fetchone()
                if not existing:
                    # Treat as new if not found
                    user_id = str(int(time.time() * 1000))
                    existing = None
            else:
                existing = None
                user_id = str(int(time.time() * 1000))

            if password:
                salt = generate_salt()
                p_hash = hash_password(password, salt)
            else:
                if existing:
                    p_hash = existing["password_hash"]
                    salt = existing["salt"]
                else:
                    # New user but no password provided? Give a default or require it.
                    salt = generate_salt()
                    p_hash = hash_password("default123", salt)

            if existing:
                cursor.execute("""
                    UPDATE users 
                    SET name = %s, email = %s, role = %s, department = %s, status = %s, permissions = %s, password_hash = %s, salt = %s
                    WHERE id = %s
                """, (name, email, role, department, status, permissions_json, p_hash, salt, user_id))
            else:
                cursor.execute("""
                    INSERT INTO users (id, name, email, role, department, status, permissions, password_hash, salt)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, name, email, role, department, status, permissions_json, p_hash, salt))
            
            # Retrieve the updated user
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE id = %s", (user_id,))
            updated_user = cursor.fetchone()
            if updated_user:
                updated_user["permissions"] = json.loads(updated_user["permissions"])
                return updated_user
            return user
    except Exception as e:
        print(f"Error saving user in DB: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            return {"status": "success"}
    except Exception as e:
        print(f"Error deleting user from DB: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ── Authentication Endpoints ──────────────────────────────────────────────────

@app.get("/api/auth/setup-status")
def api_setup_status():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM users")
            row = cursor.fetchone()
            setup_required = (row["count"] == 0) if row else True
            return {"setup_required": setup_required}
    except Exception as e:
        print(f"Error checking setup status: {e}")
        return {"setup_required": True}
    finally:
        conn.close()


@app.post("/api/auth/setup")
def api_setup(data: SetupAdminModel):
    # Check if table is empty
    status = api_setup_status()
    if not status["setup_required"]:
        raise HTTPException(status_code=400, detail="Initial setup already completed")
    
    # Create the admin user
    user_id = str(int(time.time() * 1000))
    salt = generate_salt()
    p_hash = hash_password(data.password, salt)
    
    role = "admin"
    department = "Security"
    user_status = "active"
    permissions_json = json.dumps(ALL_PERMISSIONS)
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO users (id, name, email, role, department, status, permissions, password_hash, salt)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, data.name, data.email, role, department, user_status, permissions_json, p_hash, salt))
            
            # Retrieve the created user
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if user:
                user["permissions"] = json.loads(user["permissions"])
                return user
            raise HTTPException(status_code=500, detail="Failed to retrieve created admin user")
    except Exception as e:
        print(f"Error bootstrapping admin: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.post("/api/auth/login")
def api_login(data: LoginModel):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, department, status, permissions, password_hash, salt FROM users WHERE email = %s", (data.email,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            if user["status"] != "active":
                raise HTTPException(status_code=401, detail="Account is inactive")
            
            # Verify password
            computed = hash_password(data.password, user["salt"])
            if computed != user["password_hash"]:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Return user details
            user.pop("password_hash")
            user.pop("salt")
            user["permissions"] = json.loads(user["permissions"])
            return user
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.post("/api/auth/update-profile")
def api_update_profile(data: UpdateProfileModel):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET name = %s WHERE email = %s", (data.name, data.email))
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE email = %s", (data.email,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            user["permissions"] = json.loads(user["permissions"])
            return user
    except Exception as e:
        print(f"Error updating profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()




# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
