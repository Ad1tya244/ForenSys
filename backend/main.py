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
import secrets
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import pymysql

from auth_utils import (
    hash_password_bcrypt,
    verify_and_migrate_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    REFRESH_TOKEN_EXPIRE_DAYS
)
from schemas import (
    SetupAdminModel,
    LoginModel,
    UpdateProfileModel,
    UserSaveModel,
    ReportCreateModel,
    SettingsSaveModel,
    RuleSaveModel
)

# Load env variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

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

security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            if user["status"] != "active":
                raise HTTPException(status_code=401, detail="Account is inactive")
            user["permissions"] = json.loads(user["permissions"])
            return user
    finally:
        conn.close()

def check_permissions(required_permission: str):
    def dependency(current_user: dict = Depends(get_current_user)):
        if required_permission not in current_user.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {required_permission}"
            )
        return current_user
    return dependency

from collectors.logs import get_recent_logs
from collectors.network import get_connections, get_listening_ports, get_arp_devices
from collectors.processes import get_processes
from collectors.system import get_system_metrics
from collectors.traffic import start_traffic_sniffer, get_recent_traffic_packets
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

# SOAR Automation Rules Storage
RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")

DEFAULT_RULES = [
  {
    "id": "1",
    "name": "Auto-Isolate Ransomware Host",
    "description": "Automatically quarantine endpoints showing ransomware-like behavior",
    "trigger": "Malware Detection: Ransomware pattern",
    "action": "Isolate endpoint via EDR API + notify SOC team",
    "severity": "critical",
    "enabled": True,
    "lastFired": None,
    "firedCount": 0,
    "category": "containment",
  },
  {
    "id": "2",
    "name": "Critical Alert → PagerDuty",
    "description": "Page on-call analyst for any critical severity alert",
    "trigger": "Alert severity == CRITICAL",
    "action": "POST to PagerDuty API → create incident",
    "severity": "critical",
    "enabled": True,
    "lastFired": None,
    "firedCount": 0,
    "category": "notification",
  },
  {
    "id": "3",
    "name": "IP Reputation Enrichment",
    "description": "Auto-enrich any external IP with VirusTotal + AbuseIPDB",
    "trigger": "New alert with external IP indicator",
    "action": "Query threat intel APIs → attach to alert",
    "severity": "any",
    "enabled": True,
    "lastFired": None,
    "firedCount": 0,
    "category": "enrichment",
  },
  {
    "id": "4",
    "name": "ServiceNow Ticket Creation",
    "description": "Create ITSM ticket for high+ incidents requiring change management",
    "trigger": "Incident severity >= HIGH AND status == open",
    "action": "Create ServiceNow change request via REST API",
    "severity": "high",
    "enabled": True,
    "lastFired": None,
    "firedCount": 0,
    "category": "ticketing",
  },
  {
    "id": "5",
    "name": "Block C2 IP at Firewall",
    "description": "Automatically block confirmed C2 IPs at perimeter firewall",
    "trigger": "C2 IOC confirmed with confidence >= 85%",
    "action": "Push block rule to Palo Alto via API",
    "severity": "critical",
    "enabled": False,
    "lastFired": None,
    "firedCount": 0,
    "category": "containment",
  },
  {
    "id": "6",
    "name": "Slack SOC Digest",
    "description": "Post hourly summary of new alerts to #soc-alerts Slack channel",
    "trigger": "Scheduled: every 60 minutes",
    "action": "POST alert summary to Slack webhook",
    "severity": "any",
    "enabled": True,
    "lastFired": None,
    "firedCount": 0,
    "category": "notification",
  }
]

def load_rules() -> List[dict]:
    if not os.path.exists(RULES_FILE):
        return DEFAULT_RULES
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            # Ensure timestamps are loaded as strings
            return data
    except Exception as e:
        print(f"Error loading rules: {e}")
        return DEFAULT_RULES

def save_rules(rules: List[dict]) -> None:
    try:
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=2)
    except Exception as e:
        print(f"Error saving rules: {e}")


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
            
            # Check automation rules on new alerts
            if new_alerts:
                try:
                    rules = load_rules()
                    rules_changed = False
                    for alert in new_alerts:
                        for rule in rules:
                            if not rule.get("enabled", True):
                                continue
                            
                            # Matches by severity
                            sev = rule.get("severity", "any")
                            severity_match = (sev == "any") or (sev == alert.get("severity"))
                            
                            # Heuristic matching by trigger description & alert details
                            trigger_lower = rule.get("trigger", "").lower()
                            title_lower = alert.get("title", "").lower()
                            desc_lower = alert.get("description", "").lower()
                            
                            trigger_match = False
                            if "ransomware" in trigger_lower and "ransomware" in title_lower:
                                trigger_match = True
                            elif "c2" in trigger_lower and ("c2" in title_lower or "c2" in desc_lower or "blocklist" in title_lower):
                                trigger_match = True
                            elif "severity == critical" in trigger_lower and alert.get("severity") == "critical":
                                trigger_match = True
                            elif "external ip" in trigger_lower and any(not is_private_ip(asset) for asset in alert.get("affectedAssets", [])):
                                trigger_match = True
                            elif rule.get("severity") == alert.get("severity") and rule.get("severity") != "any":
                                trigger_match = True
                            
                            if severity_match and trigger_match:
                                rule["firedCount"] = rule.get("firedCount", 0) + 1
                                rule["lastFired"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                rules_changed = True
                                print(f"[SOAR Rule Fired] Rule '{rule.get('name')}' triggered by alert '{alert.get('title')}'")
                    if rules_changed:
                        save_rules(rules)
                except Exception as ex:
                    print(f"Error executing SOAR automation rules: {ex}")

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
                "network_traffic": get_recent_traffic_packets(),
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
    # Start traffic sniffer background thread
    start_traffic_sniffer()
    # Start collection loop
    asyncio.create_task(collect_loop())
    print("[ForenSys] Backend started — collecting real data on port 8000")


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4003)
        return
        
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        await ws.close(code=4003)
        return
        
    user_id = payload.get("sub")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT status FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user or user["status"] != "active":
                await ws.close(code=4003)
                return
    except Exception:
        await ws.close(code=4003)
        return
    finally:
        conn.close()

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
def api_metrics(current_user: dict = Depends(check_permissions("view_analytics"))):
    return get_system_metrics()


@app.get("/api/connections")
def api_connections(current_user: dict = Depends(check_permissions("view_forensics"))):
    return get_connections()


@app.get("/api/processes")
def api_processes(current_user: dict = Depends(check_permissions("view_forensics"))):
    return get_processes()


@app.get("/api/logs")
def api_logs(current_user: dict = Depends(check_permissions("view_logs"))):
    return get_recent_logs()


@app.get("/api/alerts")
def api_alerts(current_user: dict = Depends(check_permissions("view_alerts"))):
    return _all_alerts


@app.get("/api/devices")
def api_devices(current_user: dict = Depends(check_permissions("view_forensics"))):
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
def api_get_reports(current_user: dict = Depends(check_permissions("view_analytics"))):
    return _all_reports


@app.post("/api/reports")
def api_create_report(report: ReportCreateModel, current_user: dict = Depends(check_permissions("export_forensics"))):
    report_dict = report.model_dump()
    _all_reports.insert(0, report_dict)  # Insert newest first
    save_reports(_all_reports)
    return report_dict


@app.delete("/api/reports/{report_id}")
def api_delete_report(report_id: str, current_user: dict = Depends(check_permissions("export_forensics"))):
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
def api_get_settings(current_user: dict = Depends(check_permissions("manage_settings"))):
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
def api_save_settings(settings: SettingsSaveModel, current_user: dict = Depends(check_permissions("manage_settings"))):
    global _current_settings
    settings_dict = settings.model_dump()
    _current_settings = settings_dict
    save_settings(_current_settings)
    
    # If a profile name change came in, we can update it in the database
    profile = settings_dict.get("profile")
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
def api_get_users(current_user: dict = Depends(check_permissions("manage_users"))):
    return load_users()


@app.post("/api/users")
def api_save_user(user: UserSaveModel, current_user: dict = Depends(check_permissions("manage_users"))):
    user_id = user.id
    role = user.role
    department = user.department
    status = user.status
    name = user.name
    email = user.email
    password = user.password # Optional password field
    
    # Ensure permissions list
    permissions = user.permissions
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
                p_hash = hash_password_bcrypt(password)
                salt = ""
            else:
                if existing:
                    p_hash = existing["password_hash"]
                    salt = existing["salt"]
                else:
                    # New user but no password provided? Give a default or require it.
                    p_hash = hash_password_bcrypt("default123")
                    salt = ""

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
            return user.model_dump()
    except Exception as e:
        print(f"Error saving user in DB: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: str, current_user: dict = Depends(check_permissions("manage_users"))):
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
def api_setup(data: SetupAdminModel, response: Response):
    # Check if table is empty
    status = api_setup_status()
    if not status["setup_required"]:
        raise HTTPException(status_code=400, detail="Initial setup already completed")
    
    # Create the admin user
    user_id = str(int(time.time() * 1000))
    p_hash = hash_password_bcrypt(data.password)
    
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
            """, (user_id, data.name, data.email, role, department, user_status, permissions_json, p_hash, ""))
            
            # Retrieve the created user
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if user:
                user["permissions"] = json.loads(user["permissions"])
                
                # Generate tokens
                access_token = create_access_token(data={"sub": user["id"], "email": user["email"]})
                refresh_token = create_refresh_token(data={"sub": user["id"], "email": user["email"]})
                
                # Set cookie
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    httponly=True,
                    secure=False,  # Set to True if HTTPS in prod
                    samesite="lax",
                    max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                )
                
                return {
                    "access_token": access_token,
                    "user": user
                }
            raise HTTPException(status_code=500, detail="Failed to retrieve created admin user")
    except Exception as e:
        print(f"Error bootstrapping admin: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.post("/api/auth/login")
def api_login(data: LoginModel, response: Response):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, department, status, permissions, password_hash, salt FROM users WHERE email = %s", (data.email,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            if user["status"] != "active":
                raise HTTPException(status_code=401, detail="Account is inactive")
            
            # Verify password and migrate if legacy sha256
            matched, new_hash = verify_and_migrate_password(data.password, user["password_hash"], user["salt"])
            if not matched:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Save upgraded hash
            if new_hash:
                try:
                    cursor.execute("UPDATE users SET password_hash = %s, salt = '' WHERE id = %s", (new_hash, user["id"]))
                except Exception as e:
                    print(f"Failed to migrate password hash for user {user['id']}: {e}")
            
            # Generate tokens
            access_token = create_access_token(data={"sub": user["id"], "email": user["email"]})
            refresh_token = create_refresh_token(data={"sub": user["id"], "email": user["email"]})
            
            # Set cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            )
            
            # Return user details without sensitive fields
            user.pop("password_hash")
            user.pop("salt")
            user["permissions"] = json.loads(user["permissions"])
            
            return {
                "access_token": access_token,
                "user": user
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.post("/api/auth/refresh")
def api_refresh(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
        
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
    user_id = payload.get("sub")
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, role, department, status, permissions FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user or user["status"] != "active":
                raise HTTPException(status_code=401, detail="User inactive or not found")
                
            user["permissions"] = json.loads(user["permissions"])
            
            # Generate new tokens
            access_token = create_access_token(data={"sub": user["id"], "email": user["email"]})
            new_refresh_token = create_refresh_token(data={"sub": user["id"], "email": user["email"]})
            
            # Reset cookie
            response.set_cookie(
                key="refresh_token",
                value=new_refresh_token,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            )
            
            return {
                "access_token": access_token,
                "user": user
            }
    finally:
        conn.close()


@app.post("/api/auth/logout")
def api_logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"status": "success"}


@app.post("/api/auth/update-profile")
def api_update_profile(data: UpdateProfileModel, current_user: dict = Depends(get_current_user)):
    if current_user["email"] != data.email and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to update this profile")
        
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


@app.get("/api/rules")
def api_get_rules(current_user: dict = Depends(get_current_user)):
    return load_rules()


@app.post("/api/rules")
def api_save_rule(rule: RuleSaveModel, current_user: dict = Depends(get_current_user)):
    if "manage_playbooks" not in current_user["permissions"] and current_user["role"] != "admin":
         raise HTTPException(status_code=403, detail="Not authorized to configure automation rules")
    
    rules = load_rules()
    rule_dict = rule.model_dump()
    
    existing_idx = next((i for i, r in enumerate(rules) if r["id"] == rule_dict["id"]), -1)
    if existing_idx >= 0:
        rules[existing_idx] = rule_dict
    else:
        rules.insert(0, rule_dict)
        
    save_rules(rules)
    return rule_dict


@app.delete("/api/rules/{rule_id}")
def api_delete_rule(rule_id: str, current_user: dict = Depends(get_current_user)):
    if "manage_playbooks" not in current_user["permissions"] and current_user["role"] != "admin":
         raise HTTPException(status_code=403, detail="Not authorized to configure automation rules")
         
    rules = load_rules()
    rules = [r for r in rules if r["id"] != rule_id]
    save_rules(rules)
    return {"status": "success"}


@app.post("/api/rules/{rule_id}/trigger")
def api_trigger_rule(rule_id: str, current_user: dict = Depends(get_current_user)):
    rules = load_rules()
    for r in rules:
        if r["id"] == rule_id:
            r["firedCount"] = r.get("firedCount", 0) + 1
            r["lastFired"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save_rules(rules)
            return r
    raise HTTPException(status_code=404, detail="Rule not found")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
