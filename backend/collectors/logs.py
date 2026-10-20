"""
Log collector — reads recent macOS system log events using the `log` CLI.
Falls back gracefully on non-macOS or permission errors.
"""

import collections
import json
import os
import platform
import subprocess
import threading
import time
import hashlib
import re
from typing import List, Dict


def _classify_level(message_type: str, message: str) -> str:
    m_type = message_type.lower()
    
    # If the operating system explicitly classified it as Error/Fault, respect it
    if m_type in ("error", "fault"):
        return "error"
    if m_type in ("info", "debug"):
        return "info"
        
    m = message.lower()
    
    # For Default/unspecified types, only classify as ERROR for strong security violations
    if any(w in m for w in ("denied", "blocked", "unauthorized", "fatal", "critical")):
        return "error"
        
    # Map common default system warnings/errors to WARN (yellow) to avoid polluting the dashboard with ERRORs
    if re.search(r'\b(error|fail|failed|failure|rejected|invalid|exception|warning|warn|timeout|retry)\b', m):
        return "warn"
        
    return "info"


def get_recent_logs(minutes: int = 5) -> List[Dict]:
    """
    On macOS: uses `log show` with a security-focused predicate.
    On Linux: reads /var/log/syslog or /var/log/auth.log tail.
    Returns up to 100 structured log entries.
    """
    if platform.system() == "Darwin":
        return _macos_logs(minutes)
    return _linux_logs()


def _macos_logs(minutes: int) -> List[Dict]:
    predicate = (
        "("
        "(eventMessage CONTAINS[c] 'fail') OR "
        "(eventMessage CONTAINS[c] 'denied') OR "
        "(eventMessage CONTAINS[c] 'invalid') OR "
        "(eventMessage CONTAINS[c] 'blocked') OR "
        "(eventMessage CONTAINS[c] 'unauthorized') OR "
        "(eventMessage CONTAINS[c] 'error') OR "
        "(process BEGINSWITH 'sshd') OR "
        "(process == 'sudo') OR "
        "(process == 'socketfilterfw') OR "
        "(process == 'configd')"
        ") AND NOT ("
        "subsystem CONTAINS 'com.apple.FileProvider' OR "
        "subsystem CONTAINS 'com.apple.CloudDocs' OR "
        "process CONTAINS 'CloudDocs' OR "
        "process CONTAINS 'cloudd' OR "
        "process CONTAINS 'bird'"
        ")"
    )
    try:
        # Request both info and debug logs so we don't only get default/error levels
        result = subprocess.run(
            ["/usr/bin/log", "show", "--last", f"{minutes}m", "--style", "json", "--predicate", predicate, "--info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        raw = json.loads(result.stdout)
        entries: List[Dict] = []
        for i, item in enumerate(raw):
            msg = item.get("eventMessage", "")
            proc_path = item.get("processImagePath", "")
            proc_name = proc_path.split("/")[-1] if proc_path else item.get("process", "system")
            msg_type = item.get("messageType", "Default")
            subsystem = item.get("subsystem", "")

            # Exclude noisy, non-security related macOS logs (e.g. iCloud, FileProvider sync warnings)
            if "com.apple.FileProvider" in subsystem or "com.apple.CloudDocs" in subsystem:
                continue
            if "CloudDocs" in proc_name or "cloudd" in proc_name or "bird" in proc_name:
                continue
            
            trace_id = item.get("traceID", 0)
            timestamp = item.get("timestamp", "")
            unique_id = f"{timestamp}-{trace_id}-{i}"
            
            entries.append(
                {
                    "id": unique_id,
                    "timestamp": timestamp,
                    "process": proc_name,
                    "pid": item.get("processID", 0),
                    "subsystem": subsystem,
                    "message": msg,
                    "category": item.get("category", "system"),
                    "level": _classify_level(msg_type, msg),
                    "source": "macOS System Log",
                }
            )
            if len(entries) >= 100:
                break
        return entries

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, Exception):
        return []


def _linux_logs() -> List[Dict]:
    """Read last N lines of syslog/auth.log on Linux and parse with regex."""
    candidates = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages"]
    syslog_regex = re.compile(
        r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\S+)\s+\S+\s+([^\[:\s]+)(?:\[(\d+)\])?:\s*(.*)$'
    )
    for path in candidates:
        try:
            result = subprocess.run(
                ["tail", "-n", "100", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            entries = []
            for i, line in enumerate(result.stdout.splitlines()):
                if not line.strip():
                    continue
                line_hash = hashlib.md5(line.encode('utf-8')).hexdigest()[:8]
                
                # Default values
                timestamp = ""
                process = "syslog"
                pid = 0
                message = line
                subsystem = ""
                category = "system"
                
                match = syslog_regex.match(line)
                if match:
                    timestamp_str, proc, pid_str, msg = match.groups()
                    timestamp = timestamp_str
                    process = proc
                    if pid_str:
                        try:
                            pid = int(pid_str)
                        except ValueError:
                            pass
                    message = msg
                    subsystem = proc
                
                entries.append(
                    {
                        "id": f"lnx-{i}-{line_hash}",
                        "timestamp": timestamp,
                        "process": process,
                        "pid": pid,
                        "subsystem": subsystem,
                        "message": message,
                        "category": category,
                        "level": _classify_level("Default", message),
                        "source": path,
                    }
                )
            return entries
        except Exception:
            continue
    return []


# ── Real-time authentication log stream ──────────────────────────────────────
# `log show --last 3m` is slow (seconds). SSH brute-force detection instead tails the unified log live
# (`log stream` on macOS, `tail -F` on Linux), so failed logins reach the detection engine within ~1s.

_AUTH_STREAM_PREDICATE = (
    '(process BEGINSWITH "sshd") OR (process == "sudo") OR (process == "su") OR (process == "screensharingd")'
)
_stream_buffer: "collections.deque[Dict]" = collections.deque(maxlen=2000)
_stream_lock = threading.Lock()
_stream_started = False


def drain_auth_stream() -> List[Dict]:
    """Returns (and clears) auth log entries captured live since the last call."""
    with _stream_lock:
        items = list(_stream_buffer)
        _stream_buffer.clear()
    return items


def start_auth_log_stream() -> None:
    global _stream_started
    if _stream_started:
        return
    _stream_started = True
    threading.Thread(target=_auth_stream_supervisor, daemon=True, name="auth-log-stream").start()


def _push_stream_entry(proc: str, message: str, level: str, pid: int = 0, timestamp: str = "") -> None:
    ts = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "id": f"stream-{ts}-{hashlib.md5(message.encode('utf-8', 'ignore')).hexdigest()[:8]}",
        "timestamp": ts, "process": proc, "pid": pid, "subsystem": "", "message": message,
        "category": "auth", "level": level, "source": "Live auth log stream",
    }
    with _stream_lock:
        _stream_buffer.append(entry)


def _auth_stream_supervisor() -> None:
    while True:
        try:
            if platform.system() == "Darwin":
                _macos_stream()
            else:
                _linux_tail()
        except FileNotFoundError:
            return  # tool not available on this host
        except Exception as e:
            print(f"[logs] auth stream error: {e}")
        time.sleep(3)  # restart if the stream process exits


def _macos_stream() -> None:
    proc = subprocess.Popen(
        ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", _AUTH_STREAM_PREDICATE],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    print("[logs] Live auth log stream started (sshd / sudo / screensharingd).")
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = item.get("eventMessage", "")
        if not msg:
            continue
        path = item.get("processImagePath", "")
        name = path.split("/")[-1] if path else item.get("process", "unknown")
        _push_stream_entry(name, msg, _classify_level(item.get("messageType", "Default"), msg),
                           item.get("processID", 0), item.get("timestamp", ""))
    proc.wait()


def _linux_tail() -> None:
    path = next((p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p)), None)
    if not path:
        raise FileNotFoundError
    rx = re.compile(r'^\S+\s+\S+\s+\S+\s+\S+\s+([^\[:\s]+)(?:\[(\d+)\])?:\s*(.*)$|^\S+\s+\S+\s+([^\[:\s]+)(?:\[(\d+)\])?:\s*(.*)$')
    proc = subprocess.Popen(["tail", "-n", "0", "-F", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    print(f"[logs] Live auth log tail started ({path}).")
    assert proc.stdout is not None
    for line in proc.stdout:
        m = rx.match(line.strip())
        if not m:
            continue
        name = m.group(1) or m.group(4) or "unknown"
        pid = int(m.group(2) or m.group(5) or 0)
        msg = m.group(3) or m.group(6) or ""
        _push_stream_entry(name, msg, _classify_level("Default", msg), pid)
    proc.wait()
