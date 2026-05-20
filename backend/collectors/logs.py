"""
Log collector — reads recent macOS system log events using the `log` CLI.
Falls back gracefully on non-macOS or permission errors.
"""

import json
import platform
import subprocess
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
        "(eventMessage CONTAINS[c] 'fail') OR "
        "(eventMessage CONTAINS[c] 'denied') OR "
        "(eventMessage CONTAINS[c] 'invalid') OR "
        "(eventMessage CONTAINS[c] 'blocked') OR "
        "(eventMessage CONTAINS[c] 'unauthorized') OR "
        "(eventMessage CONTAINS[c] 'error') OR "
        "(process == 'sshd') OR "
        "(process == 'sudo') OR "
        "(process == 'socketfilterfw') OR "
        "(process == 'configd')"
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
        for i, item in enumerate(raw[:100]):
            msg = item.get("eventMessage", "")
            proc_path = item.get("processImagePath", "")
            proc_name = proc_path.split("/")[-1] if proc_path else item.get("process", "system")
            msg_type = item.get("messageType", "Default")
            
            trace_id = item.get("traceID", 0)
            timestamp = item.get("timestamp", "")
            unique_id = f"{timestamp}-{trace_id}-{i}"
            
            entries.append(
                {
                    "id": unique_id,
                    "timestamp": timestamp,
                    "process": proc_name,
                    "message": msg,
                    "category": item.get("category", "system"),
                    "level": _classify_level(msg_type, msg),
                    "source": "macOS System Log",
                }
            )
        return entries

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, Exception):
        return []


def _linux_logs() -> List[Dict]:
    """Read last N lines of syslog/auth.log on Linux."""
    candidates = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages"]
    for path in candidates:
        try:
            result = subprocess.run(
                ["tail", "-n", "100", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            entries = []
            for i, line in enumerate(result.stdout.splitlines()):
                line_hash = hashlib.md5(line.encode('utf-8')).hexdigest()[:8]
                entries.append(
                    {
                        "id": f"lnx-{i}-{line_hash}",
                        "timestamp": "",
                        "process": "syslog",
                        "message": line,
                        "category": "system",
                        "level": _classify_level("Default", line),
                        "source": path,
                    }
                )
            return entries
        except Exception:
            continue
    return []
