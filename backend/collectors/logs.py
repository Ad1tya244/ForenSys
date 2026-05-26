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
        "("
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
