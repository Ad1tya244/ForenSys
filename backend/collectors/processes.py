"""
Process collector — enumerates running processes and flags anomalies.
"""

import psutil
from typing import List, Dict

# Known offensive security / exploit tools — flag if seen running
SUSPICIOUS_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan",
    "msfconsole", "msfvenom", "msf", "metasploit",
    "hydra", "john", "hashcat", "sqlmap", "nikto",
    "wifite", "aircrack-ng", "airodump-ng",
    "beef", "empire", "covenant", "cobaltstrike",
    "mimikatz", "lazagne", "responder",
    "reverse_shell", "shell.py",
}

# Thresholds for flagging high resource usage
HIGH_CPU_PCT = 80.0
HIGH_MEM_PCT = 40.0


def get_processes() -> List[Dict]:
    procs: List[Dict] = []

    attrs = ["pid", "name", "cpu_percent", "memory_percent", "status", "username"]

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            name_lower = (info.get("name") or "").lower()
            cpu = round(info.get("cpu_percent") or 0.0, 1)
            mem = round(info.get("memory_percent") or 0.0, 2)

            is_suspicious = name_lower in SUSPICIOUS_NAMES
            is_high_resource = cpu > HIGH_CPU_PCT or mem > HIGH_MEM_PCT

            procs.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name") or "unknown",
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "status": info.get("status") or "unknown",
                    "username": info.get("username") or "unknown",
                    "suspicious": is_suspicious,
                    "high_resource": is_high_resource,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Return top 50 by CPU usage
    return sorted(procs, key=lambda p: p["cpu_percent"], reverse=True)[:50]
