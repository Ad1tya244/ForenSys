"""
ForenSys Asset Trust Manager & Self-Protection Layer
Prevents the platform from detecting, alerting, escalating, or remediating its own components,
processes, project directories, and internal loopback IPC traffic while preserving full
external threat detection capabilities.
"""

import os
import sys
import time
import uuid
import psutil
from typing import Dict, Any, List, Optional, Tuple, Set

# Dynamically detect project root directory at runtime (do not hardcode)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

TRUSTED_PROCESS_NAMES = {
    "python", "python3", "node", "npm", "npx", "uvicorn", "mysqld", "mariadbd",
    "scapy", "next-server", "ts-node", "gunicorn", "pcap"
}

TRUSTED_PORTS = {8000, 3000, 3001, 3306, 5173}

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

TRUSTED_CMD_KEYWORDS = {
    "main.py", "start-dev.js", "next", "uvicorn", "simulate_attacks.py", "ForenSys"
}

class AssetTrustManager:
    def __init__(self) -> None:
        self.project_root = PROJECT_ROOT
        self.registered_pids: Set[int] = set()
        self.local_ips: Set[str] = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
        self.audit_log: List[Dict[str, Any]] = []
        
        # Discover local host interface IPs
        self._discover_local_host_ips()

        # Register current process PID and parent PID automatically
        self.register_pid(os.getpid())
        try:
            self.register_pid(os.getppid())
        except Exception:
            pass
        
        # Scan and register all child processes of current process
        self._discover_local_forensys_pids()

    def _discover_local_host_ips(self) -> None:
        """Discovers all local network interface IP addresses of the host machine."""
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address:
                        clean_addr = addr.address.split('%')[0]
                        self.local_ips.add(clean_addr)
        except Exception:
            pass
        try:
            import socket
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                self.local_ips.add(ip)
        except Exception:
            pass

    def get_primary_host_ip(self) -> str:
        """Finds the primary non-loopback IPv4 address assigned to this device."""
        try:
            import socket
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return addr.address
        except Exception:
            pass
        for ip in self.local_ips:
            if not ip.startswith("127.") and not ip.startswith("fe80") and "." in ip and ip != "0.0.0.0":
                return ip
        return "127.0.0.1"

    def _discover_local_forensys_pids(self) -> None:
        """Discovers running processes belonging to ForenSys based on directory & cmdline."""
        try:
            current_proc = psutil.Process(os.getpid())
            for child in current_proc.children(recursive=True):
                self.registered_pids.add(child.pid)
        except Exception:
            pass

        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cwd']):
                try:
                    pinfo = proc.info
                    exe = pinfo.get('exe') or ''
                    cwd = pinfo.get('cwd') or ''
                    cmdline = " ".join(pinfo.get('cmdline') or [])
                    
                    if (self.project_root in exe or 
                        self.project_root in cwd or 
                        self.project_root in cmdline or
                        any(kw in cmdline for kw in TRUSTED_CMD_KEYWORDS)):
                        self.registered_pids.add(pinfo['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

    def register_pid(self, pid: int) -> None:
        if pid and pid > 0:
            self.registered_pids.add(pid)

    def unregister_pid(self, pid: int) -> None:
        self.registered_pids.discard(pid)

    def is_trusted_event(self, event: Dict[str, Any], config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Determines whether a telemetry event originates from a trusted ForenSys platform component.
        Returns (is_trusted, reason_string).
        """
        # If attack simulation mode is explicitly enabled, bypass self-protection filtering
        if config.get("attack_simulation_mode", False):
            return False, None

        event_type = event.get("event_type")
        pid = event.get("pid")
        process_name = (event.get("process") or "").lower()
        src_ip = event.get("src_ip") or event.get("local_ip") or ""
        dst_ip = event.get("dst_ip") or event.get("remote_ip") or ""
        src_port = event.get("src_port") or event.get("local_port")
        dst_port = event.get("dst_port") or event.get("remote_port")
        details = str(event.get("details") or "").lower()
        path = str(event.get("path") or "").lower()

        is_src_loopback = (src_ip in LOOPBACK_HOSTS) or src_ip.startswith("127.")
        is_dst_loopback = (dst_ip in LOOPBACK_HOSTS) or dst_ip.startswith("127.")

        # Dedicated rule for raw network packets off the wire
        if event_type == "PACKET":
            if is_src_loopback and is_dst_loopback and (src_port in TRUSTED_PORTS or dst_port in TRUSTED_PORTS):
                return True, f"Internal Loopback IPC packet on port {src_port or dst_port}"
            return False, None

        # Indicator 1: Registered PID ownership
        if pid in self.registered_pids:
            return True, f"Trusted ForenSys Process PID ({pid})"

        # Indicator 2: Project Root Path in binary/event details
        if self.project_root.lower() in path or self.project_root.lower() in details:
            return True, f"Originates within ForenSys project directory ({self.project_root})"

        # Indicator 3: Internal Loopback IPC & ForenSys Listening Ports
        if is_src_loopback and is_dst_loopback:
            if process_name in TRUSTED_PROCESS_NAMES or (src_port in TRUSTED_PORTS or dst_port in TRUSTED_PORTS):
                return True, f"Internal Loopback IPC between ForenSys services ({src_ip}:{src_port} -> {dst_ip}:{dst_port})"
            if process_name in ("nmap", "curl", "python3") and any(kw in details for kw in ("simulate", "test")):
                return False, None
            return True, f"Self-generated loopback activity ({src_ip} -> {dst_ip})"

        # Indicator 4: Process Name + ForenSys Port / Path indicator
        if process_name in TRUSTED_PROCESS_NAMES:
            if (src_port in TRUSTED_PORTS or dst_port in TRUSTED_PORTS) and (is_src_loopback or is_dst_loopback):
                return True, f"ForenSys Service Process ({process_name}) on port {src_port or dst_port}"

        return False, None

    def log_ignored_event(self, event: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Records an ignored trusted event in the Self-Protection Audit Log."""
        entry = {
            "id": f"AUD-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "process": event.get("process") or "ForenSys Core Component",
            "pid": event.get("pid"),
            "src_ip": event.get("src_ip") or event.get("local_ip") or "127.0.0.1",
            "dst_ip": event.get("dst_ip") or event.get("remote_ip") or "127.0.0.1",
            "reason": reason,
            "status": "Ignored (Trusted Internal Activity)",
            "incidentCreated": False,
            "remediationExecuted": False,
        }
        self.audit_log.append(entry)
        if len(self.audit_log) > 200:
            self.audit_log = self.audit_log[-200:]
        return entry

    def is_trusted_remediation_target(self, action_type: str, target: str, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Safety Net: Checks if a proposed SOAR remediation action targets a trusted ForenSys asset.
        Returns (is_trusted, cancel_reason).
        """
        # Hard Safeguard: Never kill current main backend PID or delete project root regardless of mode
        if action_type == "kill_process":
            try:
                target_pid = int(target)
                if target_pid == os.getpid() or target_pid in self.registered_pids:
                    return True, "Skipped due to trusted asset (Protected ForenSys Process PID)."
            except ValueError:
                pass
            if target.lower() in TRUSTED_PROCESS_NAMES or "main.py" in target.lower() or "uvicorn" in target.lower():
                return True, f"Skipped due to trusted asset (Protected Process '{target}')."

        if action_type in ("block_ip", "add_pf_rule", "disable_interface"):
            if target in LOOPBACK_HOSTS or target.startswith("127.") or target in self.local_ips:
                return True, f"Skipped due to trusted asset (Protected Local Host Interface IP '{target}')."

        if action_type == "quarantine_executable":
            if self.project_root.lower() in target.lower():
                return True, f"Skipped due to trusted asset (Protected Project Directory Path '{target}')."

        # General check for loopback / project paths if attack simulation mode is false
        if not config.get("attack_simulation_mode", False):
            if target in LOOPBACK_HOSTS or target.startswith("127."):
                return True, f"Skipped due to trusted asset (Protected Loopback Target '{target}')."

        return False, None

# Singleton instance
asset_trust_manager = AssetTrustManager()

def get_primary_host_ip() -> str:
    return asset_trust_manager.get_primary_host_ip()
