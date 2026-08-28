"""
Threat detection engine — applies rule-based analysis to real collected data
and generates structured alerts identical to the frontend Alert interface.
"""

import time
import uuid
from collections import defaultdict, deque
from typing import List, Dict, Set

from analyzers.ip_intel import is_private_ip, is_blocklisted, ensure_ipv4

# ── Known C2 / backdoor ports ─────────────────────────────────────────────────
SUSPICIOUS_PORTS: Set[int] = {
    4444,   # Metasploit default listener
    1337,   # Common hacker port
    31337,  # "elite" / Back Orifice
    5555,   # Android Debug Bridge / RATs
    6666, 6667, 6668, 6669,  # IRC — often used for C2 botnets
    9001,   # Tor relay port
    9050, 9051,  # Tor SOCKS proxy
    1080,   # SOCKS proxy
    12345,  # NetBus trojan
    27374,  # SubSeven trojan
    54321,  # Back Orifice 2000
    65535,  # Common malware choice
    7777,   # Generic backdoor
    31338,  # C2 variant
    4899,   # Radmin remote admin
    2222,   # Alternate SSH (flag if unexpected)
    8888,   # Common C2 / coin miner
    3333,   # Litecoin stratum / miners
    14444,  # XMR miner
    45700,  # Mirai botnet
}

# Well-known legitimate ports — don't alert on these even if "high"
WHITELIST_REMOTE_PORTS: Set[int] = {
    80, 443, 53, 22, 25, 587, 465, 993, 995, 143, 110,
    8080, 8443, 3000, 5000, 8000, 8001, 3306, 5432,
    6379, 27017, 2181, 9092, 11211,
}

# MITRE ATT&CK tactic mappings per rule
MITRE: Dict[str, List[str]] = {
    "suspicious_port":  ["Command and Control"],
    "blocklist":        ["Command and Control", "Exfiltration"],
    "port_scan":        ["Discovery", "Reconnaissance"],
    "suspicious_proc":  ["Execution"],
    "auth_fail":        ["Credential Access"],
    "high_resource":    ["Impact"],
    "new_listener":     ["Persistence"],
    "miner":            ["Impact"],
}


class ThreatDetector:
    def __init__(self) -> None:
        # Per-source-IP: deque of connection timestamps (for rate analysis)
        self._conn_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # Per-source-IP: set of remote ports contacted
        self._port_hits: Dict[str, Set[int]] = defaultdict(set)
        # Already-fired alert IDs (prevent duplicate storms)
        self._fired: Set[str] = set()
        # Set of listening ports seen in previous cycle
        self._prev_listeners: Set[int] = set()
        self._initialized_listeners: bool = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(
        self,
        connections: List[Dict],
        processes: List[Dict],
        logs: List[Dict],
        listening_ports: List[Dict] | None = None,
    ) -> List[Dict]:
        """Run all rules and return a list of new alert dicts (may be empty)."""
        alerts: List[Dict] = []
        now = time.time()

        self._rule_connections(connections, now, alerts)
        self._rule_processes(processes, alerts)
        self._rule_logs(logs, now, alerts)
        if listening_ports is not None:
            self._rule_new_listener(listening_ports, alerts)

        return alerts

    # ── Detection rules ────────────────────────────────────────────────────────

    def _rule_connections(self, connections: List[Dict], now: float, out: List[Dict]) -> None:
        for conn in connections:
            rip: str = conn.get("remote_ip", "")
            rport: int = conn.get("remote_port", 0)
            process: str = conn.get("process", "unknown")

            if not rip or is_private_ip(rip):
                continue

            # Track timing and port spread per remote IP
            self._conn_times[rip].append(now)
            self._port_hits[rip].add(rport)

            # Rule 1 — Suspicious remote port
            if rport in SUSPICIOUS_PORTS and rport not in WHITELIST_REMOTE_PORTS:
                rip_v4 = ensure_ipv4(rip)
                aid = f"suspicious-port-{rip_v4}-{rport}"
                if aid not in self._fired:
                    self._fired.add(aid)
                    out.append(self._make(
                        aid="suspicious_port",
                        severity="critical",
                        title=f"Connection to Suspicious Port {rport}",
                        desc=(
                            f"Process '{process}' established a connection to {rip_v4}:{rport}. "
                            f"Port {rport} is associated with malware, C2 frameworks, or backdoors."
                        ),
                        source="Network Monitor",
                        assets=[process, rip_v4],
                    ))

            # Rule 2 — Blocklisted IP
            if is_blocklisted(rip):
                rip_v4 = ensure_ipv4(rip)
                aid = f"blocklist-{rip_v4}"
                if aid not in self._fired:
                    self._fired.add(aid)
                    out.append(self._make(
                        aid="blocklist",
                        severity="high",
                        title=f"Connection to Blocklisted IP: {rip_v4}",
                        desc=(
                            f"Active connection to {rip_v4}:{rport} via process '{process}'. "
                            f"This IP appears on the Emerging Threats blocklist."
                        ),
                        source="Threat Intelligence",
                        assets=[process, rip_v4],
                    ))

        # Rule 3 — Port scan (>15 unique remote ports from one IP)
        for ip, ports in self._port_hits.items():
            if len(ports) > 15:
                ip_v4 = ensure_ipv4(ip)
                aid = f"portscan-{ip_v4}"
                if aid not in self._fired:
                    self._fired.add(aid)
                    out.append(self._make(
                        aid="port_scan",
                        severity="high",
                        title=f"Port Scan Detected from {ip_v4}",
                        desc=(
                            f"IP {ip_v4} has connected to {len(ports)} unique ports "
                            f"({', '.join(str(p) for p in sorted(ports)[:10])}...). "
                            f"Indicative of automated port scanning."
                        ),
                        source="Network Monitor",
                        assets=["localhost", ip_v4],
                    ))


    def _rule_processes(self, processes: List[Dict], out: List[Dict]) -> None:
        # Local Mac processes and background daemons must NOT raise alerts
        for proc in processes:
            proc_name = (proc.get("name") or "").lower()
            # Ignore all local system processes, IDE helpers, and benign applications
            if any(b in proc_name for b in (
                "duetexpertd", "windowserver", "kernel_task", "launchd", "coreaudiod",
                "mds", "node", "python", "language_server", "antigravity", "loginwindow",
                "securityagent", "finder", "dock", "systemuiserver", "controlcenter"
            )):
                continue

            # Only alert on explicit offensive security tool names if flagged as suspicious
            if proc.get("suspicious") and any(tool in proc_name for tool in ("mimikatz", "nmap", "metasploit", "hydra", "john")):
                aid = f"proc-{proc['name']}-{proc.get('pid', 0)}"
                if aid not in self._fired:
                    self._fired.add(aid)
                    out.append(self._make(
                        aid="suspicious_proc",
                        severity="high",
                        title=f"Suspicious Offensive Tool Detected: {proc['name']}",
                        desc=(
                            f"Process '{proc['name']}' (PID {proc.get('pid')}) is a known "
                            f"offensive exploitation tool."
                        ),
                        source="Process Monitor",
                        assets=[proc["name"]],
                    ))

    def _rule_logs(self, logs: List[Dict], now: float, out: List[Dict]) -> None:
        auth_failures = [
            l for l in logs
            if l.get("level") == "error"
            and l.get("process", "") in ("sshd", "sudo", "loginwindow", "SecurityAgent")
            and any(w in l.get("message", "").lower() for w in ("fail", "denied", "invalid"))
        ]
        if len(auth_failures) >= 3:
            aid = f"auth-fail-{int(now // 120)}"
            if aid not in self._fired:
                self._fired.add(aid)
                out.append(self._make(
                    aid="auth_fail",
                    severity="high",
                    title=f"Auth Failure Spike: {len(auth_failures)} Events",
                    desc=(
                        f"Detected {len(auth_failures)} authentication failures in the past 5 minutes "
                        f"across: {', '.join(set(l.get('process','?') for l in auth_failures))}. "
                        f"Possible brute-force attack."
                    ),
                    source="Log Monitor",
                    assets=["auth"],
                ))

    def _rule_new_listener(self, current_listeners: List[Dict], out: List[Dict]) -> None:
        current_ports = {p["port"] for p in current_listeners}
        
        # On the first cycle, baseline the ports currently open without alerting
        if not self._initialized_listeners:
            self._prev_listeners = current_ports
            self._initialized_listeners = True
            return

        new_ports = current_ports - self._prev_listeners
        self._prev_listeners = current_ports

        for port in new_ports:
            if port in WHITELIST_REMOTE_PORTS:
                continue
            proc = next((p["process"] for p in current_listeners if p["port"] == port), "unknown")
            aid = f"new-listener-{port}"
            if aid not in self._fired:
                self._fired.add(aid)
                out.append(self._make(
                    aid="new_listener",
                    severity="medium",
                    title=f"New Listening Port Opened: {port}",
                    desc=(
                        f"Port {port} was not listening in the previous cycle and is now "
                        f"accepting connections (process: '{proc}'). "
                        f"Verify this is expected."
                    ),
                    source="Network Monitor",
                    assets=[proc],
                ))

    # ── Alert factory ──────────────────────────────────────────────────────────

    def _make(self, aid: str, severity: str, title: str, desc: str,
              source: str, assets: List[str]) -> Dict:
        return {
            "id": f"ALT-{uuid.uuid4().hex[:12].upper()}",
            "severity": severity,
            "title": title,
            "description": desc,
            "source": source,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "new",
            "affectedAssets": assets,
            "mitreTactics": MITRE.get(aid, ["Defense Evasion"]),
        }
