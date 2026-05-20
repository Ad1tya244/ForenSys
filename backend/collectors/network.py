"""
Network collector — reads real TCP/UDP connections from the host via psutil.
Falls back to parsing `netstat -an` output if psutil is denied access.
"""

import socket
import subprocess
import psutil
from typing import List, Dict, Optional


def _proc_name(pid: Optional[int]) -> str:
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "unknown"


def get_connections() -> List[Dict]:
    """Return all active (non-LISTEN) TCP/UDP connections with process info."""
    results: List[Dict] = []
    seen: set = set()

    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return _fallback_lsof()

    for conn in raw:
        # Only ESTABLISHED / connections that have a remote address
        if not conn.raddr:
            continue

        key = (conn.laddr, conn.raddr)
        if key in seen:
            continue
        seen.add(key)

        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        results.append(
            {
                "id": f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}",
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "status": conn.status or "NONE",
                "pid": conn.pid,
                "process": _proc_name(conn.pid),
                "protocol": proto,
            }
        )

    return results


def get_listening_ports() -> List[Dict]:
    """Return all locally listening ports with associated process."""
    ports: List[Dict] = []
    seen_ports = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                ports.append(
                    {
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "process": _proc_name(conn.pid),
                        "pid": conn.pid,
                    }
                )
    except psutil.AccessDenied:
        # Fallback to lsof for listening ports
        try:
            out = subprocess.check_output(["lsof", "-i", "-P", "-n"], text=True, timeout=5)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                if "(LISTEN)" not in parts[8]:
                    continue
                
                process = parts[0]
                try:
                    pid = int(parts[1])
                except ValueError:
                    pid = None
                
                addr = parts[8].split(" (LISTEN)")[0]
                try:
                    ip, port = addr.rsplit(":", 1)
                    ip = ip.strip("[]")
                    port_int = int(port)
                    
                    key = (ip, port_int)
                    if key in seen_ports:
                        continue
                    seen_ports.add(key)
                    
                    ports.append({
                        "port": port_int,
                        "ip": ip,
                        "process": process,
                        "pid": pid,
                    })
                except (ValueError, IndexError):
                    continue
        except Exception:
            pass
    return ports


def _fallback_lsof() -> List[Dict]:
    """Parse `lsof -i -P -n` when psutil access is denied on macOS."""
    results: List[Dict] = []
    seen = set()
    try:
        out = subprocess.check_output(["lsof", "-i", "-P", "-n"], text=True, timeout=5)
        lines = out.splitlines()
        if not lines:
            return []
        
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            
            process = parts[0]
            try:
                pid = int(parts[1])
            except ValueError:
                pid = None
            
            protocol = parts[7].upper()  # TCP or UDP
            name_col = parts[8]
            
            if "->" not in name_col:
                continue
            
            local_part, remote_part = name_col.split("->", 1)
            
            status = "ESTABLISHED"
            if " " in remote_part:
                remote_addr, status_raw = remote_part.split(" ", 1)
                status = status_raw.strip("()")
            else:
                remote_addr = remote_part
            
            try:
                lip, lport = local_part.rsplit(":", 1)
                rip, rport = remote_addr.rsplit(":", 1)
                
                lip = lip.strip("[]")
                rip = rip.strip("[]")
                
                key = (lip, int(lport), rip, int(rport))
                if key in seen:
                    continue
                seen.add(key)
                
                results.append({
                    "id": f"{lip}:{lport}-{rip}:{rport}",
                    "local_ip": lip,
                    "local_port": int(lport),
                    "remote_ip": rip,
                    "remote_port": int(rport),
                    "status": status,
                    "pid": pid,
                    "process": process,
                    "protocol": protocol,
                })
            except (ValueError, IndexError):
                continue
    except Exception as e:
        print(f"[_fallback_lsof] Error: {e}")
        return _fallback_netstat()
    return results


def _fallback_netstat() -> List[Dict]:
    """Parse `netstat -an` when psutil access is denied."""
    results: List[Dict] = []
    try:
        out = subprocess.check_output(["netstat", "-an"], text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            if parts[0] not in ("tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"):
                continue
            state = parts[5] if len(parts) > 5 else ""
            if state not in ("ESTABLISHED",):
                continue
            local = parts[3]
            remote = parts[4]
            try:
                lip, lport = local.rsplit(".", 1)
                rip, rport = remote.rsplit(".", 1)
                results.append(
                    {
                        "id": f"{local}-{remote}",
                        "local_ip": lip,
                        "local_port": int(lport),
                        "remote_ip": rip,
                        "remote_port": int(rport),
                        "status": state,
                        "pid": None,
                        "process": "unknown",
                        "protocol": parts[0].upper()[:3],
                    }
                )
            except (ValueError, IndexError):
                continue
    except Exception:
        pass
    return results


def get_arp_devices() -> List[Dict]:
    """Discover devices on the local network via the ARP table."""
    devices: List[Dict] = []
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        for line in out.splitlines():
            # macOS format: hostname (ip) at mac on iface
            parts = line.split()
            if len(parts) < 4:
                continue
            hostname = parts[0]
            ip = parts[1].strip("()")
            mac = parts[3] if parts[3] != "(incomplete)" else "unknown"
            iface = parts[-1] if "en" in parts[-1] else "unknown"
            devices.append(
                {"hostname": hostname, "ip": ip, "mac": mac, "interface": iface}
            )
    except Exception:
        pass
    return devices
