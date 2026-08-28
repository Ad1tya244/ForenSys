"""
IP intelligence — geolocation via ipapi.co and blocklist matching
from the Emerging Threats IP blocklist (loaded at startup).
No API key required.
"""

import ipaddress
import threading
import requests
from functools import lru_cache
from typing import Dict, Set

# ── Blocklist ─────────────────────────────────────────────────────────────────
BLOCKLIST_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

_blocklist: Set[str] = set()
_blocklist_lock = threading.Lock()
_blocklist_loaded = False


def load_blocklist() -> None:
    """Download the Emerging Threats IP blocklist. Called once at startup."""
    global _blocklist_loaded
    try:
        resp = requests.get(BLOCKLIST_URL, timeout=15)
        ips: Set[str] = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
        with _blocklist_lock:
            _blocklist.update(ips)
        _blocklist_loaded = True
        print(f"[ip_intel] Blocklist loaded: {len(_blocklist)} IPs")
    except Exception as e:
        print(f"[ip_intel] Blocklist load failed: {e}")


def is_blocklisted(ip: str) -> bool:
    with _blocklist_lock:
        return ip in _blocklist


def blocklist_size() -> int:
    with _blocklist_lock:
        return len(_blocklist)


# ── Private IP check ──────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Return True for loopback, link-local, and RFC-1918 addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # Treat unparseable IPs as private/safe


# ── Geolocation ───────────────────────────────────────────────────────────────

_LAN_GEO = {
    "country": "Local Network",
    "country_code": "LAN",
    "city": "LAN",
    "org": "Private Network",
    "lat": None,
    "lon": None,
}


@lru_cache(maxsize=1000)
def get_geolocation(ip: str) -> Dict:
    """
    Resolve IP → country/city/org using ipapi.co (free, no key, 1000 req/day).
    Results are cached per IP for the lifetime of the process.
    """
    if is_private_ip(ip):
        return _LAN_GEO

    try:
        resp = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5,
            headers={"User-Agent": "ForenSys-SOC/1.0"},
        )
        data = resp.json()
        if data.get("error"):
            return {"country": "Unknown", "country_code": "XX", "city": "Unknown", "org": "Unknown", "lat": None, "lon": None}
        return {
            "country": data.get("country_name", "Unknown"),
            "country_code": data.get("country_code", "XX"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
        }
    except Exception:
        return {"country": "Unknown", "country_code": "XX", "city": "Unknown", "org": "Unknown", "lat": None, "lon": None}


def ensure_ipv4(ip_str: str) -> str:
    """If ip_str is a valid IPv6 address, convert it deterministically to a valid IPv4 address."""
    if not ip_str:
        return ip_str
    # Strip brackets if present (e.g. [2401:4900:...])
    ip_str_clean = ip_str.strip().strip("[]")
    try:
        addr = ipaddress.ip_address(ip_str_clean)
        if addr.version == 4:
            return ip_str
        elif addr.version == 6:
            ipv4_mapped = addr.ipv4_mapped
            if ipv4_mapped:
                return str(ipv4_mapped)
            # Hash to deterministic IPv4 address
            import hashlib
            h = hashlib.sha256(addr.packed).digest()
            # Map to 45.x.y.z public IP range
            b1 = 45
            b2 = h[0]
            b3 = h[1]
            b4 = h[2] % 254 + 1
            return f"{b1}.{b2}.{b3}.{b4}"
    except Exception:
        pass
    return ip_str

