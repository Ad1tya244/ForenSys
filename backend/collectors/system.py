"""
System metrics collector — real CPU, memory, disk, and network I/O via psutil.
"""

import datetime
import platform
import psutil
from typing import Dict


def get_system_metrics() -> Dict:
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    boot_ts = psutil.boot_time()
    uptime_s = (datetime.datetime.now() - datetime.datetime.fromtimestamp(boot_ts)).total_seconds()

    try:
        conn_count = len(psutil.net_connections(kind="inet"))
    except psutil.AccessDenied:
        try:
            from collectors.network import get_connections
            conn_count = len(get_connections())
        except Exception:
            conn_count = 0

    return {
        # CPU
        "cpu_percent": round(cpu, 1),
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        # Memory
        "memory_total": mem.total,
        "memory_used": mem.used,
        "memory_available": mem.available,
        "memory_percent": round(mem.percent, 1),
        # Disk
        "disk_total": disk.total,
        "disk_used": disk.used,
        "disk_free": disk.free,
        "disk_percent": round(disk.percent, 1),
        # Network I/O (cumulative since boot)
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
        "errin": net.errin,
        "errout": net.errout,
        # Connections
        "connections_total": conn_count,
        # System
        "uptime_seconds": int(uptime_s),
        "platform": platform.system(),
        "platform_version": platform.version(),
        "hostname": platform.node(),
    }
