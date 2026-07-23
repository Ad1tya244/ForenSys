"""
ForenSys Configuration Engine
Loads and updates configurable detection thresholds, time windows, and process whitelists.
"""

import json
import os
from typing import Dict, Any, List

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "attack_simulation_mode": False,
    "icmp_threshold": 100,
    "icmp_window_sec": 10,
    "portscan_threshold": 20,
    "portscan_window_sec": 15,
    "syn_threshold": 50,
    "syn_window_sec": 10,
    "dns_beacon_window_sec": 60,
    "dns_beacon_min_queries": 5,
    "dns_beacon_max_variance": 0.2,
    "auth_failure_limit": 3,
    "auth_window_sec": 60,
    "data_exfiltration_bytes": 52428800,  # 50 MB
    "data_exfiltration_window_sec": 30,
    "uncommon_external_ports": [4444, 1337, 31337, 5555, 6666, 6667, 9001, 9050, 1080, 12345, 27374, 54321, 65535, 7777, 2222, 14444],
    "shell_executables": ["bash", "zsh", "sh", "python", "python3", "perl", "ruby"],
    "suspicious_parent_chains": [
        {"parent": "Microsoft Word", "child": "Terminal"},
        {"parent": "Word", "child": "bash"},
        {"parent": "Excel", "child": "bash"},
        {"parent": "Safari", "child": "bash"},
        {"parent": "Chrome", "child": "sh"},
        {"parent": "python", "child": "nc"}
    ],
    "whitelisted_processes": [
        "kernel_task",
        "launchd",
        "WindowServer",
        "systemd",
        "loginwindow",
        "Finder",
        "mds",
        "syslogd",
        "configd",
        "opendirectoryd",
        "trustd"
    ]
}

_current_config: Dict[str, Any] = {}

def load_config() -> Dict[str, Any]:
    global _current_config
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        _current_config = dict(DEFAULT_CONFIG)
        return _current_config
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            # Merge missing keys with default
            merged = {**DEFAULT_CONFIG, **data}
            _current_config = merged
            return _current_config
    except Exception as e:
        print(f"[Config] Error loading config file: {e}")
        _current_config = dict(DEFAULT_CONFIG)
        return _current_config

def save_config(config: Dict[str, Any]) -> None:
    global _current_config
    _current_config = dict(config)
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(_current_config, f, indent=2)
    except Exception as e:
        print(f"[Config] Error saving config file: {e}")

def get_config() -> Dict[str, Any]:
    if not _current_config:
        load_config()
    return _current_config

def update_config(patch: Dict[str, Any]) -> Dict[str, Any]:
    cfg = get_config()
    cfg.update(patch)
    save_config(cfg)
    return cfg

# Initialize configuration on import
load_config()
