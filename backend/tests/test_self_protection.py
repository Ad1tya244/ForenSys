"""
Unit test suite for ForenSys Self-Protection Layer & AssetTrustManager
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.self_protection import AssetTrustManager, asset_trust_manager
from pipeline.normalizer import NormalizedEvent
from pipeline.state_engine import BehaviorStateEngine
from pipeline.soar_engine import SOAREngine
from config import DEFAULT_CONFIG

class TestSelfProtection(unittest.TestCase):

    def setUp(self):
        self.trust_manager = AssetTrustManager()

    def test_dynamic_project_root_detection(self):
        self.assertTrue(os.path.exists(self.trust_manager.project_root))
        self.assertTrue(os.path.isabs(self.trust_manager.project_root))

    def test_trusted_pid_ownership(self):
        current_pid = os.getpid()
        cfg = {"attack_simulation_mode": False}
        event = {
            "pid": current_pid,
            "process": "python3",
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 50123,
            "dst_port": 8000
        }
        is_trusted, reason = self.trust_manager.is_trusted_event(event, cfg)
        self.assertTrue(is_trusted)
        self.assertIsNotNone(reason)
        self.assertIn("ForenSys Process PID", reason or "")

    def test_trusted_loopback_ipc(self):
        cfg = {"attack_simulation_mode": False}
        event = {
            "pid": 99999,
            "process": "node",
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 3000,
            "dst_port": 8000
        }
        is_trusted, reason = self.trust_manager.is_trusted_event(event, cfg)
        self.assertTrue(is_trusted)
        self.assertIsNotNone(reason)
        self.assertIn("Internal Loopback IPC", reason or "")

    def test_external_attack_targeting_forensys_is_not_ignored(self):
        """External host attacks targeting ForenSys port 8000 MUST NOT be ignored."""
        cfg = {"attack_simulation_mode": False}
        event = {
            "pid": None,
            "process": "unknown",
            "src_ip": "198.51.100.44",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 8000
        }
        is_trusted, reason = self.trust_manager.is_trusted_event(event, cfg)
        self.assertFalse(is_trusted)
        self.assertIsNone(reason)

    def test_soar_safeguard_cancels_remediation_on_trusted_asset(self):
        cfg = {"attack_simulation_mode": False}
        # Attempt to kill python main process PID
        is_trusted, cancel_reason = self.trust_manager.is_trusted_remediation_target("kill_process", str(os.getpid()), cfg)
        self.assertTrue(is_trusted)
        self.assertIsNotNone(cancel_reason)
        self.assertIn("Skipped due to trusted asset", cancel_reason or "")

        # Attempt to block localhost IP
        is_trusted, cancel_reason = self.trust_manager.is_trusted_remediation_target("block_ip", "127.0.0.1", cfg)
        self.assertTrue(is_trusted)
        self.assertIsNotNone(cancel_reason)
        self.assertIn("Skipped due to trusted asset", cancel_reason or "")

    def test_attack_simulation_mode_override(self):
        cfg = {"attack_simulation_mode": True}
        event = {
            "pid": 99999,
            "process": "node",
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 3000,
            "dst_port": 8000
        }
        is_trusted, reason = self.trust_manager.is_trusted_event(event, cfg)
        self.assertFalse(is_trusted)

if __name__ == "__main__":
    unittest.main()
