"""
End-to-end tests of the response workflow:
attack detected -> incident raised -> auto-remediation (logical IP block etc.) -> forensic evidence sealed -> history.

Remediation is purely logical (blocklist the packet sniffer honours) - these tests also assert nothing else is touched.
Run:  backend/.venv/bin/python -m unittest discover -s backend/tests -p "test_workflow.py" -t backend
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pipeline.soar_engine as soar_module
from collectors import injector, traffic
from config import get_config
from pipeline.correlation_engine import IncidentCorrelationEngine
from pipeline.metrics import IncidentLedger
from pipeline.evidence import EvidenceManager
from pipeline.normalizer import EventNormalizer
from pipeline.response import ResponseOrchestrator
from pipeline.rule_engine import RuleEngine
from pipeline.self_protection import get_primary_host_ip
from pipeline.state_engine import BehaviorStateEngine

HOST = get_primary_host_ip()   # this machine's own address: never a scan/flood source, never blockable


class Pipeline:
    """Mirrors main._detect_once() with isolated engines and temp storage."""

    def __init__(self, tmp: str) -> None:
        self.soar = soar_module.soar_engine            # sniffer consults this singleton, so isolate *it*
        self.soar.log_path = os.path.join(tmp, "history.json")
        self.soar.registry_path = os.path.join(tmp, "perimeter_registry.json")  # never touch the real one on disk
        self.soar.reset_all()
        self.state = BehaviorStateEngine()
        self.rules = RuleEngine()
        self.corr = IncidentCorrelationEngine()
        self.evidence = EvidenceManager(vault_path=os.path.join(tmp, "vault.json"), artifacts_dir=os.path.join(tmp, "evidence"))
        self.ledger = IncidentLedger(path=os.path.join(tmp, "ledger.json"))
        self.orch = ResponseOrchestrator(self.soar, self.evidence, self.state, self.ledger)
        self.norm = EventNormalizer()
        self.cfg = get_config()
        self.emitted = set()
        self.all_alerts = []

    def step(self, now=None):
        pinned = now          # None => the orchestrator uses the real wall clock, exactly like main.py
        now = now or time.time()
        pkts = traffic.get_recent_traffic_packets()
        inj = injector.drain()
        events = [self.norm.normalize_packet(p) for p in pkts]
        events += self.norm.normalize_all(inj["connection"], inj["process"], inj["log"], [], inj["listener"], now)
        self.state.process_events(events, self.cfg)
        alerts = self.rules.evaluate_all(self.state, self.cfg, now)
        fresh = [a for a in alerts if a.alert_id not in self.emitted]
        self.emitted.update(a.alert_id for a in fresh)
        self.all_alerts.extend(fresh)
        incidents = self.corr.correlate(alerts, now)
        actions = []
        for inc in incidents:
            actions += self.orch.handle(inc, pinned)
        return fresh, actions

    def run(self, seconds=1.0, tick=0.25):
        end = time.time() + seconds
        while time.time() < end:
            self.step()
            time.sleep(tick)

    def types(self, incident_id=None):
        return [(l.action_type, l.target, l.status) for l in self.soar.remediation_history
                if incident_id is None or l.incident_id == incident_id]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        traffic.get_recent_traffic_packets()   # drain leftovers
        injector.drain()
        self.p = Pipeline(self.tmp)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.p.soar.clear_history)

    def syn(self, src, port, sport=50000, ts=None):
        return traffic._add_packet("TCP", src, sport, HOST, port, 44, "[SYN]", flags="SYN", ts=ts)

    # ── nmap-style port scan ──────────────────────────────────────────────────

    def test_port_scan_full_workflow(self):
        atk = "45.155.205.50"
        for port in range(20, 20 + 60):
            self.assertTrue(self.syn(atk, port))
        fresh, actions = self.p.step()

        self.assertEqual([a.rule_name for a in fresh], ["Port Scan"], "exactly one alert (no SYN-flood double report)")
        inc = self.p.corr.incidents[0]
        self.assertEqual(inc.status, "contained")
        self.assertIn(atk, self.p.soar.blocked_ips)

        kinds = [t[0] for t in self.p.types(inc.id)]
        for expected in ("block_ip", "capture_forensics", "capture_pcap"):
            self.assertIn(expected, kinds)

        evd = self.p.evidence.get_evidence(f"EVD-{inc.id}")
        scan = evd.payload["attack_details"]["port_scan"]
        self.assertEqual(scan["scanner_ip"], atk)
        self.assertEqual(scan["ports_probed"], list(range(20, 80)))
        self.assertEqual(evd.payload["attacker_ip"], atk)
        self.assertTrue(evd.sha256_hash and evd.status == "Sealed")
        pcap = os.path.join(self.tmp, "evidence", evd.evidence_id, "capture.pcap")
        self.assertTrue(os.path.getsize(pcap) > 0)
        self.assertTrue(any(a["action"] == "block_ip" for a in evd.payload["remediation_actions"]))

    def test_same_attack_is_never_reported_twice(self):
        atk = "45.155.205.51"
        for port in range(1, 40):
            self.syn(atk, port)
        for _ in range(6):                      # many cycles, incl. a bucket boundary's worth of time shifts
            self.p.step()
            self.p.step(time.time() + 11)
        self.assertEqual(len(self.p.all_alerts), 1)
        self.assertEqual(len(self.p.corr.incidents), 1)
        ids = [l.action_id for l in self.p.soar.remediation_history]
        self.assertEqual(len(ids), len(set(ids)), "history action ids are unique")

    def test_sniffer_ignores_blocked_ip_until_manual_unblock(self):
        atk = "45.155.205.52"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.assertIn(atk, self.p.soar.blocked_ips)
        self.assertFalse(self.syn(atk, 9999), "blocked IP telemetry is ignored by the sniffer")
        self.assertFalse(traffic._add_packet("ICMP", HOST, 0, atk, 0, 84, "reply", icmp_type=0), "both directions ignored")
        self.assertEqual(traffic.get_recent_traffic_packets(), [])

        self.p.soar.unblock_ip(atk)
        self.p.rules.reset_episodes()
        self.assertTrue(self.syn(atk, 9999), "traffic is captured again after manual unblock")
        statuses = [l.status for l in self.p.soar.remediation_history if l.action_type == "block_ip"]
        self.assertEqual(statuses, ["rolled_back"])

    def test_reattack_after_unblock_is_a_new_incident_and_reblocked(self):
        atk = "45.155.205.53"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.p.soar.unblock_ip(atk)
        self.p.rules.reset_episodes()
        self.p.emitted.clear()
        time.sleep(1.1)
        for port in range(100, 140):
            self.syn(atk, port)
        self.p.step()
        self.assertEqual(len(self.p.corr.incidents), 2)
        self.assertIn(atk, self.p.soar.blocked_ips)
        self.assertEqual(len({i.id for i in self.p.corr.incidents}), 2)

    # ── ICMP ──────────────────────────────────────────────────────────────────

    def test_icmp_flood(self):
        atk = "45.155.205.60"
        for _ in range(80):
            traffic._add_packet("ICMP", atk, 0, HOST, 0, 84, "Type=8 Code=0", icmp_type=8)
        fresh, _ = self.p.step()
        self.assertEqual([a.rule_name for a in fresh], ["ICMP Flood"])
        inc = self.p.corr.incidents[0]
        self.assertEqual(inc.status, "contained")
        self.assertIn(atk, self.p.soar.blocked_ips)
        d = self.p.evidence.get_evidence(f"EVD-{inc.id}").payload["attack_details"]["icmp_flood"]
        self.assertEqual(d["attacker_ip"], atk)
        self.assertGreaterEqual(d["captured_packets"], 50)

    def test_icmp_below_threshold_and_replies_ignored(self):
        for _ in range(30):
            traffic._add_packet("ICMP", "45.155.205.61", 0, HOST, 0, 84, "Type=8", icmp_type=8)
        for _ in range(200):
            traffic._add_packet("ICMP", "45.155.205.62", 0, HOST, 0, 84, "Type=0", icmp_type=0)
        fresh, _ = self.p.step()
        self.assertEqual(fresh, [])

    # ── SYN flood ─────────────────────────────────────────────────────────────

    def test_syn_flood_is_not_a_port_scan(self):
        atk = "45.155.205.70"
        for i in range(120):
            self.syn(atk, 80, sport=1024 + i)
        fresh, _ = self.p.step()
        self.assertEqual([a.rule_name for a in fresh], ["SYN Flood"])
        self.assertIn(atk, self.p.soar.blocked_ips)

    # ── Auth ──────────────────────────────────────────────────────────────────

    def test_ssh_brute_force(self):
        atk = "45.155.205.80"
        for i in range(5):
            injector.push("log", {"id": f"l{i}", "process": "sshd", "level": "error", "pid": 1,
                                  "message": f"Failed password for invalid user admin from {atk} port {40000 + i} ssh2"})
        injector.push("log", {"id": "ok", "process": "sshd", "level": "info", "pid": 1,
                              "message": f"Accepted password for root from {atk} port 40010 ssh2"})
        fresh, _ = self.p.step()
        self.assertIn("Brute Force Authentication", {a.rule_name for a in fresh})
        self.assertEqual(len(self.p.corr.incidents), 1, "auth rules correlate into one incident")
        self.assertIn(atk, self.p.soar.blocked_ips)
        d = self.p.evidence.get_evidence(f"EVD-{self.p.corr.incidents[0].id}").payload["attack_details"]["brute_force"]
        self.assertEqual(d["attacker_ip"], atk)
        self.assertGreaterEqual(d["failed_attempts"], 5)
        self.assertTrue(d["compromised"])

    def test_auth_failures_without_an_attacker_address_raise_no_alert(self):
        # sudo/loginwindow typos, replayed history, ... have no remote IP: nothing to name or contain, so no alert.
        for i in range(12):
            injector.push("log", {"id": f"n{i}", "process": "sudo" if i % 2 else "loginwindow", "level": "error", "pid": 9,
                                  "message": "authentication failure; user not allowed"})
        fresh, _ = self.p.step()
        self.assertEqual(fresh, [])
        self.assertEqual(self.p.corr.incidents, [])

    def test_ssh_attack_raises_exactly_one_alert_even_with_background_auth_noise(self):
        atk = "45.155.205.82"
        for i in range(9):   # unrelated noise with no address
            injector.push("log", {"id": f"n{i}", "process": "sudo", "level": "error", "pid": 9, "message": "authentication failure"})
        for i in range(4):   # a real attack: each connection writes several lines that share one client port
            port = 51000 + i
            injector.push("log", {"id": f"a{i}", "process": "sshd-session", "level": "info", "pid": 1,
                                  "message": f"Invalid user admin from {atk} port {port}"})
            injector.push("log", {"id": f"b{i}", "process": "sshd-session", "level": "error", "pid": 1,
                                  "message": f"error: PAM: authentication error for illegal user admin from {atk} port {port}"})
        fresh, _ = self.p.step()
        self.assertEqual(len(fresh), 1, [a.title for a in fresh])
        self.assertEqual(fresh[0].rule_name, "Authentication Attack Correlation")
        self.assertIn(atk, fresh[0].title)
        self.assertEqual(len(self.p.corr.incidents), 1)
        self.assertIn(atk, self.p.soar.blocked_ips)

    def test_local_auth_noise_cannot_trigger_brute_force_success_alert(self):
        for i in range(4):
            injector.push("log", {"id": f"f{i}", "process": "sudo", "level": "error", "pid": 9, "message": "authentication failure"})
        injector.push("log", {"id": "ok", "process": "sudo", "level": "info", "pid": 9, "message": "session opened for user root"})
        fresh, _ = self.p.step()
        self.assertEqual(fresh, [])

    # ── DNS beaconing ─────────────────────────────────────────────────────────

    def test_dns_beaconing_sinkholes_domain(self):
        now = time.time()
        for i in range(8):
            traffic._add_packet("UDP", HOST, 50000 + i, "8.8.8.8", 53, 74, "Standard query 0x1 A c2.evil-beacon.xyz", ts=now - 14 + i * 1.5)
        fresh, _ = self.p.step(now)
        self.assertEqual([a.rule_name for a in fresh], ["DNS Beaconing"])
        self.assertIn("c2.evil-beacon.xyz", self.p.soar.blocked_domains)
        self.assertNotIn("8.8.8.8", self.p.soar.blocked_ips, "resolver must not be blocked")
        self.assertFalse(traffic._add_packet("UDP", HOST, 50100, "8.8.8.8", 53, 74, "Standard query 0x1 A c2.evil-beacon.xyz"))
        self.assertTrue(traffic._add_packet("UDP", HOST, 50101, "8.8.8.8", 53, 74, "Standard query 0x1 A github.com"))

    # ── Reverse shell / exfil / listener / process chain ──────────────────────

    def test_reverse_shell(self):
        injector.push("connection", {"id": "c1", "local_ip": HOST, "local_port": 51000, "remote_ip": "185.220.101.45",
                                     "remote_port": 4444, "status": "ESTABLISHED", "pid": 61337, "process": "bash", "protocol": "TCP"})
        fresh, _ = self.p.step()
        self.assertEqual([a.rule_name for a in fresh], ["Reverse Shell"])
        self.assertIn("185.220.101.45", self.p.soar.blocked_ips)
        self.assertIn("bash", self.p.soar.quarantined_processes)
        q = [l for l in self.p.soar.remediation_history if l.action_type == "quarantine_process"][0]
        self.assertTrue(q.result_details.get("simulated"), "process containment is simulated, never a real kill")

    def test_data_exfiltration(self):
        for _ in range(13):
            traffic._add_packet("TCP", HOST, 51888, "185.220.101.77", 443, 8 * 1024 * 1024, "[PSH+ACK]", flags="PSH+ACK")
        fresh, _ = self.p.step()
        self.assertEqual([a.rule_name for a in fresh], ["Data Exfiltration"])
        self.assertIn("185.220.101.77", self.p.soar.blocked_ips)
        d = self.p.evidence.get_evidence(f"EVD-{self.p.corr.incidents[0].id}").payload["attack_details"]["data_exfil"]
        self.assertGreaterEqual(d["transferred_mb"], 100)
        self.assertEqual(d["upload_ratio"], 1.0)

    def test_download_is_not_exfiltration(self):
        # Receive-heavy traffic (a normal download/stream) must never trigger the exfil rule, no matter the volume.
        for _ in range(20):
            traffic._add_packet("TCP", "185.220.101.77", 443, HOST, 51888, 8 * 1024 * 1024, "[PSH+ACK]", flags="PSH+ACK")
        fresh, _ = self.p.step()
        self.assertNotIn("Data Exfiltration", {a.rule_name for a in fresh})
        self.assertNotIn("185.220.101.77", self.p.soar.blocked_ips)

    def test_suspicious_listener_and_process_chain(self):
        injector.push("listener", {"port": 4444, "ip": "0.0.0.0", "process": "ncat", "pid": 61338})
        injector.push("process", {"pid": 61339, "ppid": 61000, "name": "bash", "parent_name": "Microsoft Word"})
        fresh, _ = self.p.step()
        self.assertEqual({a.rule_name for a in fresh}, {"Suspicious Listening Port", "Suspicious Process Chain"})
        self.assertTrue({"ncat", "bash"} <= self.p.soar.quarantined_processes)
        for inc in self.p.corr.incidents:
            self.assertIsNotNone(self.p.evidence.get_evidence(f"EVD-{inc.id}"))

    # ── Safety ────────────────────────────────────────────────────────────────

    def test_never_blocks_local_host_or_loopback(self):
        for port in range(1, 40):
            self.syn(HOST, port)
            self.syn("127.0.0.1", port)
            traffic._add_packet("TCP", HOST, 50000, "45.155.205.99", port, 44, "[SYN]", flags="SYN")  # replies out of the host
        fresh, actions = self.p.step()
        self.assertEqual(fresh, [])
        self.assertEqual(self.p.soar.blocked_ips, set())

    def test_remediation_never_shells_out(self):
        import subprocess
        called = []
        real = subprocess.run
        subprocess.run = lambda *a, **k: called.append(a) or real(*a, **k)
        try:
            for port in range(1, 40):
                self.syn("45.155.205.54", port)
            self.p.step()
        finally:
            subprocess.run = real
        self.assertEqual(called, [])

    def test_unblocked_ip_stays_visible_and_is_reblockable(self):
        # An unblocked IP must stay on the Playbooks list (status 'released', not deleted) so it can be
        # re-blocked with one click, instead of vanishing and forcing the analyst to retype the address.
        atk = "45.155.205.58"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.assertIn(atk, self.p.soar.blocked_ips)

        self.p.soar.unblock_ip(atk)

        self.assertNotIn(atk, self.p.soar.blocked_ips, "no longer actively blocked")
        details = {d["ip"]: d for d in self.p.soar.get_blocked_ip_details()}
        self.assertIn(atk, details, "row stays on the Playbooks list after unblocking")
        self.assertEqual(details[atk]["status"], "released")
        self.assertIsNotNone(details[atk]["released_at"])
        self.assertFalse(self.p.soar.is_blocked(atk))

        # Manually re-block it from that same row.
        self.p.soar.block_ip(atk, reason="Manual re-block")
        self.assertIn(atk, self.p.soar.blocked_ips)
        self.assertTrue(self.p.soar.is_blocked(atk))
        details = {d["ip"]: d for d in self.p.soar.get_blocked_ip_details()}
        self.assertEqual(details[atk]["status"], "active")
        self.assertIsNone(details[atk]["released_at"])

    # ── Trusted dependencies must not raise false positives ─────────────────────

    def test_project_dependencies_do_not_raise_new_listener_alerts(self):
        from analyzers.threat_detector import ThreatDetector
        det = ThreatDetector()
        det.analyze([], [], [], [{"port": 8000, "ip": "0.0.0.0", "process": "Python", "pid": 1}])  # baseline cycle

        listeners = [
            {"port": 33060, "ip": "0.0.0.0", "process": "mysqld", "pid": 777},       # MySQL X protocol (the screenshot)
            {"port": 3306, "ip": "0.0.0.0", "process": "mysqld", "pid": 777},
            {"port": 51234, "ip": "127.0.0.1", "process": "node", "pid": 888},       # Next.js worker, loopback ephemeral
            {"port": 49321, "ip": "127.0.0.1", "process": "python3.14", "pid": 999},
        ]
        self.assertEqual(det.analyze([], [], [], listeners), [], "own dependencies must stay quiet")

    def test_stock_macos_listeners_do_not_alert_but_lookalikes_do(self):
        from analyzers.threat_detector import ThreatDetector
        det = ThreatDetector()
        det.analyze([], [], [], [{"port": 8000, "ip": "0.0.0.0", "process": "Python", "pid": 1}])  # baseline cycle
        quiet = [
            {"port": 631, "ip": "127.0.0.1", "process": "cupsd", "pid": 10},         # printing (screenshot: port 631)
            {"port": 7000, "ip": "0.0.0.0", "process": "ControlCe", "pid": 11},      # lsof-truncated ControlCenter / AirPlay
            {"port": 49152, "ip": "0.0.0.0", "process": "rapportd", "pid": 12},
        ]
        self.assertEqual(det.analyze([], [], [], quiet), [])
        loud = [
            {"port": 4444, "ip": "0.0.0.0", "process": "cupsd", "pid": 13},          # right name, wrong port
            {"port": 7001, "ip": "0.0.0.0", "process": "mydaemon", "pid": 14},       # unknown process
        ]
        self.assertEqual(len(det.analyze([], [], [], loud)), 2)

    def test_attacker_tooling_listener_is_reported_once_by_the_pipeline_rule(self):
        from analyzers.threat_detector import ThreatDetector
        det = ThreatDetector()
        det.analyze([], [], [], [{"port": 8000, "ip": "0.0.0.0", "process": "Python", "pid": 1}])  # baseline cycle
        self.assertEqual(det.analyze([], [], [], [{"port": 4444, "ip": "0.0.0.0", "process": "nc", "pid": 5}]), [],
                         "the legacy analyzer must not duplicate the pipeline's Suspicious Listening Port alert")

    def test_untrusted_or_misplaced_listeners_still_alert(self):
        from analyzers.threat_detector import ThreatDetector
        det = ThreatDetector()
        det.analyze([], [], [], [{"port": 8000, "ip": "0.0.0.0", "process": "Python", "pid": 1}])  # baseline cycle

        listeners = [
            {"port": 33060, "ip": "0.0.0.0", "process": "mydaemon", "pid": 5001},    # right port, wrong process
            {"port": 4444, "ip": "0.0.0.0", "process": "mysqld", "pid": 5002},       # right name, unexpected exposed port
        ]
        titles = [a["title"] for a in det.analyze([], [], [], listeners)]
        self.assertEqual(len(titles), 2, titles)
        self.assertTrue(any("33060" in t for t in titles) and any("4444" in t for t in titles))

    def test_trusted_listener_events_are_ignored_by_rules_and_audited_once(self):
        from pipeline.self_protection import asset_trust_manager
        asset_trust_manager.audit_log.clear()
        for _ in range(5):
            injector.push("listener", {"port": 33060, "ip": "0.0.0.0", "process": "mysqld", "pid": 777})
            injector.push("listener", {"port": 4444, "ip": "0.0.0.0", "process": "ncat", "pid": 5003})
            fresh, _ = self.p.step()
        self.assertTrue(any(e.is_trusted for e in self.p.state.events if e.process_name == "mysqld"))
        self.assertEqual({a.rule_name for a in self.p.all_alerts}, {"Suspicious Listening Port"})
        self.assertEqual(len([e for e in asset_trust_manager.audit_log if e["process"] == "mysqld"]), 1)

    # ── Clear History vs Reset Lab ──────────────────────────────────────────────

    def test_clear_log_keeps_active_containment(self):
        atk = "45.155.205.55"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.assertIn(atk, self.p.soar.blocked_ips)
        self.assertTrue(len(self.p.soar.remediation_history) > 0)

        self.p.soar.clear_log()

        self.assertEqual(self.p.soar.remediation_history, [])
        self.assertIn(atk, self.p.soar.blocked_ips, "clearing the log must never release active containment")
        self.assertTrue(self.p.soar.is_blocked(atk))
        self.assertEqual([d["ip"] for d in self.p.soar.get_blocked_ip_details()], [atk])
        self.assertFalse(self.syn(atk, 9999), "sniffer still ignores it after a log clear")

    def test_reset_all_releases_containment(self):
        atk = "45.155.205.56"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.assertIn(atk, self.p.soar.blocked_ips)

        self.p.soar.reset_all()

        self.assertEqual(self.p.soar.remediation_history, [])
        self.assertNotIn(atk, self.p.soar.blocked_ips)
        self.assertFalse(self.p.soar.is_blocked(atk))
        self.assertEqual(self.p.soar.get_blocked_ip_details(), [])
        self.assertTrue(self.syn(atk, 9999), "sniffer captures it again after a full reset")

    def test_registry_persists_independently_of_history(self):
        atk = "45.155.205.57"
        for port in range(1, 40):
            self.syn(atk, port)
        self.p.step()
        self.p.soar.clear_log()  # log is gone, but the IP should still be blocked...

        # ...and a freshly-constructed engine pointed at the same files must see it too (survives a restart).
        reloaded = soar_module.SOAREngine(log_path=self.p.soar.log_path, registry_path=self.p.soar.registry_path)
        self.assertIn(atk, reloaded.blocked_ips)
        self.assertEqual(reloaded.remediation_history, [])


if __name__ == "__main__":
    unittest.main()
