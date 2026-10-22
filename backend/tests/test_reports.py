"""
Tests for MTTD/MTTR correctness, the incident ledger + analytics statistics, and PDF report generation.
Run:  backend/.venv/bin/python -m unittest discover -s backend/tests -p "test_reports.py" -t backend
"""

import os
import re
import shutil
import sys
import tempfile
import time
import unittest
import zlib
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main
from fastapi import HTTPException
from pipeline.metrics import IncidentLedger, describe, percentile, response_metrics
from reporting.incident_report import assemble_incident_data, render_incident_report
from reporting.summary_report import render_summary_report
from tests.test_workflow import HOST, Pipeline, injector, traffic

USER = {"email": "analyst@forensys.in", "name": "Analyst", "permissions": []}


# ── tiny PDF reader (enough to check structure and extract text without a PDF library) ──

def pdf_text(pdf: bytes) -> str:
    out = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", pdf, re.S):
        try:
            content = zlib.decompress(m.group(1))
        except zlib.error:
            continue
        for t in re.finditer(rb"\((.*?)(?<!\\)\) Tj", content):
            out.append(t.group(1).replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\").decode("cp1252", "replace"))
    return "\n".join(out)


def assert_valid_pdf(tc: unittest.TestCase, pdf: bytes) -> int:
    tc.assertTrue(pdf.startswith(b"%PDF-1.4"))
    tc.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
    start = int(re.search(rb"startxref\n(\d+)\n", pdf).group(1))
    tc.assertEqual(pdf[start:start + 4], b"xref")
    size = int(re.search(rb"xref\n0 (\d+)\n", pdf).group(1))
    entries = re.findall(rb"(\d{10}) 00000 n \n", pdf[start:])
    tc.assertEqual(len(entries), size - 1)
    for n, off in enumerate(entries, start=1):
        tc.assertTrue(pdf[int(off):].startswith(f"{n} 0 obj".encode()), f"object {n} offset is wrong")
    return int(re.search(rb"/Type /Pages /Count (\d+)", pdf).group(1))


class MetricsMathTests(unittest.TestCase):
    def test_percentiles_and_describe(self):
        vals = [1, 2, 3, 4, 5]
        self.assertEqual(percentile(vals, 50), 3)
        self.assertAlmostEqual(percentile(vals, 95), 4.8)
        d = describe(vals + [None])
        self.assertEqual((d["n"], d["mean"], d["median"], d["min"], d["max"]), (5, 3.0, 3.0, 1.0, 5.0))
        self.assertEqual(describe([])["mean"], None)
        self.assertEqual(describe([7])["p95"], 7.0)

    def rec(self, i, detected, mttd, mttr, severity="high", contained=True, attack="port_scan"):
        return {"id": f"X{i}", "detected_at": detected, "mttd_sec": mttd, "mttr_sec": mttr, "contained": contained,
                "severity": severity, "attack_types": [attack], "mitre_stages": ["Reconnaissance"]}

    def test_response_metrics_excludes_uncontained_from_mttr_and_computes_rates(self):
        now = 1_000_000.0
        recs = [self.rec(1, now - 100, 2.0, 0.05), self.rec(2, now - 200, 4.0, 0.15),
                self.rec(3, now - 300, 6.0, None, contained=False)]
        m = response_metrics(recs, "24h", now)
        self.assertEqual(m["total_incidents"], 3)
        self.assertEqual(m["mttd"]["mean"], 4.0)
        self.assertEqual(m["mttr"]["n"], 2, "an uncontained incident has no MTTR - it must not count as 0")
        self.assertAlmostEqual(m["mttr"]["mean"], 0.1)
        self.assertAlmostEqual(m["containment_rate"], 2 / 3, places=3)

    def test_period_over_period_change_is_real_or_absent(self):
        now = 1_000_000.0
        cur = [self.rec(1, now - 3600, 2.0, 0.1)]
        prev = [self.rec(2, now - 86400 - 3600, 4.0, 0.2)]
        m = response_metrics(cur + prev, "24h", now)
        self.assertEqual(m["mttd_change_pct"], -50.0)
        self.assertEqual(m["mttr_change_pct"], -50.0)
        self.assertIsNone(response_metrics(cur, "24h", now)["mttd_change_pct"], "no previous data => no fake delta")
        self.assertIsNone(response_metrics(cur + prev, "all", now)["mttd_change_pct"])

    def test_empty_ledger(self):
        m = response_metrics([], "7d", 1_000_000.0)
        self.assertEqual((m["total_incidents"], m["mttd"]["n"], m["containment_rate"]), (0, 0, None))
        self.assertEqual(len(m["trend"]), 7)


class DetectionTimingTests(unittest.TestCase):
    """MTTD/MTTR come from real timestamps - no clamps, no placeholder constants."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        traffic.get_recent_traffic_packets()
        injector.drain()
        self.p = Pipeline(self.tmp)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.p.soar.clear_history)

    def test_port_scan_mttd_matches_first_probe_and_mttr_is_real_latency(self):
        now = time.time()
        for i, port in enumerate(range(100, 160)):
            traffic._add_packet("TCP", "45.155.205.50", 50000, HOST, port, 44, "[SYN]", flags="SYN", ts=now - 3.0 + i * 0.005)
        self.p.step()
        inc = self.p.corr.incidents[0]
        self.assertAlmostEqual(inc.mttd_sec, 3.0, delta=0.4)
        self.assertGreater(inc.mttr_sec, 0.0)
        self.assertLess(inc.mttr_sec, 1.0)
        rec = self.p.ledger.get(inc.id)
        self.assertEqual((rec["mttd_sec"], rec["mttr_sec"]), (inc.mttd_sec, inc.mttr_sec))
        evd = self.p.evidence.get_evidence(f"EVD-{inc.id}").payload["timing"]
        self.assertEqual((evd["mttd_sec"], evd["mttr_sec"]), (inc.mttd_sec, inc.mttr_sec))

    def test_fast_detection_is_not_clamped_up_to_100ms(self):
        now = time.time()
        for port in range(100, 160):
            traffic._add_packet("TCP", "45.155.205.51", 50000, HOST, port, 44, "[SYN]", flags="SYN", ts=now - 0.02)
        self.p.step()
        self.assertLess(self.p.corr.incidents[0].mttd_sec, 0.1)

    def test_exfil_mttd_uses_first_upload_not_a_constant(self):
        now = time.time()
        for i in range(13):
            traffic._add_packet("TCP", HOST, 51888, "185.220.101.77", 443, 8 * 1024 * 1024, "[PSH+ACK]", flags="PSH+ACK", ts=now - 6 + i * 0.1)
        self.p.step()
        self.assertAlmostEqual(self.p.corr.incidents[0].mttd_sec, 6.0, delta=0.4)

    def test_uncontained_incident_has_no_mttr(self):
        # Containment can be refused (e.g. self-protection). The incident then has no MTTR - unknown, not zero.
        from pipeline.self_protection import asset_trust_manager
        for port in range(100, 140):
            traffic._add_packet("TCP", "45.155.205.59", 50000, HOST, port, 44, "[SYN]", flags="SYN")
        with mock.patch.object(asset_trust_manager, "is_trusted_remediation_target", return_value=(True, "trusted asset")):
            self.p.step()
        rec = self.p.ledger.get(self.p.corr.incidents[0].id)
        self.assertFalse(rec["contained"])
        self.assertIsNone(rec["mttr_sec"])
        self.assertIsNotNone(rec["mttd_sec"])


class AuthEvidenceTests(unittest.TestCase):
    def test_usernames_are_extracted_from_macos_and_linux_ssh_messages(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        p = Pipeline(tmp)
        self.addCleanup(p.soar.clear_history)
        msgs = ["Invalid user admin from 45.155.205.81 port 50000", "Failed password for invalid user root from 45.155.205.81 port 50001 ssh2",
                "Invalid user oracle from 45.155.205.81 port 50002", "Failed password for ubuntu from 45.155.205.81 port 50003 ssh2"]
        for i, m in enumerate(msgs):
            injector.push("log", {"id": f"u{i}", "process": "sshd-session", "level": "info", "pid": 1, "message": m})
        p.step()
        d = assemble_incident_data(p.corr.incidents[0].id, p.corr, p.ledger, p.evidence, p.soar)
        users = d["attack_details"]["auth_attack"]["usernames_targeted"]
        self.assertEqual(set(users), {"admin", "root", "oracle", "ubuntu"})


class LedgerTests(unittest.TestCase):
    def test_persists_and_keeps_first_containment_time(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "ledger.json")
        led = IncidentLedger(path)
        led.upsert({"id": "A1", "detected_at": 100.0, "contained_at": 100.5, "contained": True, "mttr_sec": 0.5})
        led.upsert({"id": "A1", "detected_at": 100.0, "contained_at": None, "contained": False, "mttr_sec": None})
        self.assertEqual(IncidentLedger(path).get("A1")["mttr_sec"], 0.5, "a later pass must not erase the first containment")
        led.clear()
        self.assertEqual(IncidentLedger(path).all(), [])

    def test_backfill_from_evidence_leaves_timing_unknown(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        p = Pipeline(tmp)
        self.addCleanup(p.soar.clear_history)
        for port in range(100, 140):
            traffic._add_packet("TCP", "45.155.205.52", 50000, HOST, port, 44, "[SYN]", flags="SYN")
        p.step()
        inc_id = p.corr.incidents[0].id
        fresh = IncidentLedger(os.path.join(tmp, "other.json"))
        self.assertEqual(fresh.backfill(p.evidence, p.soar), 1)
        rec = fresh.get(inc_id)
        self.assertTrue(rec["legacy"] and rec["contained"])
        self.assertIsNone(rec["mttd_sec"])
        self.assertIsNone(rec["mttr_sec"])
        self.assertEqual(fresh.backfill(p.evidence, p.soar), 0, "idempotent")


class PdfReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        traffic.get_recent_traffic_packets()
        injector.drain()
        self.p = Pipeline(self.tmp)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.p.soar.clear_history)
        now = time.time()
        for i, port in enumerate(list(range(20, 80)) + [443]):
            traffic._add_packet("TCP", "45.155.205.50", 50000, HOST, port, 44, f"[SYN] Seq={i}", flags="SYN", ts=now - 1.5 + i * 0.005)
        self.p.step()
        self.inc = self.p.corr.incidents[0]

    def data(self):
        return assemble_incident_data(self.inc.id, self.p.corr, self.p.ledger, self.p.evidence, self.p.soar, "analyst@forensys.in")

    def test_incident_report_is_a_valid_pdf_with_all_sections_and_evidence(self):
        pdf = render_incident_report(self.data())
        pages = assert_valid_pdf(self, pdf)
        self.assertGreaterEqual(pages, 2)
        text = pdf_text(pdf)
        for needle in (self.inc.id, "45.155.205.50", "Executive Summary", "Incident Timeline", "Detections", "Attack Forensics",
                       "Containment & Response Actions", "Forensic Evidence & Integrity", "Network Evidence", "Log Evidence",
                       "MTTD (time to detect)", "MTTR (time to remediate)", "VERIFIED", "SHA-256", "analyst@forensys.in",
                       "Scanner IP", "Ports probed", "No OS firewall rule was changed"):
            self.assertIn(needle, text, f"missing from PDF: {needle}")
        evd = self.p.evidence.get_evidence(f"EVD-{self.inc.id}")
        self.assertIn(evd.sha256_hash, text.replace("\n", ""))

    def test_tampered_evidence_is_flagged_in_the_report(self):
        evd = self.p.evidence.get_evidence(f"EVD-{self.inc.id}")
        evd.payload["attacker_ip"] = "6.6.6.6"   # alter a sealed package after the fact
        text = pdf_text(render_incident_report(self.data()))
        self.assertIn("MISMATCH", text)
        self.assertNotIn("VERIFIED", text)

    def test_report_still_builds_after_restart_and_after_evidence_deletion(self):
        self.p.corr.incidents.clear()                  # backend restarted: no live incident, only persisted data
        self.p.evidence.delete_evidence(self.inc.id)   # and the evidence package was deleted
        pdf = render_incident_report(self.data())
        assert_valid_pdf(self, pdf)
        text = pdf_text(pdf)
        self.assertIn(self.inc.id, text)
        self.assertIn("No sealed evidence package is on file", text)
        self.assertIn("Block IP", text)                # containment actions still come from the audit log

    def test_unknown_incident_returns_none(self):
        self.assertIsNone(assemble_incident_data("NOPE99", self.p.corr, self.p.ledger, self.p.evidence, self.p.soar))

    def test_summary_report(self):
        now = time.time()
        pdf = render_summary_report(self.p.ledger.all(), now - 86400, now, "analyst@forensys.in")
        assert_valid_pdf(self, pdf)
        text = pdf_text(pdf)
        for needle in ("Key Metrics", "MTTD (mean / median / p95)", "Top Attackers", "Incident Register", self.inc.id, "45.155.205.50"):
            self.assertIn(needle, text)
        assert_valid_pdf(self, render_summary_report([], now - 86400, now))   # empty period still renders

    def test_non_latin_and_hostile_text_cannot_break_the_pdf(self):
        d = self.data()
        d["title"] = "Incident (with) parens \\ backslash 中文 \x00 control"
        d["logs"] = [{"time": "2026-01-01T00:00:00Z", "process": "x", "message": "a)b(c\\d \U0001F600"}]
        assert_valid_pdf(self, render_incident_report(d))


class ReportEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        traffic.get_recent_traffic_packets()
        injector.drain()
        self.p = Pipeline(self.tmp)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.p.soar.clear_history)
        for port in range(100, 140):
            traffic._add_packet("TCP", "45.155.205.53", 50000, HOST, port, 44, "[SYN]", flags="SYN")
        self.p.step()
        self.inc_id = self.p.corr.incidents[0].id
        patcher = mock.patch.multiple(main, incident_ledger=self.p.ledger, correlation_engine=self.p.corr,
                                      evidence_manager=self.p.evidence, soar_engine=self.p.soar)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_incident_pdf_endpoint(self):
        resp = main.api_incident_report(self.inc_id, current_user=USER)
        self.assertEqual(resp.media_type, "application/pdf")
        self.assertIn(f"ForenSys-incident-{self.inc_id}.pdf", resp.headers["content-disposition"])
        assert_valid_pdf(self, resp.body)

    def test_incident_pdf_rejects_bad_and_unknown_ids(self):
        with self.assertRaises(HTTPException) as bad:
            main.api_incident_report('X"\r\nSet-Cookie: a=b', current_user=USER)
        self.assertEqual(bad.exception.status_code, 400)
        with self.assertRaises(HTTPException) as missing:
            main.api_incident_report("NOPE99", current_user=USER)
        self.assertEqual(missing.exception.status_code, 404)

    def test_summary_pdf_endpoint_and_validation(self):
        today = time.strftime("%Y-%m-%d", time.gmtime())
        resp = main.api_summary_report(start=today, end=today, current_user=USER)
        assert_valid_pdf(self, resp.body)
        self.assertIn(self.inc_id, pdf_text(resp.body))
        for start, end in (("not-a-date", today), (today, "2020-01-01"), ("2020-01-01", today)):
            with self.assertRaises(HTTPException) as e:
                main.api_summary_report(start=start, end=end, current_user=USER)
            self.assertEqual(e.exception.status_code, 400)

    def test_ledger_and_metrics_endpoints(self):
        rows = main.api_incident_ledger(current_user=USER)
        self.assertEqual(rows[0]["id"], self.inc_id)
        self.assertTrue(rows[0]["has_evidence"])
        self.assertRegex(rows[0]["detected_at"], r"^\d{4}-\d\d-\d\dT")
        m = main.api_response_metrics(range_key="all", current_user=USER)
        self.assertEqual(m["total_incidents"], 1)
        self.assertEqual(m["mttr"]["n"], 1)
        self.assertGreaterEqual(m["mttd"]["mean"], 0)   # packets were stamped "now", so ~0 s is the correct MTTD here


if __name__ == "__main__":
    unittest.main()
