import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import NetworkTrafficAnalyzer
from audit import AuditLog
from alerts import AlertDispatcher
from integrations import BiometricAuthAdapter, CloudMonitorExporter, ThreatIntelAdapter
from roi import ROIInputs, calculate_roi


class NetworkHomeworkTests(unittest.TestCase):
    def test_ddos_detects_injected_pps_not_baseline(self):
        analyzer = NetworkTrafficAnalyzer()
        analyzer.simulate_traffic_data(rows=250, hours=24)
        self.assertEqual(analyzer.detect_ddos(), [])
        analyzer.inject_demo_attacks(ddos_seconds=2, pps=450)
        events = analyzer.detect_ddos()
        self.assertEqual(len(events), 2)
        self.assertTrue(all(x["type"] == "DDOS_SUSPECTED" for x in events))
        self.assertTrue(all(x["pps"] >= 400 and x["unique_sources"] >= 15 for x in events))
        self.assertEqual(analyzer.detect_ddos(), [])  # нет повторной записи

    def test_port_scan_is_detected(self):
        analyzer = NetworkTrafficAnalyzer()
        analyzer.simulate_traffic_data(rows=250)
        analyzer.inject_demo_attacks(ddos_seconds=1, pps=450)
        events = analyzer.detect_policy_violations()
        self.assertTrue(any(item["type"] == "PORT_SCAN" for item in events))

    def test_audit_chain_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path)
            log.append("TEST", {"value": 123})
            log.append("TEST2", {"result": "ok"})
            self.assertTrue(log.verify()[0])
            lines = path.read_text(encoding="utf-8").splitlines()
            row = json.loads(lines[0])
            row["details"]["value"] = 777
            lines[0] = json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(log.verify()[0])
            with self.assertRaises(ValueError):
                AuditLog(path)

    def test_roi_number_and_availability(self):
        result = calculate_roi(ROIInputs())
        self.assertEqual(result["annual_breach_savings_usd"], 39920.0)
        self.assertEqual(result["routine_downtime_savings_usd"], 4800.0)
        self.assertEqual(result["minor_data_leak_savings_usd"], 4000)
        self.assertEqual(result["total_annual_benefit_usd"], 48720.0)
        self.assertEqual(result["first_year_cost_usd"], 33000)
        self.assertEqual(result["first_year_roi_pct"], 47.64)
        self.assertGreater(result["availability_after_pct"], result["availability_before_pct"])
        with self.assertRaises(ValueError):
            calculate_roi(replace(ROIInputs(), major_breach_probability_after=2))

    def test_offline_integrations_do_not_authenticate(self):
        self.assertFalse(BiometricAuthAdapter(live=False).verify("demo")["authenticated"])
        self.assertEqual(CloudMonitorExporter(live=False).export(1, 620, 1000)["aws"], "DEMO_ONLY")
        self.assertTrue(ThreatIntelAdapter(live=False).lookup_ip("203.0.113.66")["suspicious"])
        self.assertEqual(AlertDispatcher(live=False).notify({
            "severity": "HIGH", "type": "TEST", "source": "demo",
            "timestamp": "2026-11-17T00:00:00Z", "details": "demo",
        })["mode"], "DEMO")


if __name__ == "__main__":
    unittest.main()
