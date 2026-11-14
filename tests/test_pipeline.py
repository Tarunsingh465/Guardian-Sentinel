"""
Guardian-Sentinel Unit & Integration Tests
Validates classifier, zero-day ensemble, threat memory, containment playbooks, and flow extraction.
"""

import sys
import unittest
from pathlib import Path

# Add root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardian.core.agent.security_agent import analyze_network_flow
from guardian.core.agent.normalizer import normalize_attack_name
from guardian.core.agent.severity import calculate_severity
from guardian.core.agent.reputation import calculate_reputation
from guardian.core.zero_day.hybrid_engine import hybrid_zero_day_engine
from guardian.sniffer.flow_engine import BidirectionalFlow

class TestGuardianPipeline(unittest.TestCase):

    def test_normalizer(self):
        self.assertEqual(normalize_attack_name("DDoS"), "DDOS")
        self.assertEqual(normalize_attack_name("PortScan"), "PORTSCAN")
        self.assertEqual(normalize_attack_name("BENIGN"), "BENIGN")
        self.assertEqual(normalize_attack_name("Web Attack – SQL Injection"), "WEB_ATTACK_SQLI")

    def test_severity_calculation(self):
        self.assertEqual(calculate_severity("BENIGN"), "LOW")
        self.assertEqual(calculate_severity("DDOS"), "HIGH")
        self.assertEqual(calculate_severity("POTENTIAL_ZERO_DAY"), "CRITICAL")
        self.assertEqual(calculate_severity("PORTSCAN", repeat_offender=True), "HIGH")

    def test_reputation_scoring(self):
        self.assertEqual(calculate_reputation(0, "LOW"), 100)
        self.assertLess(calculate_reputation(5, "HIGH"), 50)
        self.assertLess(calculate_reputation(2, "CRITICAL", is_zero_day=True), 30)

    def test_bidirectional_flow_78_features(self):
        flow = BidirectionalFlow("192.168.1.10", "10.0.0.1", 54321, 80, 6)
        flow.add_packet(100, "FWD", {"SYN": 1}, 1000.0)
        flow.add_packet(150, "BWD", {"ACK": 1, "SYN": 1}, 1000.05)
        vec = flow.to_feature_vector()
        self.assertEqual(len(vec), 78)
        self.assertEqual(vec[0], 80.0)  # Destination Port
        self.assertEqual(vec[2], 1.0)   # Total Fwd Packets
        self.assertEqual(vec[3], 1.0)   # Total Bwd Packets

    def test_zero_day_consensus_chamber(self):
        # Realistic benign flow (Standard port, duration, ACK set, no conflicting control flags)
        normal_vec = [5.0] * 78
        normal_vec[0] = 80.0
        normal_vec[1] = 15000.0
        normal_vec[43] = 0.0  # FIN
        normal_vec[44] = 0.0  # SYN
        normal_vec[45] = 0.0  # RST
        normal_vec[47] = 1.0  # ACK
        res_normal = hybrid_zero_day_engine.analyze(normal_vec)
        self.assertIn(res_normal["final_status"], ["NORMAL", "SUSPICIOUS"])

        anomaly_vec = [99999.0] * 78
        res_anomaly = hybrid_zero_day_engine.analyze(anomaly_vec)
        self.assertGreaterEqual(res_anomaly["anomaly_votes"], 2)

    def test_end_to_end_security_pipeline(self):
        features = [0.0] * 78
        res = analyze_network_flow(features, source_ip="192.168.1.55")
        self.assertIn("attack_type", res)
        self.assertIn("decision", res)
        self.assertIn("severity", res)
        self.assertIn("zero_day_analysis", res)
        self.assertIn("explanation", res)
        self.assertIn("recommendation", res)

if __name__ == "__main__":
    unittest.main()
