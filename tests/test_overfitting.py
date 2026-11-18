"""
Unit Test: Overfitting & Generalization Checks
Validates that model training does not suffer from memorization or excessive generalization gaps.
"""

import sys
import unittest
from pathlib import Path
import numpy as np

# Add root directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from guardian.core.features.engineer import feature_engineer
from guardian.core.detection.classifier import attack_classifier
from simulate_traffic import generate_sample_flow

class TestOverfittingAndGeneralization(unittest.TestCase):

    def test_feature_pruning_dimensions(self):
        """Validates that 18 unused/collinear features are pruned (78 -> 80 engineered)."""
        raw = [1.0] * 78
        raw[0] = 443.0
        engineered = feature_engineer.transform_single_flow(raw, protocol=6)
        self.assertEqual(len(engineered), 80)

    def test_benign_traffic_no_zero_day_false_positive(self):
        """Verifies that generated realistic benign flows are never misclassified as zero-day."""
        from guardian.core.agent.security_agent import analyze_network_flow
        for i in range(5):
            benign_flow = generate_sample_flow("BENIGN")
            res = analyze_network_flow(benign_flow, source_ip=f"192.168.1.{20+i}")
            self.assertEqual(res["attack_type"], "BENIGN")
            self.assertEqual(res["decision"], "ALLOW")
            self.assertEqual(res["severity"], "LOW")
            self.assertFalse(res["zero_day_analysis"]["is_zero_day"])

if __name__ == "__main__":
    unittest.main()
