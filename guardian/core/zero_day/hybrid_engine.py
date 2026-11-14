"""
Guardian-Sentinel: Hybrid Zero-Day Anomaly Detection Engine
Ensembles Deep Autoencoder, Isolation Forest, and One-Class SVM via consensus voting.
"""

import numpy as np
from typing import Dict, Any

from guardian.core.zero_day.autoencoder import AutoencoderDetector
from guardian.core.zero_day.isolation_forest import IsolationForestDetector
from guardian.core.zero_day.one_class_svm import OneClassSVMDetector

class HybridZeroDayEngine:
    def __init__(self):
        self.autoencoder = AutoencoderDetector()
        self.isolation_forest = IsolationForestDetector()
        self.one_class_svm = OneClassSVMDetector()

    def analyze(self, sample: np.ndarray) -> Dict[str, Any]:
        """
        Runs sample across all three anomaly detectors and tallies consensus votes.
        """
        auto_res = self.autoencoder.detect(sample)
        iso_res = self.isolation_forest.detect(sample)
        svm_res = self.one_class_svm.detect(sample)

        anomaly_votes = 0
        if auto_res["status"] != "NORMAL":
            anomaly_votes += 1
        if iso_res["status"] != "NORMAL":
            anomaly_votes += 1
        if svm_res["status"] != "NORMAL":
            anomaly_votes += 1

        if anomaly_votes == 0:
            final_status = "NORMAL"
            is_zero_day = False
        elif anomaly_votes == 1:
            final_status = "SUSPICIOUS"
            is_zero_day = False
        elif anomaly_votes == 2:
            final_status = "HIGH_ANOMALY"
            is_zero_day = False
        else:
            final_status = "POTENTIAL_ZERO_DAY"
            is_zero_day = True

        return {
            "final_status": final_status,
            "is_zero_day": is_zero_day,
            "anomaly_votes": anomaly_votes,
            "total_models": 3,
            "reconstruction_error": auto_res["reconstruction_error"],
            "threshold": auto_res["threshold"],
            "autoencoder": auto_res,
            "isolation_forest": iso_res,
            "one_class_svm": svm_res
        }

# Singleton
hybrid_zero_day_engine = HybridZeroDayEngine()
