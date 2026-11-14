"""
Guardian-Sentinel: One-Class Support Vector Machine (OC-SVM) Detector
Maps flow vectors into RBF feature space to establish max-margin boundary enclosing normal traffic.
"""

import numpy as np
import joblib
from pathlib import Path

class OneClassSVMDetector:
    def __init__(self, model_path: Path = None):
        from config import ONE_CLASS_SVM_PATH
        self.model_path = model_path or ONE_CLASS_SVM_PATH
        self.model = None
        self._load()

    def _load(self):
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
        except Exception:
            self.model = None

    def detect(self, sample: np.ndarray) -> dict:
        sample_vec = np.array(sample, dtype=np.float32).reshape(1, -1)

        if self.model is not None:
            pred = self.model.predict(sample_vec)
            score = float(self.model.decision_function(sample_vec)[0])
            status = "NORMAL" if pred[0] == 1 else "ANOMALY"
        else:
            # Analytical fallback
            norm_mag = float(np.linalg.norm(sample_vec))
            score = 1.0 - (norm_mag * 0.1)
            status = "NORMAL" if score > 0 else "ANOMALY"

        return {
            "status": status,
            "score": round(float(score), 6)
        }
