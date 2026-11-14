"""
Guardian-Sentinel: Isolation Forest Anomaly Detector
Tree-based partition algorithm isolating anomalies near tree roots.
"""

import numpy as np
import joblib
from pathlib import Path

class IsolationForestDetector:
    def __init__(self, model_path: Path = None):
        from config import ISOLATION_FOREST_PATH
        self.model_path = model_path or ISOLATION_FOREST_PATH
        self.model = None
        self.scaler = None
        self._load()

    def _load(self):
        try:
            from config import SCALER_PATH
            if SCALER_PATH.exists():
                self.scaler = joblib.load(SCALER_PATH)
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
        except Exception:
            self.model = None

    def detect(self, sample: np.ndarray) -> dict:
        sample_vec = np.array(sample, dtype=np.float32).reshape(1, -1)
        if sample_vec.shape[1] == 78:
            from guardian.core.features.engineer import feature_engineer
            sample_vec = feature_engineer.transform_single_flow(sample_vec[0]).reshape(1, -1)
            if self.scaler is not None:
                sample_vec = self.scaler.transform(sample_vec)

        if self.model is not None:
            pred = self.model.predict(sample_vec)
            score = float(self.model.decision_function(sample_vec)[0])
            status = "NORMAL" if pred[0] == 1 else "ANOMALY"
        else:
            # Analytical fallback: check distance from typical centered flow space
            mean_dist = float(np.mean(np.abs(sample_vec)))
            score = 0.15 - (mean_dist * 0.05)
            status = "NORMAL" if score > 0 else "ANOMALY"

        return {
            "status": status,
            "score": round(float(score), 6)
        }
