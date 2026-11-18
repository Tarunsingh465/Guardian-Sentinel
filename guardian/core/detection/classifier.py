"""
Guardian-Sentinel: Multi-Class Attack Classifier
Supervised model identifying known attack signatures from CIC-IDS2017 features.
"""

import numpy as np
import joblib
from pathlib import Path
from typing import Tuple, Dict, Any

from config import (
    SUPERVISED_MODEL_PATH,
    NEURAL_MLP_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH
)
from guardian.core.agent.normalizer import normalize_attack_name
from guardian.core.features.engineer import feature_engineer

class AttackClassifier:
    def __init__(self):
        self.model = None
        self.neural_model = None
        self.scaler = None
        self.encoder = None
        self._load()

    def _load(self):
        try:
            if SCALER_PATH.exists():
                self.scaler = joblib.load(SCALER_PATH)
            if LABEL_ENCODER_PATH.exists():
                self.encoder = joblib.load(LABEL_ENCODER_PATH)
            
            # 1. Attempt to load Primary Deep Learning Keras Neural MLP
            if NEURAL_MLP_PATH.exists():
                try:
                    import tensorflow as tf
                    self.neural_model = tf.keras.models.load_model(str(NEURAL_MLP_PATH))
                except Exception:
                    self.neural_model = None

            # 2. Load Classical Supervised Model as high-speed ensemble/fallback
            if SUPERVISED_MODEL_PATH.exists():
                self.model = joblib.load(SUPERVISED_MODEL_PATH)
        except Exception:
            self.model = None
            self.neural_model = None

    def get_model_info(self) -> Dict[str, Any]:
        """Returns metadata about the active detection engine."""
        dim = getattr(self.scaler, "n_features_in_", 80) if self.scaler is not None else 80
        if self.neural_model is not None:
            return {
                "engine_type": "DEEP_NEURAL_MLP",
                "framework": "TensorFlow / Keras CPU",
                "input_dim": dim,
                "status": "ACTIVE_PRIMARY"
            }
        elif self.model is not None:
            return {
                "engine_type": "RANDOM_FOREST_ENSEMBLE",
                "framework": "Scikit-Learn",
                "input_dim": dim,
                "status": "ACTIVE_FALLBACK"
            }
        else:
            return {
                "engine_type": "DOMAIN_HEURISTIC",
                "framework": "Rule-Based Expert System",
                "input_dim": 78,
                "status": "HEURISTIC_STANDBY"
            }

    def predict(self, features: list, protocol: int = 6) -> Tuple[str, float, np.ndarray]:
        """
        Takes 78 flow features, applies domain feature engineering & OHE (93 features),
        returns (predicted_label, confidence, scaled_vector).
        Prioritizes Deep Neural MLP with graceful fallback to Random Forest.
        """
        arr = np.array(features, dtype=np.float32).reshape(1, -1)
        if arr.shape[1] == 78:
            engineered_vec = feature_engineer.transform_single_flow(features, protocol=protocol).reshape(1, -1)
        else:
            engineered_vec = arr

        # Scale features
        if self.scaler is not None:
            scaled = self.scaler.transform(engineered_vec)
        else:
            # Fallback robust min-max normalization
            scaled = np.clip(engineered_vec / 1000.0, -10.0, 10.0)

        # 1. Predict with Primary Deep Neural MLP if available
        if self.neural_model is not None and self.encoder is not None:
            try:
                probs = self.neural_model.predict(scaled, verbose=0)[0]
                top_idx = int(np.argmax(probs))
                conf = float(probs[top_idx])
                raw_label = str(self.encoder.inverse_transform([top_idx])[0])
                return normalize_attack_name(raw_label), conf, scaled
            except Exception:
                pass  # Fall back to classical model if tensor evaluation fails

        # 2. Predict with Classical Trained Model if available
        if self.model is not None and self.encoder is not None:
            probs = self.model.predict_proba(scaled)[0]
            top_idx = int(np.argmax(probs))
            conf = float(probs[top_idx])
            raw_label = str(self.encoder.inverse_transform([top_idx])[0])
            return normalize_attack_name(raw_label), conf, scaled

        # High-Fidelity Domain Heuristic Classifier
        # Evaluates signature network traits (SYN floods, Port Scans, volumetric bursts)
        # Allows instant operation if trained binary is not present
        flow_duration = float(arr[0, 1]) if arr.shape[1] > 1 else 0
        total_fwd_pkts = float(arr[0, 2]) if arr.shape[1] > 2 else 0
        bwd_pkts = float(arr[0, 3]) if arr.shape[1] > 3 else 0
        flow_bytes_sec = float(arr[0, 14]) if arr.shape[1] > 14 else 0
        syn_flags = float(arr[0, 44]) if arr.shape[1] > 44 else 0
        dst_port = float(arr[0, 0]) if arr.shape[1] > 0 else 0

        # DDoS Signature: Massive packets/sec or high byte rate with high forward packets
        if flow_bytes_sec > 100000 or (total_fwd_pkts > 200 and flow_duration < 1000):
            return "DDOS", 0.94, scaled

        # PortScan Signature: Minimal backward packets, syn flags or rapid sweeps
        if bwd_pkts == 0 and total_fwd_pkts <= 2 and flow_duration < 50:
            return "PORTSCAN", 0.91, scaled

        # SSH / FTP BruteForce Signature
        if dst_port in [22.0, 2222.0] and total_fwd_pkts > 15:
            return "BRUTEFORCE_SSH", 0.88, scaled
        if dst_port in [21.0, 2121.0] and total_fwd_pkts > 15:
            return "BRUTEFORCE_FTP", 0.86, scaled

        # Default Benign
        return "BENIGN", 0.96, scaled

# Singleton
attack_classifier = AttackClassifier()
