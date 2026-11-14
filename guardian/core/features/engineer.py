"""
Guardian-Sentinel: Advanced Feature Engineering & Categorical Encoding Pipeline
Implements:
1. One-Hot Encoding (OHE) for Protocol and Port categories.
2. Non-linear log1p transformations for heavy-tailed flow attributes.
3. Domain-specific Cyber Flow Ratios (Asymmetry, Header-to-Payload, Bytes/Pkt).
4. Composite TCP Attack Flag signatures (SYN flood probes, XMAS scans, NULL scans).
5. Collinear duplicate leakage pruning.
6. Target One-Hot Encoding (OHE) for Neural Network loss functions.
"""

import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Any, Union
from sklearn.preprocessing import OneHotEncoder

class NetworkFeatureEngineer:
    """
    Transforms raw 78 CIC-IDS2017 features into an enhanced, engineered feature vector.
    """
    def __init__(self):
        # Target One-Hot Encoder
        self.target_ohe = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
        self.fitted_classes = None

    def fit_target_encoder(self, y: Union[List[str], np.ndarray]):
        """
        Fits One-Hot Encoder on categorical target class names.
        """
        arr = np.array(y).reshape(-1, 1)
        self.target_ohe.fit(arr)
        self.fitted_classes = list(self.target_ohe.categories_[0])
        return self

    def transform_target_ohe(self, y: Union[List[str], np.ndarray]) -> np.ndarray:
        """
        Converts labels to one-hot binary matrix: e.g. 'DDOS' -> [0, 1, 0, 0].
        """
        arr = np.array(y).reshape(-1, 1)
        return self.target_ohe.transform(arr)

    def inverse_transform_target(self, ohe_matrix: np.ndarray) -> List[str]:
        """
        Converts one-hot probability vectors back to string labels.
        """
        return list(self.target_ohe.inverse_transform(ohe_matrix).ravel())

    def transform_single_flow(self, raw_78: List[float], protocol: int = 6) -> np.ndarray:
        """
        Transforms a single 78-feature vector into an engineered feature vector.
        """
        return self.transform_batch(np.array(raw_78).reshape(1, -1), protocols=[protocol])[0]

    def transform_batch(self, X: np.ndarray, protocols: List[int] = None) -> np.ndarray:
        """
        Processes batch matrix of raw 78-dimensional flows into engineered feature space.
        """
        X = np.array(X, dtype=np.float32)
        n_samples = X.shape[0]

        if protocols is None:
            protocols = [6] * n_samples  # Default TCP if not passed
        protocols = np.array(protocols)

        # ----------------------------------------------------
        # 1. CATEGORICAL ONE-HOT ENCODING (OHE)
        # ----------------------------------------------------
        # A. Protocol OHE (TCP=6, UDP=17, ICMP=1, Other)
        ohe_proto_tcp = (protocols == 6).astype(np.float32).reshape(-1, 1)
        ohe_proto_udp = (protocols == 17).astype(np.float32).reshape(-1, 1)
        ohe_proto_icmp = (protocols == 1).astype(np.float32).reshape(-1, 1)
        ohe_proto_other = (~np.isin(protocols, [1, 6, 17])).astype(np.float32).reshape(-1, 1)

        # B. Port Category OHE (Destination Port is col 0)
        dst_ports = X[:, 0]
        ohe_port_wellknown = ((dst_ports >= 0) & (dst_ports <= 1023)).astype(np.float32).reshape(-1, 1)
        ohe_port_registered = ((dst_ports >= 1024) & (dst_ports <= 49151)).astype(np.float32).reshape(-1, 1)
        ohe_port_ephemeral = (dst_ports >= 49152).astype(np.float32).reshape(-1, 1)
        ohe_port_web = np.isin(dst_ports, [80, 443, 8080, 8443]).astype(np.float32).reshape(-1, 1)
        ohe_port_remote = np.isin(dst_ports, [22, 23, 21, 3389]).astype(np.float32).reshape(-1, 1)
        ohe_port_dns = (dst_ports == 53).astype(np.float32).reshape(-1, 1)

        categorical_ohe = np.hstack([
            ohe_proto_tcp, ohe_proto_udp, ohe_proto_icmp, ohe_proto_other,
            ohe_port_wellknown, ohe_port_registered, ohe_port_ephemeral,
            ohe_port_web, ohe_port_remote, ohe_port_dns
        ])

        # ----------------------------------------------------
        # 2. DOMAIN CYBER RATIO & ASYMMETRY ENGINEERING
        # ----------------------------------------------------
        fwd_pkts = X[:, 2]
        bwd_pkts = X[:, 3]
        fwd_bytes = X[:, 4]
        bwd_bytes = X[:, 5]
        fwd_hdr_len = X[:, 34]
        bwd_hdr_len = X[:, 35]

        # Flow Asymmetry Ratios (normalized between -1 and +1)
        byte_asymmetry = ((fwd_bytes - bwd_bytes) / (fwd_bytes + bwd_bytes + 1e-5)).reshape(-1, 1)
        packet_asymmetry = ((fwd_pkts - bwd_pkts) / (fwd_pkts + bwd_pkts + 1e-5)).reshape(-1, 1)

        # Header-to-Payload Overhead (High ratio indicates empty probes / SYN floods)
        fwd_hdr_ratio = (fwd_hdr_len / (fwd_bytes + 1e-5)).reshape(-1, 1)
        bwd_hdr_ratio = (bwd_hdr_len / (bwd_bytes + 1e-5)).reshape(-1, 1)

        # Average Bytes per Packet
        avg_bytes_fwd = (fwd_bytes / (fwd_pkts + 1e-5)).reshape(-1, 1)
        avg_bytes_bwd = (bwd_bytes / (bwd_pkts + 1e-5)).reshape(-1, 1)

        # ----------------------------------------------------
        # 3. COMPOSITE ATTACK FLAG SIGNATURES
        # ----------------------------------------------------
        fin = X[:, 43]
        syn = X[:, 44]
        rst = X[:, 45]
        psh = X[:, 46]
        ack = X[:, 47]
        urg = X[:, 48]

        # SYN Flood Probe: SYN without ACK
        is_syn_probe = ((syn > 0) & (ack == 0)).astype(np.float32).reshape(-1, 1)
        # XMAS Scan: FIN + PSH + URG active together
        is_xmas_scan = ((fin > 0) & (psh > 0) & (urg > 0)).astype(np.float32).reshape(-1, 1)
        # NULL Scan: No control flags set
        is_null_scan = ((fin == 0) & (syn == 0) & (rst == 0) & (psh == 0) & (ack == 0) & (urg == 0)).astype(np.float32).reshape(-1, 1)
        # Anomalous FIN-RST combination
        is_fin_rst = ((fin > 0) & (rst > 0)).astype(np.float32).reshape(-1, 1)

        engineered_domain_features = np.hstack([
            byte_asymmetry, packet_asymmetry,
            fwd_hdr_ratio, bwd_hdr_ratio,
            avg_bytes_fwd, avg_bytes_bwd,
            is_syn_probe, is_xmas_scan, is_null_scan, is_fin_rst
        ])

        # ----------------------------------------------------
        # 4. NON-LINEAR LOG1P COMPRESSION ON HEAVY TAILS
        # ----------------------------------------------------
        X_transformed = X.copy()
        # Log1p compress extreme right-skewed columns:
        # col 1 (Duration), 2 (Fwd Pkts), 3 (Bwd Pkts), 4 (Fwd Bytes), 5 (Bwd Bytes),
        # 14 (Flow Bytes/s), 15 (Flow Pkts/s), 16 (IAT Mean), 18 (IAT Max)
        heavy_skew_cols = [1, 2, 3, 4, 5, 14, 15, 16, 18]
        for col_idx in heavy_skew_cols:
            if col_idx < X_transformed.shape[1]:
                X_transformed[:, col_idx] = np.log1p(np.clip(X_transformed[:, col_idx], 0, 1e12))

        # ----------------------------------------------------
        # 5. PRUNING COLLINEAR LEAKAGE COLUMNS
        # Drop Subflow duplicates identified in Research EDA Report #1:
        # Col 55 (Fwd Header Length.1), 62 (Subflow Fwd Pkts), 63 (Subflow Fwd Bytes),
        # 64 (Subflow Bwd Pkts), 65 (Subflow Bwd Bytes)
        # ----------------------------------------------------
        drop_indices = [55, 62, 63, 64, 65]
        keep_indices = [i for i in range(X_transformed.shape[1]) if i not in drop_indices]
        X_pruned = X_transformed[:, keep_indices]

        # ----------------------------------------------------
        # 6. ASSEMBLE FULL ENGINEERED FEATURE MATRIX
        # ----------------------------------------------------
        final_features = np.hstack([
            X_pruned,
            categorical_ohe,
            engineered_domain_features
        ])

        return final_features

# Global instance
feature_engineer = NetworkFeatureEngineer()
