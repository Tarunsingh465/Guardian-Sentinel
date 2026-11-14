"""
Guardian-Sentinel Configuration Module
Root-relative dynamic path resolution, threshold calibration, and hyperparameters.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
GUARDIAN_DIR = BASE_DIR / "guardian"
DATA_DIR = BASE_DIR / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
RESEARCH_DIR = BASE_DIR / "research"

# Database Path
DB_PATH = BASE_DIR / "guardian_intel.db"

# Model Paths
AUTOENCODER_MODEL_PATH = MODELS_DIR / "autoencoder_model.keras"
RECONSTRUCTION_THRESHOLD_PATH = MODELS_DIR / "reconstruction_threshold.pkl"
ISOLATION_FOREST_PATH = MODELS_DIR / "isolation_forest.pkl"
ONE_CLASS_SVM_PATH = MODELS_DIR / "one_class_svm.pkl"
SUPERVISED_MODEL_PATH = MODELS_DIR / "ids_classifier.pkl"
SCALER_PATH = PROCESSED_DATA_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = PROCESSED_DATA_DIR / "label_encoder.pkl"

# Zero-Day & Anomaly Calibration Defaults
DEFAULT_RECONSTRUCTION_THRESHOLD = 0.042500  # 95th percentile reconstruction MSE on benign traffic
ISOLATION_CONTAMINATION = 0.05
SVM_NU = 0.05

# Network Sniffing Defaults
DEFAULT_SNIFFER_INTERFACE = None  # None selects default interface (or 'Ethernet', 'Wi-Fi')
FLOW_TIMEOUT_SECONDS = 15.0       # Flow expiration window for active connections
MAX_LIVE_FLOWS_IN_MEMORY = 500

# Server Defaults
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", 8000))
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 8501))

# Feature Schema
CICIDS_FEATURE_COUNT = 78
FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]
