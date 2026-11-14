# Research Report 00: Repository Audit & Universal Feature Inventory
**System:** Guardian-Sentinel  
**Repository:** https://github.com/Tarunsingh465/Guardian-Sentinel  
**Audit Date:** November 2026  
**Auditor:** Senior Data Scientist & Cybersecurity Systems Architect  

---

## 1. Executive Summary & Audit Mandate
This document establishes the official repository audit, architectural assessment, and complete feature inventory for **Guardian-Sentinel**. In accordance with the Universal Existing Functionality Preservation rule, all working features, API contracts, dashboard widgets, network flow engines, and security modules are documented and preserved.

The project is an autonomous, deep-learning-powered, real-time Network Intrusion Detection (NIDS) and Intrusion Prevention (NIPS) system built for CPU-efficient execution on an Intel Core i5 with 8 GB RAM under Windows 10.

---

## 2. Directory Structure & Module Audit

```
Guardian-Sentinel/
├── config.py                      # Dynamic path management, threshold calibration, and schema
├── run.py                         # Master CLI launcher (API, Dashboard, Research, All)
├── simulate_traffic.py            # High-throughput flow generator & API stress tester
├── requirements.txt               # Pinned Python 3.11 CPU-compatible dependencies
├── .gitignore                     # Exclusion rules for virtualenvs, binaries, and dataset dumps
├── README.md                      # Primary documentation & architecture diagrams
│
├── guardian/                      # Core Production Package
│   ├── api/                       # High-Performance FastAPI Microservice
│   │   ├── main.py                # FastAPI initialization, CORS, health checks
│   │   ├── routes.py              # Endpoints: /predict, /predict/batch, /sniffer, /threats
│   │   ├── schemas.py             # Pydantic v2 data models & validation schemas
│   │   └── database.py            # SQLite persistence via SQLAlchemy ORM (traffic_logs)
│   │
│   ├── core/                      # Detection & AI Agent Logic
│   │   ├── detection/             # Supervised multi-class attack classification
│   │   │   └── classifier.py      # Random Forest & TensorFlow Neural integration
│   │   ├── zero_day/              # Unsupervised Zero-Day Anomaly Detection
│   │   │   ├── autoencoder.py     # Deep Autoencoder reconstruction loss (MSE)
│   │   │   ├── isolation_forest.py# Tree-based partition outlier detector
│   │   │   ├── one_class_svm.py   # RBF max-margin novelty boundary
│   │   │   └── hybrid_engine.py   # 3-Model consensus voting chamber
│   │   ├── agent/                 # Autonomous Security Operations
│   │   │   ├── security_agent.py  # Master end-to-end pipeline coordinator
│   │   │   ├── normalizer.py      # Canonical attack taxonomy normalizer
│   │   │   ├── severity.py        # Multi-factor dynamic severity engine
│   │   │   ├── memory.py          # Stateful IP attack history & repeat offender tracking
│   │   │   ├── reputation.py      # Algorithmic IP reputation score (0 - 100)
│   │   │   ├── containment.py     # Tiered containment playbooks (ALLOW, MONITOR, TEMP_BAN, BLOCK)
│   │   │   ├── firewall.py        # Safe OS firewall adapter (Simulation, netsh, iptables)
│   │   │   └── explainability.py  # Plain-English SOC incident triage rationales
│   │   └── features/              # Preprocessing & Representation Learning
│   │       └── engineer.py        # 78 -> 93 dimensional feature engineering & OHE
│   │
│   ├── sniffer/                   # Real-Time Network Packet Ingestion Layer
│   │   ├── flow_engine.py         # Bidirectional 5-tuple flow aggregator (78 CIC features)
│   │   ├── packet_sniffer.py      # Live packet listener (Scapy / raw socket / fallback)
│   │   └── live_capture.py        # Background capture worker & threat dispatcher
│   │
│   └── dashboard/                 # Streamlit SOC Analyst Console
│       └── app.py                 # Multi-tab interactive UI (SOC, Sniffer, Research, Sandbox)
│
├── training/                      # Model Training & Preprocessing Pipelines
│   └── train_all_models.py        # Calibrated training & artifact generation
│
├── research/                      # Executable Statistical & Research Engines
│   ├── statistical_testing.py     # Parametric & non-parametric hypothesis tests
│   ├── eda_engine.py              # Advanced feature distributions, kurtosis, VIF audit
│   └── imbalance_benchmark.py     # Focal loss & class imbalance evaluation
│
├── reports/                       # Formal Research Documentation
│   ├── 00_REPOSITORY_AUDIT_AND_FEATURE_INVENTORY.md
│   ├── 01_ADVANCED_EDA_REPORT.md
│   ├── 02_HYPOTHESIS_TESTING_REPORT.md
│   ├── 03_CLASS_IMBALANCE_STUDY.md
│   ├── 04_MODEL_ABLATION_AND_BENCHMARK.md
│   └── 05_FEATURE_ENGINEERING_REPORT.md
│
├── tests/                         # Unit & Integration Tests
│   └── test_pipeline.py           # Verification of normalizer, severity, OHE, flow engine
│
├── models/                        # Serialized Model Artifacts
│   ├── ids_classifier.pkl         # Trained Supervised Classifier
│   ├── isolation_forest.pkl       # Trained Isolation Forest Anomaly Detector
│   ├── one_class_svm.pkl          # Trained One-Class SVM Novelty Model
│   ├── pca_autoencoder.pkl        # Subspace Autoencoder Reconstruction Model
│   └── reconstruction_threshold.pkl # Calibrated 95th percentile MSE threshold (0.116056)
│
└── data/processed/                # Preprocessing Artifacts
    ├── scaler.pkl                 # Fitted StandardScaler (93 dimensions)
    ├── label_encoder.pkl          # Fitted LabelEncoder for classes
    └── target_ohe.pkl             # Fitted OneHotEncoder for target classes
```

---

## 3. Universal Feature Inventory

| Feature ID | Feature Name | Implementation Files | Expected Responsibility | Observed Behavior | Status | Verification Protocol |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F-01** | **78-Dim Flow Extraction** | `guardian/sniffer/flow_engine.py` | Assembles packets into 5-tuple bidirectional flows and extracts 78 CIC-IDS2017 features. | Correctly aggregates packet timestamps, flag counts, and byte distributions. | **COMPLETE** | `test_bidirectional_flow_78_features` passes. |
| **F-02** | **Live Network Sniffer** | `guardian/sniffer/packet_sniffer.py`, `live_capture.py` | Captures inbound & outbound packets from local NIC and extracts flows. | Scapy capture with safe fallback simulation when unprivileged. | **COMPLETE** | Live 2-second capture test verified (13 pkts). |
| **F-03** | **Feature Engineering & OHE** | `guardian/core/features/engineer.py` | Prunes 5 collinear columns, applies $\log_{1p}$ compression, adds 10 OHE features & 10 cyber ratios (93 total). | Transforms raw 78-dim vectors to 93-dim vectors orthogonally. | **COMPLETE** | Verified shape `(N, 93)`, OHE bits active. |
| **F-04** | **Supervised Attack Classification** | `guardian/core/detection/classifier.py` | Classifies known attack vectors (`BENIGN`, `DDOS`, `PORTSCAN`, `BRUTEFORCE`). | Correctly predicts class and probability score with model fallback. | **COMPLETE** | Verified in test suite. |
| **F-05** | **Zero-Day Autoencoder** | `guardian/core/zero_day/autoencoder.py` | Evaluates flow reconstruction MSE against 95th percentile threshold ($\tau_{95} = 0.116$). | Reconstructs flows and flags $\text{MSE} > \tau_{95}$ as anomaly. | **COMPLETE** | Verified with out-of-distribution vectors. |
| **F-06** | **Isolation Forest Detector**| `guardian/core/zero_day/isolation_forest.py` | Partitions feature space to detect isolated outliers. | Evaluates tree path length decision function. | **COMPLETE** | Verified on scaled samples. |
| **F-07** | **One-Class SVM Detector** | `guardian/core/zero_day/one_class_svm.py` | RBF max-margin boundary enclosing benign traffic. | Computes signed distance to hyperplane. | **COMPLETE** | Verified on scaled samples. |
| **F-08** | **Hybrid Voting Chamber** | `guardian/core/zero_day/hybrid_engine.py` | Tallies votes across Autoencoder, Isolation Forest, and One-Class SVM. | 0: Normal, 1: Suspicious, 2: High Anomaly, 3: Potential Zero-Day. | **COMPLETE** | Verified consensus voting logic. |
| **F-09** | **Attack Normalizer** | `guardian/core/agent/normalizer.py` | Standardizes raw attack labels into unified canonical uppercase taxonomy. | Standardizes 15+ attack variants cleanly. | **COMPLETE** | `test_normalizer` passes. |
| **F-10** | **Dynamic Severity Scoring**| `guardian/core/agent/severity.py` | Calculates risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | Escalates based on attack type, repeat offenders, and zero-day status. | **COMPLETE** | `test_severity_calculation` passes. |
| **F-11** | **Stateful Threat Memory** | `guardian/core/agent/memory.py` | Tracks per-IP attack counts, unique vectors, timestamps, and repeat offenders. | Thread-safe in-memory cache tracking offender history. | **COMPLETE** | Verified repeat-offender flag toggle. |
| **F-12** | **IP Reputation Engine** | `guardian/core/agent/reputation.py` | Computes empirical trust score between 0 and 100. | Decrements based on severity, frequency, and zero-day status. | **COMPLETE** | `test_reputation_scoring` passes. |
| **F-13** | **Containment Playbooks** | `guardian/core/agent/containment.py` | Determines action: `ALLOW`, `MONITOR`, `TEMP_BAN`, `BLOCK`. | Manages timed temporary bans and critical blocks. | **COMPLETE** | Active ban expiration logic verified. |
| **F-14** | **Firewall Adapter** | `guardian/core/agent/firewall.py` | Abstraction layer for OS firewall rule enforcement. | SIMULATION mode active by default; hooks for Windows `netsh` and Linux `iptables`. | **COMPLETE** | Verified rule generation & audit logging. |
| **F-15** | **Explainability Engine** | `guardian/core/agent/explainability.py` | Produces plain-English SOC triage rationales and playbooks. | Generates clear explanation and actionable mitigation steps. | **COMPLETE** | Verified in end-to-end tests. |
| **F-16** | **FastAPI Microservice** | `guardian/api/main.py`, `routes.py` | Async high-throughput REST API with OpenAPI/Swagger docs. | Endpoints: `/predict`, `/predict/batch`, `/sniffer`, `/threats`. | **COMPLETE** | Verified compilation and Pydantic schemas. |
| **F-17** | **SQLite DB Logging** | `guardian/api/database.py` | Persistent relational storage for security incidents. | SQLAlchemy models for `DBTrafficLog` with auto-migration. | **COMPLETE** | SQLite tables initialized automatically. |
| **F-18** | **Streamlit SOC Console** | `guardian/dashboard/app.py` | 4-tab interactive analyst console with Plotly charts and live feed. | Command Center, Packet Sniffer, Research Lab, Zero-Day Sandbox. | **COMPLETE** | Verified compile and widget rendering. |
| **F-19** | **Statistical Testing Suite**| `research/statistical_testing.py` | Executes 5 formal parametric/non-parametric hypothesis tests. | Mann-Whitney U, KS 2-Sample, Welch's t, Chi-Square, Levene. | **COMPLETE** | Verified with test statistics & p-values. |
| **F-20** | **Advanced EDA Engine** | `research/eda_engine.py` | Analyzes skewness, kurtosis, VIF multicollinearity, and Mutual Information. | Identifies 5 collinear pairs and ranks top MI features. | **COMPLETE** | Verified execution & JSON output. |
| **F-21** | **Class Imbalance Suite** | `research/imbalance_benchmark.py` | Benchmarks Baseline vs RUS vs SMOTE vs Class Weights vs Focal Loss. | Compares PR-AUC, F1-Macro, and minority recall on rare attacks. | **COMPLETE** | Verified output metrics. |
| **F-22** | **Master CLI Launcher** | `run.py` | Unified runner: `--api`, `--dashboard`, `--research`, `--all`. | Launches respective processes cleanly from command line. | **COMPLETE** | Verified CLI execution. |
| **F-23** | **Traffic Simulator** | `simulate_traffic.py` | Streams synthetic and real test flows to the API. | Sends POST requests with randomized attack profiles. | **COMPLETE** | Verified streaming generator. |

---

## 4. Preserved Working Interfaces & Dependencies
1. **Schema Interface:** `CICIDS_FEATURE_COUNT = 78` in `config.py` remains the external contract. Any raw 78-element array is automatically expanded to 93 dimensions via `feature_engineer.transform_single_flow`.
2. **API Contract:** `POST /api/v1/predict` input payload `{ "features": [...78 floats...], "source_ip": "...", "destination_ip": "..." }` is strictly maintained.
3. **Database Schema:** `DBTrafficLog` columns (`source_ip`, `attack_type`, `confidence`, `severity`, `decision`, `reputation_score`, `is_zero_day`, `reconstruction_error`, `explanation`, `recommendation`) remain unchanged for backward compatibility.
4. **Streamlit Console:** The 4 tabs (`SOC Command Center`, `Live Network Packet Sniffer`, `Data Science & Research Lab`, `Zero-Day Anomaly Sandbox`) remain fully intact with existing metrics, charts, and interactive controls.
