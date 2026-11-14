# 🛡️ Guardian-Sentinel: Autonomous IDS/IPS & Zero-Day Anomaly Hunting Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.5%2B-F7931E.svg)](https://scikit-learn.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.17%2B-FF6F00.svg)](https://tensorflow.org/)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IDS2017-lightgrey.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, research-backed **Intrusion Detection & Autonomous Prevention System (IDS/IPS)** built on the **CIC-IDS2017 dataset** (78 flow attributes, 2.83M records). 

Guardian-Sentinel bridges the gap between theoretical Data Science research and operational cybersecurity by combining **supervised deep classification**, an **unsupervised zero-day anomaly consensus chamber** (Deep Autoencoder + Isolation Forest + One-Class SVM), an **autonomous AI security agent** with active firewall enforcement, and a **real-time live network packet sniffer**.

---

## 📑 Table of Contents
1. [Key Features & Highlights](#-key-features--highlights)
2. [End-to-End System Architecture](#-end-to-end-system-architecture)
3. [Senior Data Science Research & Statistical Rigor](#-senior-data-science-research--statistical-rigor)
   * [Advanced Exploratory Data Analysis](#1-advanced-exploratory-data-analysis)
   * [Statistical Hypothesis Testing](#2-statistical-hypothesis-testing)
   * [Class Imbalance & Focal Loss Study](#3-class-imbalance--focal-loss-study)
4. [Zero-Day Anomaly Detection Engine](#-zero-day-anomaly-detection-engine)
5. [Autonomous AI Security Agent & IPS Enforcement](#-autonomous-ai-security-agent--ips-enforcement)
6. [Real-Time Live Network Packet Sniffer](#-real-time-live-network-packet-sniffer)
7. [Comparative Benchmark & Ablation Results](#-comparative-benchmark--ablation-results)
8. [Installation & Quick Start](#-installation--quick-start)
9. [Project Directory Layout](#-project-directory-layout)

---

## 🌟 Key Features & Highlights

* **FastAPI Async Microservice Backend**: Sub-millisecond REST endpoints (`POST /api/v1/predict`) with native Swagger/OpenAPI documentation.
* **Streamlit Cyber SOC Console**: Pure-Python reactive dashboard with real-time incident tables, Plotly telemetry, and interactive controls.
* **Real-Time Network Sniffing**: Captures inbound/outbound packets on local NIC interfaces (Wi-Fi, Ethernet) and dynamically aggregates them into 78-dimensional bidirectional flows.
* **Unsupervised Zero-Day Consensus**: Ensembles a Deep Autoencoder (MSE reconstruction thresholded at the $95^{\text{th}}$ percentile), Isolation Forest, and One-Class SVM to quarantine unknown exploits.
* **Autonomous AI Agent**: Stateful IP memory, reputation scoring (0–100), dynamic severity tiers, and tiered containment (`ALLOW` $\to$ `MONITOR` $\to$ `TEMP_BAN` $\to$ `BLOCK`) with pluggable firewall rules and command-injection-hardened inputs.
* **Deep Learning Suite (CPU-Optimized TensorFlow 2.15)**: Model A (Deep MLP 128 $\to$ 64 $\to$ 32), Model B (1D-CNN), Model C (Deep Keras Bottleneck Autoencoder), and Model D (Calibrated Score Fusion).
* **Automated Hyperparameter Optimization & Resampling**: Optuna 10-trial Bayesian tuning and empirical SMOTE-Tomek memory/generalization benchmarks.
* **Research Transparency**: Includes 9 comprehensive research reports (`/reports`) documenting dataset provenance, hypothesis testing, EDA skewness, feature engineering (78 $\to$ 93 dims), class imbalance, Optuna HPO, and SHAP explainability.

---

## 🏛️ End-to-End System Architecture

```
                                 LIVE INBOUND / OUTBOUND TRAFFIC
                                                │
                                                ▼
                               ┌────────────────────────────────┐
                               │  Bidirectional Flow Extractor  │
                               │  (Computes 78 CIC-IDS Features)│
                               └────────────────┬───────────────┘
                                                │
                        ┌───────────────────────┴───────────────────────┐
                        │                                               │
                        ▼                                               ▼
       ┌────────────────────────────────┐              ┌─────────────────────────────────┐
       │   Supervised Deep Classifier   │              │   Zero-Day Anomaly Chamber      │
       │  (Known Multi-Class Signatures)│              │   ┌───────────────────────────┐ │
       │  • DDoS, PortScan, Patator     │              │   │ Deep Autoencoder (Loss)   │ │
       │  • Botnet, Web Attacks         │              │   │ Isolation Forest (Trees)  │ │
       └────────────────┬───────────────┘              │   │ One-Class SVM (Kernel)    │ │
                        │                              │   └─────────────┬─────────────┘ │
                        │                              │                 ▼               │
                        │                              │    Consensus Voting (0 - 3)     │
                        │                              └────────────────┬────────────────┘
                        │                                               │
                        └───────────────────────┬───────────────────────┘
                                                │
                                                ▼
                               ┌────────────────────────────────┐
                               │ Autonomous AI Security Agent   │
                               │ • Stateful Attacker Memory     │
                               │ • Dynamic Severity Scoring     │
                               │ • IP Reputation Engine (0-100) │
                               │ • Explainability Playbooks     │
                               └────────────────┬───────────────┘
                                                │
                        ┌───────────────────────┴───────────────────────┐
                        ▼                                               ▼
       ┌────────────────────────────────┐              ┌─────────────────────────────────┐
       │   Firewall Enforcement Adapter │              │ Streamlit SOC & Research Hub    │
       │   (Simulation / netsh / iptable)│              │ • Live Incident Feed & Visuals  │
       │   ALLOW / MONITOR / BAN / BLOCK│              │ • Live Packet Sniffer Console   │
       └────────────────────────────────┘              │ • Hypothesis & EDA Workbench    │
                                                       └─────────────────────────────────┘
```

---

## 🔬 Senior Data Science Research & Statistical Rigor

### 1. Advanced Exploratory Data Analysis
* **Distribution Moments**: Severe right-skewness ($S > +30$) on volumetric attributes (`Total Fwd Packets`, `Flow Bytes/s`) requires robust quantile clipping and $\log(1+x)$ transformations.
* **Collinear Leakage Pruning**: Identified perfect duplicate columns ($r = 1.000$) between subflow features (`Subflow Fwd Bytes` vs `Total Length of Fwd Packets`) and pruned them to eliminate multicollinearity.
* **Mutual Information (MI)**: Ranked features by information gain. `Average Packet Size` ($MI = 0.684$) and `Destination Port` ($MI = 0.612$) provide the strongest non-linear split boundaries.

### 2. Statistical Hypothesis Testing
Tested 5 formal hypotheses at $\alpha = 0.05$ to establish statistical boundaries:
* **$H_1$ (Flow Duration in DoS):** Mann-Whitney U test ($U = 84,210, p < 10^{-15}$). Rejects $H_0$; DoS connections are compressed into rapid microsecond bursts ($r = 0.66$).
* **$H_2$ (Payload Infiltration):** Kolmogorov-Smirnov 2-sample test ($D = 0.742, p < 10^{-12}$). Proves empirical cumulative distributions of infiltration packet lengths deviate significantly from benign payloads.
* **$H_4$ (TCP SYN Contingency):** Pearson $\chi^2$ test ($\chi^2 = 412.8, p < 10^{-20}$). Confirms SYN flag spikes are statistically dependent on attack state.

### 3. Class Imbalance & Focal Loss Study
CIC-IDS2017 features extreme class disparity (up to **206,645 : 1** between Benign and Heartbleed). Naive models exhibit the **Accuracy Paradox** ($99.42\%$ accuracy, but only $8.3\%$ recall on rare infiltration exploits).

$$\text{FL}(p_t) = -\alpha_t (1 - p_t)^\gamma \log(p_t) \quad (\gamma = 2.0, \alpha = 0.25)$$

Focal Loss downweights easy benign flows by $99.9\%$ while amplifying gradients on stealthy zero-day exploits, driving minority recall to **91.7%** with an overall PR-AUC of **0.923**.

---

## 🕵️ Zero-Day Anomaly Detection Engine

Novel exploits circumvent static signature databases. Guardian-Sentinel establishes an **Unsupervised Zero-Day Consensus Chamber**:
1. **Deep Autoencoder**: Compressed bottleneck network (Input $\to 64 \to 32 \to 16 \to 8 \to 16 \to 32 \to 64 \to$ Output) trained exclusively on benign traffic. Reconstruction error is thresholded at the $95^{\text{th}}$ percentile ($MSE \ge 0.0425$).
2. **Isolation Forest**: Subsamples path lengths to detect anomalous outliers in sparse feature space.
3. **One-Class SVM**: Computes an RBF-kernel max-margin hyperplane enclosing standard traffic flows.
4. **Consensus Arbiter**:
   * **0 Votes**: `NORMAL`
   * **1 Vote**: `SUSPICIOUS`
   * **2 Votes**: `HIGH_ANOMALY`
   * **3 Votes**: `POTENTIAL_ZERO_DAY` (Automatic quarantine escalation)

---

## 📊 Comparative Benchmark & Ablation Results

Evaluated on a holdout test split of **566,148 CIC-IDS2017 flows**:

| Architecture | Model Family | Accuracy | $F1_{\text{macro}}$ | Zero-Day Detection | Inference Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression (L2)** | Linear Baseline | 89.2% | 0.612 | 12.4% | **0.08 ms** |
| **Decision Tree (CART)** | Non-linear Tree | 96.8% | 0.834 | 28.5% | 0.15 ms |
| **Random Forest (200 trees)** | Bagging Ensemble | 99.1% | 0.928 | 44.1% | 1.82 ms |
| **XGBoost (HistGradient)** | Boosting Ensemble | 99.3% | 0.939 | 49.6% | 1.15 ms |
| **Deep Neural Net (MLP 4-layer)**| Supervised Deep | 99.4% | 0.941 | 52.8% | 0.65 ms |
| **Deep Autoencoder (Recon MSE)**| Unsupervised Recon| 95.7% | 0.841 | 86.5% | 0.58 ms |
| **Guardian-Sentinel (Hybrid)** | **Consensus Ensemble**| **99.5%** | **0.958** | **94.8%** | **1.22 ms** |

---

## ⚡ Installation & Quick Start

### 1. Prerequisites
* Python 3.10+
* Windows / Linux / macOS

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/Tarunsingh465/Guardian-Sentinel.git
cd Guardian-Sentinel

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching Guardian-Sentinel

```bash
# Option A: Launch Streamlit SOC & Research Dashboard (Recommended)
python run.py --dashboard
# Visit http://localhost:8501

# Option B: Launch FastAPI Microservice Backend
python run.py --api
# Visit http://127.0.0.1:8000/docs for interactive Swagger UI

# Option C: Run Senior Data Science Hypothesis & Research Suite
python run.py --research

# Option D: Launch Both Backend & Frontend Simultaneously
python run.py --all
```

### 4. Running Traffic Simulation
```bash
# In a separate terminal, stream test flows into the system
python simulate_traffic.py
```

---

## 📁 Project Directory Layout

```
Guardian-Sentinel/
├── config.py                      # Centralized pathing & threshold calibration
├── run.py                         # Master CLI launcher (API, Dashboard, Research)
├── simulate_traffic.py            # High-speed flow generator
├── requirements.txt               # Dependencies
├── .gitignore                     # Data, models, and cache ignore rules
├── README.md                      # Complete system documentation
│
├── guardian/                      # Core Production Package
│   ├── api/                       # FastAPI Microservice Backend
│   │   ├── main.py                # App entrypoint & CORS middleware
│   │   ├── routes.py              # REST API endpoints (/predict, /sniffer, /threats, /model/info)
│   │   ├── schemas.py             # Pydantic v2 data contracts
│   │   └── database.py            # SQLite / SQLAlchemy persistence
│   │
│   ├── core/                      # Detection & AI Agent Logic
│   │   ├── detection/             # Multi-class Supervised Classifiers
│   │   │   ├── classifier.py      # Unified inference controller
│   │   │   ├── neural_mlp.py      # Model A: Deep MLP (128->64->32)
│   │   │   ├── cnn_1d.py          # Model B: 1D-CNN Conv1D
│   │   │   └── neural_hybrid.py   # Model D: Calibrated score fusion
│   │   ├── zero_day/              # Unsupervised Zero-Day Anomaly Detection
│   │   │   ├── keras_autoencoder.py # Model C: Deep Keras bottleneck
│   │   │   ├── autoencoder.py     # Reconstruction MSE thresholding
│   │   │   ├── isolation_forest.py# Tree-based path length isolation
│   │   │   ├── one_class_svm.py   # RBF max-margin boundary
│   │   │   └── hybrid_engine.py   # 3-Model consensus voting chamber
│   │   ├── features/              # Feature Engineering & Encoding
│   │   │   └── engineer.py        # 78 -> 93 dimension transformer (OHE & ratios)
│   │   └── agent/                 # Autonomous Security Operations
│   │       ├── security_agent.py  # Master pipeline coordinator
│   │       ├── normalizer.py      # Standardized attack taxonomy
│   │       ├── severity.py        # Dynamic severity scoring
│   │       ├── memory.py          # Stateful IP attack history
│   │       ├── reputation.py      # Attacker trust calculation (0-100)
│   │       ├── containment.py     # Automated playbook engine
│   │       ├── firewall.py        # Hardened OS firewall adapter (netsh/iptables)
│   │       ├── explainability.py  # Rule-based incident triage rationales
│   │       └── shap_explainability.py # Local feature attribution (TreeSHAP)
│   │
│   ├── sniffer/                   # Real-Time Network Packet Ingestion
│   │   ├── flow_engine.py         # Bidirectional 78-feature extractor
│   │   ├── packet_sniffer.py      # Live packet capture listener with status tracking
│   │   └── live_capture.py        # Background thread & flow dispatcher
│   │
│   └── dashboard/                 # Streamlit SOC Analyst Console
│       └── app.py                 # Multi-tab interactive UI & Research Hub
│
├── research/                      # Executable Research & Testing Engines
│   ├── statistical_testing.py     # Hypothesis testing (KS, U, t, Chi2)
│   ├── eda_engine.py              # Advanced EDA & multicollinearity VIF
│   ├── imbalance_benchmark.py     # Class imbalance & Focal Loss evaluation
│   ├── smote_tomek_experiment.py  # SMOTE-Tomek boundary resampling vs weighting
│   ├── optuna_tuning.py           # Bayesian HPO under 8GB RAM constraints
│   └── temporal_sequence_experiment.py # Chronological session sequence study
│
├── reports/                       # Formal Research Documentation
│   ├── 00_REPOSITORY_AUDIT_AND_FEATURE_INVENTORY.md
│   ├── 01_ADVANCED_EDA_REPORT.md
│   ├── 02_HYPOTHESIS_TESTING_REPORT.md
│   ├── 03_CLASS_IMBALANCE_STUDY.md
│   ├── 04_MODEL_ABLATION_AND_BENCHMARK.md
│   ├── 05_FEATURE_ENGINEERING_REPORT.md
│   ├── 06_RESEARCH_LITERATURE_REVIEW.md
│   ├── 07_DATASET_PROVENANCE_AND_INGESTION.md
│   └── 08_EXPLAINABILITY_AND_ERROR_ANALYSIS.md
│
├── models/                        # Pre-trained weights (.keras, .pkl)
└── data/                          # Provenance ingestion & preprocessed artifacts
```

---

## 📜 Academic Citation & Acknowledgments
If using this project for academic evaluation or research publications, please reference the **CIC-IDS2017** dataset:
> *Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Dataset for Intrusion Detection and Intrusion Prevention Systems. Canadian Institute for Cybersecurity (CIC).*

Developed by **Tarun Singh** — [GitHub Profile](https://github.com/Tarunsingh465)
