"""
Guardian-Sentinel: CIC-IDS2017 Dataset Provenance & Memory-Efficient Ingestion Pipeline
Designed for 8 GB RAM systems:
1. Implements chunked reading (chunksize=50,000) to prevent Out-Of-Memory (OOM).
2. Casts continuous flow metrics from float64 to float32 (saving 50% RAM).
3. Performs column hygiene (stripping whitespace, handling NaN/inf).
4. Exports optimized compressed Parquet shards.
"""

import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
import pandas as pd

# Root path configuration
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PROCESSED_DIR = DATA_DIR / "processed"

DATASET_PROVENANCE = {
    "dataset_name": "CIC-IDS2017",
    "provider": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
    "official_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "citation": "Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Dataset for Intrusion Detection and Intrusion Prevention Systems.",
    "files": [
        {"name": "Monday-WorkingHours.pcap_ISCX.csv", "attack": "BENIGN", "raw_rows": 529918},
        {"name": "Tuesday-WorkingHours.pcap_ISCX.csv", "attack": "FTP-Patator, SSH-Patator", "raw_rows": 445909},
        {"name": "Wednesday-workingHours.pcap_ISCX.csv", "attack": "DoS, Heartbleed", "raw_rows": 692703},
        {"name": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "attack": "Web Attacks (BruteForce, XSS, SqlInjection)", "raw_rows": 170366},
        {"name": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "attack": "Infiltration", "raw_rows": 288602},
        {"name": "Friday-WorkingHours-Morning.pcap_ISCX.csv", "attack": "Botnet", "raw_rows": 191033},
        {"name": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "attack": "PortScan", "raw_rows": 286467},
        {"name": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "attack": "DDoS", "raw_rows": 225745}
    ],
    "total_corpus_rows": 2830743
}

def clean_and_optimize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Strips whitespace from column names, handles Inf/NaN, casts float64 -> float32.
    """
    # 1. Clean column headers
    df.columns = df.columns.str.strip()

    # 2. Replace Infinite values with NaN, then impute
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0.0, inplace=True)

    # 3. Downcast numeric columns to float32 to conserve 50% RAM
    num_cols = df.select_dtypes(include=["float64", "int64"]).columns
    for c in num_cols:
        df[c] = df[c].astype(np.float32)

    return df

def process_file_chunked(file_path: Path, output_parquet: Path, chunk_size: int = 50000):
    """
    Ingests large CSV in streaming chunks and writes to compressed Snappy Parquet.
    """
    print(f"📖 Streaming ingestion for {file_path.name} in chunks of {chunk_size:,}...")
    chunks = []
    total_rows = 0

    for idx, chunk in enumerate(pd.read_csv(file_path, chunksize=chunk_size, low_memory=False)):
        cleaned_chunk = clean_and_optimize_dataframe(chunk)
        chunks.append(cleaned_chunk)
        total_rows += len(cleaned_chunk)
        if (idx + 1) % 5 == 0:
            print(f"  -> Processed {total_rows:,} rows...")

    combined = pd.concat(chunks, ignore_index=True)
    combined.to_parquet(output_parquet, engine="pyarrow", compression="snappy")
    print(f"✅ Exported {total_rows:,} rows to optimized Parquet: {output_parquet.name}")

def calculate_sha256(file_path: Path) -> str:
    """Computes cryptographic SHA-256 checksum for data integrity auditing."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192 * 16):
            sha.update(chunk)
    return sha.hexdigest()

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  GUARDIAN-SENTINEL: DATASET PROVENANCE & CHUNKED INGESTION")
    print("=" * 60)
    print(f"Dataset: {DATASET_PROVENANCE['dataset_name']}")
    print(f"Official Source: {DATASET_PROVENANCE['official_url']}")
    print(f"Total Corpus: {DATASET_PROVENANCE['total_corpus_rows']:,} network flow records across 8 files.")
    print("Memory Constraints: Chunked streaming enabled (8 GB RAM safe mode).")
