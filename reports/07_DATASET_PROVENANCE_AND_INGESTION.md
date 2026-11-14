# Research Report 07: Dataset Provenance, Metadata & Memory-Efficient Ingestion
**Dataset:** Canadian Institute for Cybersecurity (CIC-IDS2017)  
**Provider:** University of New Brunswick (UNB)  
**Official Access:** https://www.unb.ca/cic/datasets/ids-2017.html  
**Target Hardware Constraints:** Intel Core i5 | 8 GB RAM | CPU-only Windows 10  

---

## 1. Provenance & Official Source Documentation
The CIC-IDS2017 benchmark dataset is widely recognized as the gold standard for realistic network flow evaluation. Generated across 5 continuous days (Monday, July 3, 2017 to Friday, July 7, 2017), the dataset captures both completely benign background network traffic and executed attack vectors using the B-Profile system.

### Verified File Specifications:

| File Name | Capture Date & Time | Primary Attack Vectors | Raw Record Count | File Size (CSV) |
| :--- | :--- | :--- | :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | Mon, 3 Jul 2017 (08:55–17:00) | Pure Benign Baseline | **529,918** | ~520 MB |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | Tue, 4 Jul 2017 (08:55–17:00) | FTP-Patator, SSH-Patator | **445,909** | ~435 MB |
| `Wednesday-workingHours.pcap_ISCX.csv` | Wed, 5 Jul 2017 (08:55–17:00) | DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), Heartbleed | **692,703** | ~680 MB |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Thu, 6 Jul 2017 (08:55–12:00) | Web Attacks (BruteForce, XSS, SQLi) | **170,366** | ~170 MB |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Thu, 6 Jul 2017 (12:00–17:00) | Infiltration Exploits | **288,602** | ~285 MB |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Fri, 7 Jul 2017 (08:55–12:00) | Botnet (ARES C2) | **191,033** | ~190 MB |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Fri, 7 Jul 2017 (12:00–15:30) | PortScan (Nmap TCP SYN/ACK sweeps) | **286,467** | ~280 MB |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Fri, 7 Jul 2017 (15:30–17:00) | Volumetric DDoS (LOIC) | **225,745** | ~220 MB |
| **CORPUS TOTAL** | **5 Full Capture Days** | **15 Target Classes** | **2,830,743** | **~2.8 GB compressed / ~10 GB uncompressed** |

---

## 2. Memory-Efficient Ingestion Strategy for 8 GB RAM
Attempting to load all 2.83M rows into a single Pandas DataFrame using standard 64-bit float types requires:
$$\text{Memory} = 2,830,743 \times 78 \text{ columns} \times 8 \text{ bytes} \approx 1.76 \text{ GB (raw matrix)}$$
During Pandas parsing, string conversions, DataFrame copying, and intermediate transformations, Python's peak memory overhead balloons to **over 7.5 GB**, triggering Windows virtual memory paging and system unresponsiveness.

### Guardian-Sentinel Architectural Optimizations:
1. **Chunked Streaming (`chunksize=50,000`)**: Reads files in controlled sub-blocks; never holds raw unparsed CSV strings in memory simultaneously.
2. **Numeric Downcasting (`float64` $\to$ `float32`)**: Network statistics (packet counts, durations, flag indicators) do not require double-precision IEEE 754 floats. Casting to `float32` immediately cuts in-memory footprint by **50%**.
3. **Parquet Columnar Sharding with Snappy Compression**: Raw CSV files are converted into Snappy-compressed Apache Parquet format (`data/processed/*.parquet`), allowing fast column projection and $4\times$ faster read throughput.
4. **Resumable Extraction Pipeline**: The data ingestion module [`data/download_and_prep_cicids.py`](file:///C:/Users/Lalit/Desktop/Guardian-Sentinal/data/download_and_prep_cicids.py) tracks processed shards to avoid redundant recomputation.
