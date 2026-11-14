"""
Guardian-Sentinel: High-Throughput Traffic Simulator
Streams synthetic and real CIC-IDS2017 network flows to the FastAPI inference endpoint.
"""

import time
import random
import requests
from typing import List

API_URL = "http://127.0.0.1:8000/api/v1/predict"

def generate_sample_flow(attack_type: str = "BENIGN") -> List[float]:
    """
    Generates realistic 78-feature flow vector matching specified profile and live network packet captures.
    """
    features = [random.uniform(0.1, 5.0) for _ in range(78)]

    if attack_type == "BENIGN":
        fwd_p = random.randint(5, 35)
        bwd_p = random.randint(4, 30)
        fwd_len = random.uniform(80, 1400)
        bwd_len = random.uniform(80, 1400)
        tot_fwd_len = fwd_p * fwd_len
        tot_bwd_len = bwd_p * bwd_len
        duration = random.uniform(10000, 1000000)
        dur_sec = duration / 1e6

        features[0] = float(random.choice([80, 443, 8080, 8443, 53, 22, 21, random.randint(1024, 65535)]))
        features[1] = duration
        features[2] = float(fwd_p)
        features[3] = float(bwd_p)
        features[4] = float(tot_fwd_len)
        features[5] = float(tot_bwd_len)
        features[6] = float(min(fwd_len * 1.5, 1500))
        features[7] = float(max(fwd_len * 0.5, 40))
        features[8] = float(fwd_len)
        features[10] = float(min(bwd_len * 1.5, 1500))
        features[11] = float(max(bwd_len * 0.5, 40))
        features[12] = float(bwd_len)
        features[14] = float((tot_fwd_len + tot_bwd_len) / dur_sec)
        features[15] = float((fwd_p + bwd_p) / dur_sec)
        features[16] = float(duration / (fwd_p + bwd_p))
        features[34] = float(fwd_p * 20)
        features[35] = float(bwd_p * 20)
        features[40] = float((fwd_len + bwd_len) / 2.0)
        features[47] = 1.0  # ACK
        features[52] = float(bwd_p / fwd_p)
        features[67] = float(random.choice([8192, 16384, 29200, 65535]))
        features[68] = float(random.choice([8192, 16384, 29200, 65535]))
    elif attack_type == "DDOS":
        duration = random.uniform(50, 1500)
        fwd_p = random.randint(500, 3000)
        dur_sec = duration / 1e6
        features[0] = 80.0
        features[1] = duration
        features[2] = float(fwd_p)
        features[3] = 0.0
        features[4] = float(fwd_p * 60)
        features[5] = 0.0
        features[14] = float(fwd_p * 60 / dur_sec)
        features[15] = float(fwd_p / dur_sec)
        features[44] = 1.0  # SYN
        features[47] = 0.0  # No ACK
    elif attack_type == "PORTSCAN":
        duration = random.uniform(10, 100)
        dur_sec = duration / 1e6
        features[0] = float(random.randint(1, 1024))
        features[1] = duration
        features[2] = 1.0
        features[3] = 0.0
        features[4] = 40.0
        features[5] = 0.0
        features[14] = float(40.0 / dur_sec)
        features[15] = float(1.0 / dur_sec)
        features[44] = 1.0  # SYN
        features[47] = 0.0
    elif attack_type == "ZERO_DAY":
        # Massive out-of-distribution feature corruption across 30 dimensions
        for i in range(10, 40):
            features[i] = random.uniform(500000, 2000000)

    return features

def stream_traffic(delay_seconds: float = 0.5):
    print("🚀 Starting Guardian-Sentinel Traffic Streamer...")
    print(f"Target Endpoint: {API_URL}")
    print("Press Ctrl+C to terminate stream.\n")

    counter = 0
    attack_choices = ["BENIGN", "BENIGN", "BENIGN", "DDOS", "PORTSCAN", "ZERO_DAY"]

    while True:
        counter += 1
        chosen_type = random.choice(attack_choices)
        flow_vec = generate_sample_flow(chosen_type)
        ip = f"192.168.1.{random.randint(15, 245)}"

        payload = {
            "features": flow_vec,
            "source_ip": ip,
            "destination_ip": "10.0.0.1"
        }

        try:
            resp = requests.post(API_URL, json=payload, timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                print(f"[{counter:04d}] IP: {ip:15} | Attack: {data['attack_type']:18} | Severity: {data['severity']:8} | Action: {data['decision']:10} | Zero-Day: {data['zero_day_analysis']['is_zero_day']}")
            else:
                print(f"Error {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"Connection Error (Is FastAPI running?): {e}")

        time.sleep(delay_seconds)

if __name__ == "__main__":
    stream_traffic()
