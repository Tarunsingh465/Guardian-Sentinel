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
    Generates realistic 78-feature flow vector matching specified profile.
    """
    features = [random.uniform(0.1, 5.0) for _ in range(78)]

    if attack_type == "BENIGN":
        features[0] = float(random.choice([80, 443, 8080, 53]))
        features[1] = random.uniform(5000, 500000)  # Microseconds
        features[2] = random.uniform(5, 30)          # Fwd pkts
        features[3] = random.uniform(4, 25)          # Bwd pkts
        features[14] = random.uniform(1000, 50000)   # Bytes/sec
        features[47] = 1.0                           # ACK
    elif attack_type == "DDOS":
        features[0] = 80.0
        features[1] = random.uniform(50, 800)
        features[2] = random.uniform(300, 1500)
        features[3] = 0.0
        features[14] = random.uniform(2000000, 15000000)
        features[44] = 1.0                           # SYN
    elif attack_type == "PORTSCAN":
        features[0] = float(random.randint(1, 1024))
        features[1] = random.uniform(10, 50)
        features[2] = 1.0
        features[3] = 0.0
        features[44] = 1.0
    elif attack_type == "ZERO_DAY":
        # Out-of-Distribution Feature Shift
        for i in range(10, 30):
            features[i] = random.uniform(50000, 200000)

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
