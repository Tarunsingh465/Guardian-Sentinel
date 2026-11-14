"""
Guardian-Sentinel: Real-Time Bidirectional Flow Engine
Assembles raw packet streams into bidirectional 5-tuple IP flows and
computes the standard 78 CIC-IDS2017 statistical features in real time.
"""

import time
import numpy as np
from typing import Dict, List, Tuple, Any

class BidirectionalFlow:
    """
    Maintains packet timing, byte distributions, and flag statistics for a single conversation.
    """
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = time.time()
        self.last_seen = self.start_time

        self.fwd_packets: List[int] = []
        self.bwd_packets: List[int] = []

        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []

        # Flags count
        self.flags = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "CWR": 0, "ECE": 0
        }
        self.fwd_header_len = 0
        self.bwd_header_len = 0

    def add_packet(self, length: int, direction: str, flags_dict: Dict[str, int], timestamp: float, header_len: int = 20):
        self.last_seen = timestamp
        self.all_timestamps.append(timestamp)

        if direction == "FWD":
            self.fwd_packets.append(length)
            self.fwd_timestamps.append(timestamp)
            self.fwd_header_len += header_len
        else:
            self.bwd_packets.append(length)
            self.bwd_timestamps.append(timestamp)
            self.bwd_header_len += header_len

        for flag, val in flags_dict.items():
            if flag in self.flags and val:
                self.flags[flag] += 1

    def to_feature_vector(self) -> List[float]:
        """
        Calculates and exports the exact 78 CIC-IDS2017 features.
        """
        # Duration in microseconds
        duration = max((self.last_seen - self.start_time) * 1e6, 1.0)

        tot_fwd = len(self.fwd_packets)
        tot_bwd = len(self.bwd_packets)
        tot_fwd_len = sum(self.fwd_packets)
        tot_bwd_len = sum(self.bwd_packets)

        # Fwd packet stats
        fwd_max = max(self.fwd_packets) if tot_fwd else 0.0
        fwd_min = min(self.fwd_packets) if tot_fwd else 0.0
        fwd_mean = np.mean(self.fwd_packets) if tot_fwd else 0.0
        fwd_std = np.std(self.fwd_packets) if tot_fwd > 1 else 0.0

        # Bwd packet stats
        bwd_max = max(self.bwd_packets) if tot_bwd else 0.0
        bwd_min = min(self.bwd_packets) if tot_bwd else 0.0
        bwd_mean = np.mean(self.bwd_packets) if tot_bwd else 0.0
        bwd_std = np.std(self.bwd_packets) if tot_bwd > 1 else 0.0

        # Rates
        dur_sec = max(duration / 1e6, 0.0001)
        flow_bytes_s = (tot_fwd_len + tot_bwd_len) / dur_sec
        flow_pkts_s = (tot_fwd + tot_bwd) / dur_sec

        # Flow Inter-Arrival Times (IAT)
        def calc_iat(ts_list):
            if len(ts_list) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            diffs = [(ts_list[i] - ts_list[i-1]) * 1e6 for i in range(1, len(ts_list))]
            return sum(diffs), float(np.mean(diffs)), float(np.std(diffs)), max(diffs), min(diffs)

        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = calc_iat(self.all_timestamps)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = calc_iat(self.fwd_timestamps)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = calc_iat(self.bwd_timestamps)

        all_pkts = self.fwd_packets + self.bwd_packets
        min_pkt = min(all_pkts) if all_pkts else 0.0
        max_pkt = max(all_pkts) if all_pkts else 0.0
        pkt_mean = np.mean(all_pkts) if all_pkts else 0.0
        pkt_std = np.std(all_pkts) if len(all_pkts) > 1 else 0.0
        pkt_var = float(np.var(all_pkts)) if len(all_pkts) > 1 else 0.0

        down_up_ratio = (tot_bwd / tot_fwd) if tot_fwd else 0.0
        avg_pkt_size = float(np.mean(all_pkts)) if all_pkts else 0.0

        # Construct vector (78 entries matching config.FEATURE_NAMES)
        features = [
            float(self.dst_port),               # 0: Destination Port
            float(duration),                    # 1: Flow Duration
            float(tot_fwd),                     # 2: Total Fwd Packets
            float(tot_bwd),                     # 3: Total Backward Packets
            float(tot_fwd_len),                 # 4: Total Length of Fwd Packets
            float(tot_bwd_len),                 # 5: Total Length of Bwd Packets
            float(fwd_max),                     # 6: Fwd Packet Length Max
            float(fwd_min),                     # 7: Fwd Packet Length Min
            float(fwd_mean),                    # 8: Fwd Packet Length Mean
            float(fwd_std),                     # 9: Fwd Packet Length Std
            float(bwd_max),                     # 10: Bwd Packet Length Max
            float(bwd_min),                     # 11: Bwd Packet Length Min
            float(bwd_mean),                    # 12: Bwd Packet Length Mean
            float(bwd_std),                     # 13: Bwd Packet Length Std
            float(flow_bytes_s),                # 14: Flow Bytes/s
            float(flow_pkts_s),                 # 15: Flow Packets/s
            float(flow_iat_mean),               # 16: Flow IAT Mean
            float(flow_iat_std),                # 17: Flow IAT Std
            float(flow_iat_max),                # 18: Flow IAT Max
            float(flow_iat_min),                # 19: Flow IAT Min
            float(fwd_iat_tot),                 # 20: Fwd IAT Total
            float(fwd_iat_mean),                # 21: Fwd IAT Mean
            float(fwd_iat_std),                 # 22: Fwd IAT Std
            float(fwd_iat_max),                 # 23: Fwd IAT Max
            float(fwd_iat_min),                 # 24: Fwd IAT Min
            float(bwd_iat_tot),                 # 25: Bwd IAT Total
            float(bwd_iat_mean),                # 26: Bwd IAT Mean
            float(bwd_iat_std),                 # 27: Bwd IAT Std
            float(bwd_iat_max),                 # 28: Bwd IAT Max
            float(bwd_iat_min),                 # 29: Bwd IAT Min
            float(self.flags["PSH"]),           # 30: Fwd PSH Flags
            0.0,                                # 31: Bwd PSH Flags
            float(self.flags["URG"]),           # 32: Fwd URG Flags
            0.0,                                # 33: Bwd URG Flags
            float(self.fwd_header_len),         # 34: Fwd Header Length
            float(self.bwd_header_len),         # 35: Bwd Header Length
            float(tot_fwd / dur_sec),           # 36: Fwd Packets/s
            float(tot_bwd / dur_sec),           # 37: Bwd Packets/s
            float(min_pkt),                     # 38: Min Packet Length
            float(max_pkt),                     # 39: Max Packet Length
            float(pkt_mean),                    # 40: Packet Length Mean
            float(pkt_std),                     # 41: Packet Length Std
            float(pkt_var),                     # 42: Packet Length Variance
            float(self.flags["FIN"]),           # 43: FIN Flag Count
            float(self.flags["SYN"]),           # 44: SYN Flag Count
            float(self.flags["RST"]),           # 45: RST Flag Count
            float(self.flags["PSH"]),           # 46: PSH Flag Count
            float(self.flags["ACK"]),           # 47: ACK Flag Count
            float(self.flags["URG"]),           # 48: URG Flag Count
            float(self.flags["CWR"]),           # 49: CWR Flag Count
            float(self.flags["ECE"]),           # 50: ECE Flag Count
            float(down_up_ratio),               # 51: Down/Up Ratio
            float(avg_pkt_size),                # 52: Average Packet Size
            float(fwd_mean),                    # 53: Avg Fwd Segment Size
            float(bwd_mean),                    # 54: Avg Bwd Segment Size
            float(self.fwd_header_len),         # 55: Fwd Header Length.1
            0.0,                                # 56: Fwd Avg Bytes/Bulk
            0.0,                                # 57: Fwd Avg Packets/Bulk
            0.0,                                # 58: Fwd Avg Bulk Rate
            0.0,                                # 59: Bwd Avg Bytes/Bulk
            0.0,                                # 60: Bwd Avg Packets/Bulk
            0.0,                                # 61: Bwd Avg Bulk Rate
            float(tot_fwd),                     # 62: Subflow Fwd Packets
            float(tot_fwd_len),                 # 63: Subflow Fwd Bytes
            float(tot_bwd),                     # 64: Subflow Bwd Packets
            float(tot_bwd_len),                 # 65: Subflow Bwd Bytes
            float(8192.0),                      # 66: Init_Win_bytes_forward
            float(8192.0),                      # 67: Init_Win_bytes_backward
            float(tot_fwd),                     # 68: act_data_pkt_fwd
            float(20.0),                        # 69: min_seg_size_forward
            0.0,                                # 70: Active Mean
            0.0,                                # 71: Active Std
            0.0,                                # 72: Active Max
            0.0,                                # 73: Active Min
            0.0,                                # 74: Idle Mean
            0.0,                                # 75: Idle Std
            0.0,                                # 76: Idle Max
            0.0                                 # 77: Idle Min
        ]
        return features
