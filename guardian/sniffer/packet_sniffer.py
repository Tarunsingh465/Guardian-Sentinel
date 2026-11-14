"""
Guardian-Sentinel: Live Network Packet Sniffer
Captures real-time inbound & outbound IP packets using Scapy or native Python sockets.
Passes parsed packets to the BidirectionalFlow manager.
"""

import time
import socket
import struct
import threading
from typing import Callable, Optional, List, Dict, Any, Tuple

from guardian.sniffer.flow_engine import BidirectionalFlow
from config import FLOW_TIMEOUT_SECONDS, MAX_LIVE_FLOWS_IN_MEMORY

class LivePacketSniffer:
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.is_running = False
        self.capture_mode = "STOPPED"  # One of: LIVE, SIMULATED, STARTING, STOPPED, ERROR
        self.error_reason: Optional[str] = None
        self._thread: Optional[threading.Thread] = None

        self.flows: Dict[str, BidirectionalFlow] = {}
        self.completed_flows: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        self.packets_captured = 0
        self.flows_completed = 0
        self.on_flow_complete_callback: Optional[Callable] = None

    def start(self, callback: Optional[Callable] = None, allow_simulation: bool = False):
        """
        Starts live capture thread.
        Explicitly distinguishes between LIVE, SIMULATED, and ERROR states.
        """
        if self.is_running:
            return

        self.is_running = True
        self.capture_mode = "STARTING"
        self.error_reason = None
        self.on_flow_complete_callback = callback
        self._thread = threading.Thread(target=self._capture_loop, args=(allow_simulation,), daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False
        self.capture_mode = "STOPPED"
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> Tuple[str, str]:
        """
        Returns (canonical_flow_id, direction)
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}", "FWD"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}", "BWD"

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        length: int,
        flags: Dict[str, int],
        ts: float
    ):
        flow_id, direction = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self._lock:
            self.packets_captured += 1

            if flow_id not in self.flows:
                self.flows[flow_id] = BidirectionalFlow(src_ip, dst_ip, src_port, dst_port, proto)

            flow = self.flows[flow_id]
            flow.add_packet(length, direction, flags, ts)

            # Check if flow has sufficient packets or is terminating
            if flags.get("FIN") or flags.get("RST") or len(flow.all_timestamps) >= 50:
                self._flush_flow(flow_id)

    def _flush_flow(self, flow_id: str):
        flow = self.flows.pop(flow_id, None)
        if not flow:
            return

        features = flow.to_feature_vector()
        flow_record = {
            "source_ip": flow.src_ip,
            "destination_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "features": features,
            "timestamp": time.time()
        }

        self.flows_completed += 1
        self.completed_flows.append(flow_record)
        if len(self.completed_flows) > MAX_LIVE_FLOWS_IN_MEMORY:
            self.completed_flows.pop(0)

        if self.on_flow_complete_callback:
            try:
                self.on_flow_complete_callback(flow_record)
            except Exception:
                pass

    def _clean_stale_flows(self):
        now = time.time()
        with self._lock:
            stale_keys = [
                k for k, f in self.flows.items()
                if (now - f.last_seen) > FLOW_TIMEOUT_SECONDS
            ]
            for k in stale_keys:
                self._flush_flow(k)

    def _capture_loop(self, allow_simulation: bool = False):
        """
        Attempts real Scapy live packet sniffing.
        If live capture fails, explicitly transitions to ERROR or SIMULATED (only if authorized).
        """
        use_scapy = False
        scapy_error = None
        try:
            from scapy.all import sniff, IP, TCP, UDP
            use_scapy = True
        except Exception as e:
            use_scapy = False
            scapy_error = str(e)

        if use_scapy:
            def scapy_pkt_handler(pkt):
                if not self.is_running:
                    return
                try:
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        proto = pkt[IP].proto
                        length = len(pkt)
                        src_port = 0
                        dst_port = 0
                        flags = {}

                        if pkt.haslayer(TCP):
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                            tcp_flags = pkt[TCP].flags
                            flags = {
                                "FIN": 1 if "F" in tcp_flags else 0,
                                "SYN": 1 if "S" in tcp_flags else 0,
                                "RST": 1 if "R" in tcp_flags else 0,
                                "PSH": 1 if "P" in tcp_flags else 0,
                                "ACK": 1 if "A" in tcp_flags else 0,
                                "URG": 1 if "U" in tcp_flags else 0,
                                "ECE": 1 if "E" in tcp_flags else 0,
                                "CWR": 1 if "C" in tcp_flags else 0
                            }
                        elif pkt.haslayer(UDP):
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport

                        self.process_packet(src_ip, dst_ip, src_port, dst_port, proto, length, flags, time.time())
                except Exception:
                    pass

            try:
                self.capture_mode = "LIVE"
                sniff(
                    iface=self.interface,
                    prn=scapy_pkt_handler,
                    stop_filter=lambda p: not self.is_running,
                    store=False,
                    timeout=1.0
                )
                return
            except Exception as e:
                scapy_error = str(e)

        # Handle failure: Do not silently simulate unless explicitly allowed!
        if not allow_simulation:
            self.is_running = False
            self.capture_mode = "ERROR"
            self.error_reason = (
                f"Live packet capture failed: {scapy_error}. "
                "Ensure Npcap is installed on Windows and terminal has administrator privileges."
            )
            return

        # Explicit Authorized Simulation Loop
        self.capture_mode = "SIMULATED"
        self.error_reason = f"Authorized simulation fallback active (Live error: {scapy_error})"
        import random
        while self.is_running:
            self._clean_stale_flows()

            # Simulate live incoming packet from network stream
            src_ip = f"192.168.1.{random.randint(2, 254)}"
            dst_ip = "192.168.1.100"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 21, 8080, 53])
            proto = 6  # TCP
            length = random.randint(40, 1500)
            flags = {"SYN": 1 if random.random() > 0.8 else 0, "ACK": 1}

            self.process_packet(src_ip, dst_ip, src_port, dst_port, proto, length, flags, time.time())
            time.sleep(random.uniform(0.05, 0.25))

# Singleton
live_packet_sniffer = LivePacketSniffer()
