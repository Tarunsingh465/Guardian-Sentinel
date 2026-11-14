"""
Guardian-Sentinel: Live Capture Controller
Manages lifecycle of live network packet sniffing and pipes assembled flows
directly into the security agent for real-time autonomous triage.
"""

from typing import List, Dict, Any
from guardian.sniffer.packet_sniffer import live_packet_sniffer
from guardian.core.agent.security_agent import analyze_network_flow

class LiveCaptureService:
    def __init__(self):
        self.live_threat_feed: List[Dict[str, Any]] = []
        self.max_feed_size = 200

    def start_capture(self, interface: str = None) -> Dict[str, Any]:
        if live_packet_sniffer.is_running:
            return {"status": "ALREADY_RUNNING", "interface": live_packet_sniffer.interface}

        live_packet_sniffer.interface = interface
        live_packet_sniffer.start(callback=self._on_flow_detected)

        return {
            "status": "STARTED",
            "interface": interface or "DEFAULT",
            "message": "Live packet capture and bidirectional flow extraction active."
        }

    def stop_capture(self) -> Dict[str, Any]:
        live_packet_sniffer.stop()
        return {
            "status": "STOPPED",
            "packets_captured": live_packet_sniffer.packets_captured,
            "flows_completed": live_packet_sniffer.flows_completed
        }

    def _on_flow_detected(self, flow_record: Dict[str, Any]):
        """
        Callback executed whenever the sniffer completes a bidirectional flow.
        """
        features = flow_record["features"]
        src_ip = flow_record["source_ip"]
        dst_ip = flow_record["destination_ip"]

        # Run through autonomous AI security agent
        analysis = analyze_network_flow(
            features=features,
            source_ip=src_ip,
            destination_ip=dst_ip
        )

        analysis["src_port"] = flow_record.get("src_port")
        analysis["dst_port"] = flow_record.get("dst_port")
        analysis["protocol"] = flow_record.get("protocol")
        analysis["timestamp"] = flow_record.get("timestamp")

        self.live_threat_feed.insert(0, analysis)
        if len(self.live_threat_feed) > self.max_feed_size:
            self.live_threat_feed.pop()

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": live_packet_sniffer.is_running,
            "interface": live_packet_sniffer.interface or "Auto-detected",
            "packets_captured": live_packet_sniffer.packets_captured,
            "flows_completed": live_packet_sniffer.flows_completed,
            "active_flows_in_buffer": len(live_packet_sniffer.flows),
            "threats_logged": len(self.live_threat_feed)
        }

    def get_recent_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.live_threat_feed[:limit]

# Singleton
live_capture_service = LiveCaptureService()
