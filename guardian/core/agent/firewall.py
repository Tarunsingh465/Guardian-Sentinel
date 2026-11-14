"""
Guardian-Sentinel: Firewall Adapter
Abstraction layer decoupling autonomous decisions from the underlying OS packet filter.
Supports SIMULATION mode and live OS execution (netsh on Windows, iptables on Linux).
"""

import sys
import subprocess
from datetime import datetime
from typing import List, Dict, Any

class FirewallAdapter:
    def __init__(self, mode: str = "SIMULATION"):
        self.mode = mode.upper()
        self.history: List[Dict[str, Any]] = []

    def enforce_rule(self, action: str, ip_address: str, duration_minutes: int = 0) -> Dict[str, Any]:
        """
        Executes or simulates: BLOCK, UNBLOCK, TEMP_BAN, MONITOR
        """
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "action": action,
            "ip_address": ip_address,
            "duration_minutes": duration_minutes,
            "mode": self.mode,
            "status": "SUCCESS"
        }

        if self.mode == "SIMULATION":
            message = f"[FIREWALL SIMULATION] Executed {action} on {ip_address} (duration: {duration_minutes}m)"
            log_entry["detail"] = message
            self.history.append(log_entry)
            return log_entry

        # Real OS execution mode
        try:
            if sys.platform == "win32":
                # Windows Defender Firewall via netsh
                rule_name = f"Guardian_Block_{ip_address.replace('.', '_')}"
                if action in ["BLOCK", "TEMP_BAN"]:
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    log_entry["detail"] = f"Windows Firewall rule added: {rule_name}"
                elif action == "UNBLOCK":
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                    subprocess.run(cmd, shell=True, check=False, capture_output=True)
                    log_entry["detail"] = f"Windows Firewall rule removed: {rule_name}"
            else:
                # Linux iptables
                if action in ["BLOCK", "TEMP_BAN"]:
                    cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    log_entry["detail"] = f"iptables rule added for {ip_address}"
                elif action == "UNBLOCK":
                    cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
                    subprocess.run(cmd, shell=True, check=False, capture_output=True)
                    log_entry["detail"] = f"iptables rule removed for {ip_address}"
        except Exception as e:
            log_entry["status"] = "ERROR"
            log_entry["detail"] = str(e)

        self.history.append(log_entry)
        return log_entry

    def get_history(self) -> List[Dict[str, Any]]:
        return self.history[-100:]

# Singleton
firewall_adapter = FirewallAdapter(mode="SIMULATION")
