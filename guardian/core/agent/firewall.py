"""
Guardian-Sentinel: Firewall Adapter
Abstraction layer decoupling autonomous decisions from the underlying OS packet filter.
Supports SIMULATION mode and live OS execution (netsh on Windows, iptables on Linux).
"""

import sys
import subprocess
import ipaddress
from datetime import datetime
from typing import List, Dict, Any

class FirewallAdapter:
    def __init__(self, mode: str = "SIMULATION"):
        self.mode = mode.upper()
        self.history: List[Dict[str, Any]] = []

    def enforce_rule(self, action: str, ip_address: str, duration_minutes: int = 0) -> Dict[str, Any]:
        """
        Executes or simulates: BLOCK, UNBLOCK, TEMP_BAN, MONITOR
        Implements strict IP validation and safe non-shell subprocess execution.
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

        # 1. Strict IP Address Validation (prevents command injection)
        try:
            valid_ip = ipaddress.ip_address(ip_address)
            clean_ip_str = str(valid_ip)
        except ValueError:
            log_entry["status"] = "REJECTED_INVALID_IP"
            log_entry["detail"] = f"Security Violation: '{ip_address}' is not a valid IPv4 or IPv6 address."
            self.history.append(log_entry)
            return log_entry

        # 2. Simulation Mode (Default Safe Guard)
        if self.mode == "SIMULATION":
            message = f"[FIREWALL SIMULATION] Executed {action} on {clean_ip_str} (duration: {duration_minutes}m)"
            log_entry["detail"] = message
            self.history.append(log_entry)
            return log_entry

        # 3. Real OS execution mode (Parameterized without shell=True)
        try:
            if sys.platform == "win32":
                rule_name = f"Guardian_Block_{clean_ip_str.replace('.', '_').replace(':', '_')}"
                if action in ["BLOCK", "TEMP_BAN"]:
                    cmd_args = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=block", f"remoteip={clean_ip_str}"
                    ]
                    subprocess.run(cmd_args, shell=False, check=True, capture_output=True)
                    log_entry["detail"] = f"Windows Firewall rule added safely: {rule_name}"
                elif action == "UNBLOCK":
                    cmd_args = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ]
                    subprocess.run(cmd_args, shell=False, check=False, capture_output=True)
                    log_entry["detail"] = f"Windows Firewall rule removed: {rule_name}"
            else:
                # Linux iptables
                if action in ["BLOCK", "TEMP_BAN"]:
                    cmd_args = ["iptables", "-A", "INPUT", "-s", clean_ip_str, "-j", "DROP"]
                    subprocess.run(cmd_args, shell=False, check=True, capture_output=True)
                    log_entry["detail"] = f"iptables rule added for {clean_ip_str}"
                elif action == "UNBLOCK":
                    cmd_args = ["iptables", "-D", "INPUT", "-s", clean_ip_str, "-j", "DROP"]
                    subprocess.run(cmd_args, shell=False, check=False, capture_output=True)
                    log_entry["detail"] = f"iptables rule removed for {clean_ip_str}"
        except Exception as e:
            log_entry["status"] = "ERROR"
            log_entry["detail"] = str(e)

        self.history.append(log_entry)
        return log_entry

    def get_history(self) -> List[Dict[str, Any]]:
        return self.history[-100:]

# Singleton
firewall_adapter = FirewallAdapter(mode="SIMULATION")
