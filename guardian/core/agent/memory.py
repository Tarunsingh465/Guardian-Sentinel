"""
Guardian-Sentinel: Stateful Threat Memory Engine
Tracks per-IP attack history, frequency acceleration, and repeat-offender metadata.
"""

from datetime import datetime
from threading import Lock
from typing import Dict, Any, List

class ThreatMemory:
    def __init__(self):
        self._lock = Lock()
        self.memory: Dict[str, Dict[str, Any]] = {}

    def update_attacker_memory(self, ip_address: str, attack_type: str) -> Dict[str, Any]:
        """
        Records an interaction and returns updated IP threat profile.
        """
        now = datetime.utcnow().isoformat()

        with self._lock:
            if ip_address not in self.memory:
                self.memory[ip_address] = {
                    "ip_address": ip_address,
                    "attack_count": 0,
                    "unique_attacks": set(),
                    "first_seen": now,
                    "last_seen": now,
                    "repeat_offender": False,
                    "containment_status": "ALLOW"
                }

            record = self.memory[ip_address]
            record["last_seen"] = now

            if attack_type != "BENIGN":
                record["attack_count"] += 1
                record["unique_attacks"].add(attack_type)
                if record["attack_count"] >= 3:
                    record["repeat_offender"] = True

            return {
                "ip_address": record["ip_address"],
                "attack_count": record["attack_count"],
                "unique_attacks": list(record["unique_attacks"]),
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "repeat_offender": record["repeat_offender"],
                "containment_status": record["containment_status"]
            }

    def get_profile(self, ip_address: str) -> Dict[str, Any]:
        with self._lock:
            record = self.memory.get(ip_address)
            if not record:
                return {
                    "ip_address": ip_address,
                    "attack_count": 0,
                    "unique_attacks": [],
                    "repeat_offender": False,
                    "containment_status": "ALLOW"
                }
            return {
                "ip_address": record["ip_address"],
                "attack_count": record["attack_count"],
                "unique_attacks": list(record["unique_attacks"]),
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "repeat_offender": record["repeat_offender"],
                "containment_status": record["containment_status"]
            }

    def get_all_offenders(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "ip_address": r["ip_address"],
                    "attack_count": r["attack_count"],
                    "unique_attacks": list(r["unique_attacks"]),
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "repeat_offender": r["repeat_offender"],
                    "containment_status": r["containment_status"]
                }
                for r in self.memory.values() if r["attack_count"] > 0
            ]

# Singleton instance
threat_memory = ThreatMemory()
