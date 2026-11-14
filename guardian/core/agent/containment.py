"""
Guardian-Sentinel: Autonomous Containment & Playbook Engine
Determines active intervention policies: ALLOW, MONITOR, TEMP_BAN, BLOCK.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Tuple

class ContainmentEngine:
    def __init__(self):
        self.active_bans: Dict[str, Dict[str, Any]] = {}

    def evaluate_decision(
        self,
        ip_address: str,
        severity: str,
        reputation: int,
        attack_count: int,
        is_zero_day: bool = False
    ) -> Tuple[str, str, int]:
        """
        Returns (decision, containment_level, ban_duration_minutes)
        Decisions: ALLOW, MONITOR, TEMP_BAN, BLOCK, CRITICAL_ALERT
        """
        # Whitelist protection for local/gateway and DNS infrastructure
        whitelist = {"127.0.0.1", "::1", "localhost", "10.0.0.1", "192.168.1.1", "8.8.8.8", "1.1.1.1"}
        if ip_address in whitelist:
            return "ALLOW", "WHITELISTED", 0

        # Check existing active ban
        if ip_address in self.active_bans:
            ban_info = self.active_bans[ip_address]
            if datetime.utcnow() < ban_info["expires_at"]:
                return "BLOCK", "ACTIVE_ENFORCEMENT", ban_info["duration_minutes"]
            else:
                del self.active_bans[ip_address]

        if severity == "LOW" and reputation > 75:
            return "ALLOW", "NO_CONTAINMENT", 0

        if is_zero_day or severity == "CRITICAL":
            # Multi-stage containment: First offense gets temporary probation ban (5 min), repeat offenses get hard block (60 min)
            if attack_count >= 2:
                duration = 60  # 1 hour
                self._apply_ban(ip_address, duration, "Confirmed repeat Zero-Day / Critical exploit")
                return "BLOCK", "CRITICAL_CONTAINMENT", duration
            else:
                duration = 5   # 5 minutes probation
                self._apply_ban(ip_address, duration, "Probationary isolation for novel zero-day anomaly")
                return "TEMP_BAN", "PROBATION_CONTAINMENT", duration

        if severity == "HIGH" or attack_count >= 3:
            duration = 15
            self._apply_ban(ip_address, duration, "Repeat offender / High severity")
            return "TEMP_BAN", "MEDIUM_CONTAINMENT", duration

        if severity == "MEDIUM" or attack_count >= 1:
            return "MONITOR", "LOW_CONTAINMENT", 0

        return "ALLOW", "NO_CONTAINMENT", 0

    def _apply_ban(self, ip_address: str, minutes: int, reason: str):
        expires_at = datetime.utcnow() + timedelta(minutes=minutes)
        self.active_bans[ip_address] = {
            "ip_address": ip_address,
            "banned_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at,
            "duration_minutes": minutes,
            "reason": reason
        }

    def release_ban(self, ip_address: str):
        if ip_address in self.active_bans:
            del self.active_bans[ip_address]

    def get_all_active_bans(self) -> Dict[str, Any]:
        now = datetime.utcnow()
        # Clean expired
        expired = [ip for ip, data in self.active_bans.items() if now >= data["expires_at"]]
        for ip in expired:
            del self.active_bans[ip]

        return {
            ip: {
                "ip_address": data["ip_address"],
                "banned_at": data["banned_at"],
                "expires_at": data["expires_at"].isoformat(),
                "duration_minutes": data["duration_minutes"],
                "reason": data["reason"]
            }
            for ip, data in self.active_bans.items()
        }

# Singleton
containment_engine = ContainmentEngine()
