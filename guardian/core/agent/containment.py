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
        # Check existing active ban
        if ip_address in self.active_bans:
            ban_info = self.active_bans[ip_address]
            if datetime.utcnow() < ban_info["expires_at"]:
                return "BLOCK", "ACTIVE_ENFORCEMENT", ban_info["duration_minutes"]
            else:
                del self.active_bans[ip_address]

        if severity == "LOW" and reputation > 80:
            return "ALLOW", "NO_CONTAINMENT", 0

        if is_zero_day or severity == "CRITICAL" or reputation < 25:
            # Immediate block or temporary ban escalation
            if attack_count >= 2 or is_zero_day:
                duration = 120  # 2 hours
                self._apply_ban(ip_address, duration, "CRITICAL threat / Zero-Day heuristic")
                return "BLOCK", "CRITICAL_CONTAINMENT", duration
            else:
                duration = 30
                self._apply_ban(ip_address, duration, "Severe initial threat")
                return "TEMP_BAN", "HIGH_CONTAINMENT", duration

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
