"""
Guardian-Sentinel: Explainability & Playbook Recommendation Engine
Generates human-interpretable technical rationales and actionable SOC incident playbooks.
"""

from typing import Dict, Any

def generate_explanation(
    attack_type: str,
    confidence: float,
    severity: str,
    decision: str,
    repeat_offender: bool,
    reputation: int,
    zero_day_info: Dict[str, Any] = None
) -> str:
    """
    Produces a clear, analyst-grade incident explanation.
    """
    if attack_type == "BENIGN":
        return f"Normal network traffic pattern detected with {confidence*100:.1f}% confidence. Packet behavior conforms to standard protocol baselines."

    if zero_day_info and zero_day_info.get("status") in ["POTENTIAL_ZERO_DAY", "HIGH_ANOMALY"]:
        err = zero_day_info.get("reconstruction_error", 0.0)
        thresh = zero_day_info.get("threshold", 0.042)
        votes = zero_day_info.get("anomaly_votes", 0)
        return (
            f"Zero-Day Anomaly Triggered! Deep Autoencoder reconstruction loss ({err:.5f}) exceeded "
            f"the 95th percentile baseline threshold ({thresh:.5f}). Ensemble consensus verified by "
            f"{votes}/3 unsupervised anomaly detectors (Autoencoder, Isolation Forest, One-Class SVM). "
            f"Traffic exhibits statistical deviation from all known attack signatures."
        )

    parts = [
        f"Detected {attack_type} signature with {confidence*100:.1f}% model confidence.",
        f"Assigned {severity} severity level based on asset risk profile."
    ]

    if repeat_offender:
        parts.append(f"Attacker identified as a REPEAT OFFENDER with depleted reputation score ({reputation}/100).")

    parts.append(f"Autonomous defense triggered action: '{decision}'.")
    return " ".join(parts)


def generate_recommendation(attack_type: str, severity: str, decision: str) -> str:
    """
    Generates tailored operational containment recommendations.
    """
    playbooks = {
        "DDOS": (
            "1. Activate upstream ISP volumetric rate-limiting. "
            "2. Enable SYN cookies on perimeter reverse proxies. "
            "3. Verify edge CDN scrubbing rules."
        ),
        "PORTSCAN": (
            "1. Null-route aggressive reconnaissance scanning. "
            "2. Audit exposed service ports on edge DMZ. "
            "3. Rotate public port bindings if non-standard services detected."
        ),
        "BRUTEFORCE_SSH": (
            "1. Enforce fail2ban / SSH key-only authentication. "
            "2. Disable root login over SSH (`PermitRootLogin no`). "
            "3. Isolate targeting IP at border gateway."
        ),
        "BRUTEFORCE_FTP": (
            "1. Terminate anonymous FTP sessions immediately. "
            "2. Implement aggressive connection throttling per subnet. "
            "3. Audit authentication event logs."
        ),
        "BOTNET": (
            "1. Isolate compromised internal host from subnet VLAN. "
            "2. Sinkhole Command & Control (C2) DNS domain. "
            "3. Capture memory dump for forensic analysis."
        ),
        "WEB_ATTACK_SQLI": (
            "1. Deploy WAF rule blocking union/boolean SQL injection payloads. "
            "2. Inspect parameterized query sanitation in API backend. "
            "3. Review database query logs for exfiltration attempts."
        ),
        "POTENTIAL_ZERO_DAY": (
            "1. Quarantine flow traffic in sandbox capture buffer. "
            "2. Export PCAP packet capture for deep-packet inspection (DPI). "
            "3. Alert Senior Security Operations Center (SOC) Tier 3 Incident Response."
        )
    }

    return playbooks.get(
        attack_type,
        f"1. Maintain {decision} policy on source IP. 2. Monitor traffic volume changes. 3. Log event to SIEM."
    )
