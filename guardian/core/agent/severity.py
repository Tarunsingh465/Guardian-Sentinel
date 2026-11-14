"""
Guardian-Sentinel: Dynamic Severity Scoring Engine
Computes granular risk tiers based on attack taxonomy, confidence,
repeat offender frequency, and zero-day anomaly indicators.
"""

def calculate_severity(attack_type: str, confidence: float = 0.8, repeat_offender: bool = False, is_zero_day: bool = False) -> str:
    """
    Returns one of: LOW, MEDIUM, HIGH, CRITICAL
    """
    if attack_type == "BENIGN":
        return "LOW"

    # Base severity matrix
    critical_threats = {
        "POTENTIAL_ZERO_DAY", "INFILTRATION", "HEARTBLEED", 
        "BOTNET", "WEB_ATTACK_SQLI"
    }
    high_threats = {
        "DDOS", "DOS_HULK", "DOS_GOLDENEYE", "HIGH_ANOMALY",
        "BRUTEFORCE_SSH", "WEB_ATTACK_XSS"
    }
    medium_threats = {
        "PORTSCAN", "DOS_SLOWLORIS", "DOS_SLOWHTTPTEST", 
        "BRUTEFORCE_FTP", "WEB_ATTACK_BRUTEFORCE", "SUSPICIOUS"
    }

    if is_zero_day or attack_type in critical_threats:
        base = "CRITICAL"
    elif attack_type in high_threats:
        base = "HIGH"
    elif attack_type in medium_threats:
        base = "MEDIUM"
    else:
        base = "MEDIUM"

    # Escalate if repeat offender with high confidence
    if repeat_offender:
        if base == "MEDIUM":
            base = "HIGH"
        elif base == "HIGH":
            base = "CRITICAL"

    if confidence < 0.60 and base != "LOW":
        # Downgrade one level if low confidence
        downgrade_map = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW"}
        base = downgrade_map.get(base, base)

    return base
