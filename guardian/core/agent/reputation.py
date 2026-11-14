"""
Guardian-Sentinel: Attacker Reputation Engine
Computes an empirical 0-100 IP trust score based on attack frequency,
severity weights, and zero-day involvement.
"""

def calculate_reputation(attack_count: int, severity: str, is_zero_day: bool = False) -> int:
    """
    Returns an integer reputation score between 0 (hostile) and 100 (trusted).
    """
    if attack_count == 0:
        return 100

    severity_penalties = {
        "LOW": 5,
        "MEDIUM": 15,
        "HIGH": 30,
        "CRITICAL": 50
    }

    base_penalty = severity_penalties.get(severity, 15)
    frequency_penalty = min(attack_count * 8, 40)
    zero_day_penalty = 30 if is_zero_day else 0

    total_penalty = base_penalty + frequency_penalty + zero_day_penalty
    reputation = max(0, 100 - total_penalty)

    return reputation
