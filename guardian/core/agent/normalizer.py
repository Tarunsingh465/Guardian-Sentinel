"""
Guardian-Sentinel: Attack Label Normalizer
Standardizes disparate raw CIC-IDS2017 labels and live packet classifications
into a canonical security taxonomy.
"""

def normalize_attack_name(attack_type: str) -> str:
    """
    Converts raw attack strings to canonical uppercase threat keys.
    """
    if not attack_type:
        return "UNKNOWN_ATTACK"

    cleaned = str(attack_type).strip()

    mapping = {
        # Normal
        "benign": "BENIGN",
        "normal": "BENIGN",

        # DoS / DDoS
        "ddos": "DDOS",
        "dos": "DOS",
        "dos slowloris": "DOS_SLOWLORIS",
        "dos slowhttptest": "DOS_SLOWHTTPTEST",
        "dos hulk": "DOS_HULK",
        "dos goldeneye": "DOS_GOLDENEYE",
        "heartbleed": "HEARTBLEED",

        # Reconnaissance
        "portscan": "PORTSCAN",
        "port scan": "PORTSCAN",
        "probe": "PORTSCAN",

        # Brute Force
        "ftp-patator": "BRUTEFORCE_FTP",
        "ssh-patator": "BRUTEFORCE_SSH",
        "brute force": "BRUTEFORCE",

        # Botnet
        "bot": "BOTNET",
        "botnet": "BOTNET",

        # Web Attacks
        "web attack – brute force": "WEB_ATTACK_BRUTEFORCE",
        "web attack – xss": "WEB_ATTACK_XSS",
        "web attack – sql injection": "WEB_ATTACK_SQLI",
        "web attack": "WEB_ATTACK",

        # Infiltration & Zero-Day
        "infiltration": "INFILTRATION",
        "potential_zero_day": "POTENTIAL_ZERO_DAY",
        "zero_day": "POTENTIAL_ZERO_DAY",
        "high_anomaly": "HIGH_ANOMALY",
        "anomaly": "ANOMALY"
    }

    lower_key = cleaned.lower()
    for key, normalized in mapping.items():
        if key in lower_key:
            return normalized

    return cleaned.upper().replace(" ", "_")
