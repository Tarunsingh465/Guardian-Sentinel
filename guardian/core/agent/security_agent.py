"""
Guardian-Sentinel: Master Autonomous Security Agent
Coordinates classification, zero-day consensus, memory, reputation,
containment playbooks, firewall enforcement, and explainability.
"""

import random
from typing import Dict, Any, List

from guardian.core.detection.classifier import attack_classifier
from guardian.core.zero_day.hybrid_engine import hybrid_zero_day_engine
from guardian.core.agent.normalizer import normalize_attack_name
from guardian.core.agent.severity import calculate_severity
from guardian.core.agent.memory import threat_memory
from guardian.core.agent.reputation import calculate_reputation
from guardian.core.agent.containment import containment_engine
from guardian.core.agent.firewall import firewall_adapter
from guardian.core.agent.explainability import (
    generate_explanation,
    generate_recommendation
)
from guardian.core.agent.shap_explainability import explainability_engine

def analyze_network_flow(
    features: List[float],
    source_ip: str = None,
    destination_ip: str = "192.168.1.100"
) -> Dict[str, Any]:
    """
    End-to-End Autonomous Pipeline for a single 78-feature flow vector.
    """
    if not source_ip:
        source_ip = f"192.168.1.{random.randint(10, 250)}"

    # 1. Supervised Known Attack Classification
    predicted_attack, confidence, scaled_vec = attack_classifier.predict(features)

    # 2. Unsupervised Zero-Day Anomaly Detection
    zero_day_analysis = hybrid_zero_day_engine.analyze(scaled_vec)

    # 3. Intelligent Decision Fusion & Zero-Day Escalation
    recon_err = zero_day_analysis["reconstruction_error"]
    ae_thresh = zero_day_analysis["threshold"]
    is_unanimous_anomaly = (zero_day_analysis["anomaly_votes"] >= 3)
    is_extreme_recon_anomaly = (recon_err > ae_thresh * 2.5)

    is_zero_day = False
    final_attack_label = predicted_attack

    if predicted_attack == "BENIGN":
        if confidence < 0.85 and (is_unanimous_anomaly or is_extreme_recon_anomaly):
            # Ambiguous or stealth exploit
            is_zero_day = True
            final_attack_label = "POTENTIAL_ZERO_DAY"
            confidence = 0.90
        elif is_extreme_recon_anomaly and is_unanimous_anomaly:
            # Catastrophic out-of-distribution shift (genuine zero-day exploit)
            is_zero_day = True
            final_attack_label = "POTENTIAL_ZERO_DAY"
            confidence = 0.95
        else:
            # Confirmed Benign
            final_attack_label = "BENIGN"
    else:
        # Known attack signature
        final_attack_label = predicted_attack

    # 4. Update Stateful Attacker Memory
    mem_profile = threat_memory.update_attacker_memory(source_ip, final_attack_label)
    attack_count = mem_profile["attack_count"]
    repeat_offender = mem_profile["repeat_offender"]

    # 5. Calculate Attacker Reputation (0 - 100)
    reputation = calculate_reputation(attack_count, "HIGH" if is_zero_day else "MEDIUM", is_zero_day)

    # 6. Dynamic Severity Calculation
    severity = calculate_severity(
        final_attack_label,
        confidence=confidence,
        repeat_offender=repeat_offender,
        is_zero_day=is_zero_day
    )

    # 7. Autonomous Containment Policy Evaluation
    decision, containment_level, ban_duration = containment_engine.evaluate_decision(
        ip_address=source_ip,
        severity=severity,
        reputation=reputation,
        attack_count=attack_count,
        is_zero_day=is_zero_day
    )

    # 8. Firewall Rule Enforcement / Logging
    firewall_result = firewall_adapter.enforce_rule(
        action=decision,
        ip_address=source_ip,
        duration_minutes=ban_duration
    )

    # 9. Explainability & Playbook Recommendation
    explanation = generate_explanation(
        attack_type=final_attack_label,
        confidence=confidence,
        severity=severity,
        decision=decision,
        repeat_offender=repeat_offender,
        reputation=reputation,
        zero_day_info=zero_day_analysis
    )

    recommendation = generate_recommendation(
        attack_type=final_attack_label,
        severity=severity,
        decision=decision
    )

    # 10. Compute Explainability & Local Feature Attribution
    shap_attribution = explainability_engine.explain_flow_prediction(
        scaled_feature_vector=scaled_vec,
        predicted_class=final_attack_label,
        top_k=5
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "attack_type": final_attack_label,
        "confidence": round(confidence, 4),
        "severity": severity,
        "decision": decision,
        "containment_level": containment_level,
        "ban_duration_minutes": ban_duration,
        "reputation_score": reputation,
        "repeat_offender": repeat_offender,
        "attack_count": attack_count,
        "zero_day_analysis": zero_day_analysis,
        "firewall_action": firewall_result,
        "explanation": explanation,
        "recommendation": recommendation,
        "feature_attribution": shap_attribution
    }
