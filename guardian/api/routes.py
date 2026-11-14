"""
Guardian-Sentinel: FastAPI Route Endpoints
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from guardian.api.schemas import (
    FlowInput,
    BatchFlowInput,
    ThreatPredictionResponse,
    SnifferStartRequest,
    SnifferStatusResponse,
    ModelInfoResponse
)
from guardian.api.database import get_db, DBTrafficLog
from guardian.core.agent.security_agent import analyze_network_flow
from guardian.core.agent.containment import containment_engine
from guardian.core.agent.memory import threat_memory
from guardian.core.agent.firewall import firewall_adapter
from guardian.sniffer.live_capture import live_capture_service

router = APIRouter(prefix="/api/v1")

@router.post("/predict", response_model=ThreatPredictionResponse)
def predict_single_flow(flow: FlowInput, db: Session = Depends(get_db)):
    """
    Analyzes a 78-dimensional network flow vector through the full autonomous IDS/IPS stack.
    """
    if len(flow.features) != 78:
        raise HTTPException(
            status_code=400,
            detail=f"Expected exactly 78 CIC-IDS2017 features, received {len(flow.features)}"
        )

    result = analyze_network_flow(
        features=flow.features,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip
    )

    # Persist log to DB
    try:
        log_entry = DBTrafficLog(
            source_ip=result["source_ip"],
            destination_ip=result["destination_ip"],
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            decision=result["decision"],
            reputation_score=result["reputation_score"],
            repeat_offender=result["repeat_offender"],
            is_zero_day=result["zero_day_analysis"]["is_zero_day"],
            reconstruction_error=result["zero_day_analysis"]["reconstruction_error"],
            explanation=result["explanation"],
            recommendation=result["recommendation"]
        )
        db.add(log_entry)
        db.commit()
    except Exception:
        db.rollback()

    return result

@router.post("/predict/batch", response_model=List[ThreatPredictionResponse])
def predict_batch_flows(batch: BatchFlowInput, db: Session = Depends(get_db)):
    """
    Batch classification for large network flow capture logs.
    """
    results = []
    for item in batch.flows:
        if len(item.features) == 78:
            res = analyze_network_flow(
                features=item.features,
                source_ip=item.source_ip,
                destination_ip=item.destination_ip
            )
            results.append(res)
    return results

@router.post("/sniffer/start")
def start_live_sniffer(req: SnifferStartRequest = SnifferStartRequest()):
    """
    Starts live inbound & outbound packet capture and real-time flow detection.
    """
    return live_capture_service.start_capture(interface=req.interface, allow_simulation=req.allow_simulation)

@router.post("/sniffer/stop")
def stop_live_sniffer():
    """
    Stops live packet capture.
    """
    return live_capture_service.stop_capture()

@router.get("/sniffer/status", response_model=SnifferStatusResponse)
def get_sniffer_status():
    """
    Returns live packet throughput, completed flows, and sniffer state.
    """
    return live_capture_service.get_status()

@router.get("/sniffer/feed")
def get_live_sniffer_feed(limit: int = 50):
    """
    Retrieves the most recent live flows captured and classified from the network interface.
    """
    return live_capture_service.get_recent_feed(limit=limit)

@router.get("/threats/live")
def get_live_threats(limit: int = 50, db: Session = Depends(get_db)):
    """
    Returns recent persisted threat records from SQLite database.
    """
    logs = db.query(DBTrafficLog).order_by(DBTrafficLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "attack_type": log.attack_type,
            "confidence": log.confidence,
            "severity": log.severity,
            "decision": log.decision,
            "reputation_score": log.reputation_score,
            "repeat_offender": log.repeat_offender,
            "is_zero_day": log.is_zero_day,
            "reconstruction_error": log.reconstruction_error,
            "explanation": log.explanation,
            "recommendation": log.recommendation
        }
        for log in logs
    ]

@router.get("/threats/bans")
def get_active_bans():
    """
    Lists all active automated IP bans and remaining duration.
    """
    return containment_engine.get_all_active_bans()

@router.post("/threats/unban/{ip_address}")
def release_ip_ban(ip_address: str):
    """
    Manually overrides and unbans an IP address.
    """
    containment_engine.release_ban(ip_address)
    firewall_adapter.enforce_rule("UNBLOCK", ip_address)
    return {"status": "SUCCESS", "message": f"IP {ip_address} released from ban list."}

@router.get("/threats/memory")
def get_threat_memory():
    """
    Retrieves stateful IP reputation and attack profiles.
    """
    return threat_memory.get_all_offenders()

@router.get("/model/info", response_model=ModelInfoResponse)
def get_detection_model_info():
    """
    Retrieves metadata about active Deep Learning and anomaly detection architectures.
    """
    from guardian.core.detection.classifier import attack_classifier
    return attack_classifier.get_model_info()
