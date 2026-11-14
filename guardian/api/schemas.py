"""
Guardian-Sentinel: Pydantic v2 Schemas for FastAPI
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class FlowInput(BaseModel):
    features: List[float] = Field(..., description="78 numerical flow features from CIC-IDS2017 schema")
    source_ip: Optional[str] = Field(default=None, description="Source IP address of connection")
    destination_ip: Optional[str] = Field(default="192.168.1.100", description="Destination server IP")

class BatchFlowInput(BaseModel):
    flows: List[FlowInput] = Field(..., description="List of flow vectors to analyze in batch")

class ZeroDayReport(BaseModel):
    final_status: str
    is_zero_day: bool
    anomaly_votes: int
    total_models: int
    reconstruction_error: float
    threshold: float
    autoencoder: Dict[str, Any]
    isolation_forest: Dict[str, Any]
    one_class_svm: Dict[str, Any]

class ThreatPredictionResponse(BaseModel):
    source_ip: str
    destination_ip: str
    attack_type: str
    confidence: float
    severity: str
    decision: str
    containment_level: str
    ban_duration_minutes: int
    reputation_score: int
    repeat_offender: bool
    attack_count: int
    zero_day_analysis: Dict[str, Any]
    firewall_action: Dict[str, Any]
    explanation: str
    recommendation: str

class SnifferStartRequest(BaseModel):
    interface: Optional[str] = Field(default=None, description="Network interface name (e.g., 'Wi-Fi', 'Ethernet')")

class SnifferStatusResponse(BaseModel):
    is_running: bool
    interface: str
    packets_captured: int
    flows_completed: int
    active_flows_in_buffer: int
    threats_logged: int
