#!/usr/bin/env python3
"""
Pydantic Request & Response Schemas
Team Neural Breach — Role 6: Backend & Real-Time Detection
"""

from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field


class FlowRecordDict(BaseModel):
    """Network flow input feature dictionary."""
    features: Dict[str, float]


class PredictRequest(BaseModel):
    """Prediction request payload accepting one or more network flows."""
    flows: List[Dict[str, Any]] = Field(
        ...,
        description="List of flow dictionaries containing the 77 required network flow features."
    )
    explain: bool = Field(
        default=True,
        description="Whether to generate explainable AI (SHAP/LIME) feature attributions."
    )
    explainer_type: str = Field(
        default="shap",
        description="Explainer algorithm: 'shap' for Tree-SHAP or 'lime' for LIME Tabular."
    )
    top_k: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of top influential features to extract in explanation."
    )


class PredictionDetail(BaseModel):
    label: str
    is_attack: bool
    confidence: float
    classifier_type: str
    probabilities: Dict[str, float]


class AnomalyDetail(BaseModel):
    is_anomaly: bool
    isolation_forest_score: float
    isolation_forest_alert: bool
    autoencoder_recon_error: float
    autoencoder_alert: bool


class ThreatPriorityDetail(BaseModel):
    level: str
    score: float
    urgency: str
    scoring_factors: Dict[str, float]


class ExplanationDetail(BaseModel):
    method: str
    target_class: Optional[str] = None
    target_class_index: Optional[int] = None
    top_features: List[Dict[str, Any]]
    summary: str


class ThreatIntelDetail(BaseModel):
    attack_category: str
    effective_threat: str
    mitre_attack: Dict[str, Any]
    mitigations: List[str]
    recommendations: Dict[str, List[str]]


class FlowMetadataDetail(BaseModel):
    flow_index: int = 0
    protocol: int = 6
    flow_duration_ms: float = 0.0
    total_fwd_pkts: int = 0
    total_bwd_pkts: int = 0
    flow_bytes_per_sec: float = 0.0


class AlertResponse(BaseModel):
    """Unified security alert schema conforming to the Role 5/6 contract."""
    alert_id: str
    timestamp: str
    observe_only_mode: bool = True
    action_enforced: str = "NONE_OBSERVE_ONLY"
    prediction: PredictionDetail
    anomaly_detection: AnomalyDetail
    threat_priority: ThreatPriorityDetail
    explanation: ExplanationDetail
    threat_intelligence: ThreatIntelDetail
    flow_metadata: FlowMetadataDetail
    
    # Deduplication and aggregation tracking
    repeat_count: int = 1
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class PredictBatchResponse(BaseModel):
    """Batch prediction summary and generated alerts."""
    total_flows: int
    attacks_detected: int
    anomalies_detected: int
    observe_only_mode: bool = True
    action_enforced: str = "NONE_OBSERVE_ONLY"
    alerts: List[AlertResponse]


class HealthResponse(BaseModel):
    """Service health and model provenance response."""
    status: str
    app_name: str
    version: str
    timestamp: str
    observe_only_mode: bool
    action_enforced: str
    classifier_type: str
    fpr_budget: str
    expected_features_count: int
    models_loaded: Dict[str, bool]
    uptime_seconds: float
    active_websocket_connections: int
    stored_alerts_count: int


class StatsResponse(BaseModel):
    """Summary SOC telemetry and threat landscape metrics."""
    total_flows_evaluated: int
    total_alerts_stored: int
    observe_only_mode: bool
    alerts_by_threat_level: Dict[str, int]
    alerts_by_attack_category: Dict[str, int]
    top_mitre_techniques: List[Dict[str, Any]]


class SimulationRequest(BaseModel):
    """Request to simulate real-time ingestion from benchmark test split."""
    sample_size: int = Field(default=20, ge=1, le=500, description="Number of test flows to stream.")
    attack_ratio: float = Field(default=0.5, ge=0.0, le=1.0, description="Desired ratio of attack flows.")
    stream_delay_seconds: float = Field(default=0.01, ge=0.0, le=2.0, description="Delay between streaming flows.")
    broadcast_websocket: bool = Field(default=True, description="Whether to broadcast alerts to live WebSockets.")
