#!/usr/bin/env python3
"""
FastAPI Security Backend Service
Team Neural Breach — Role 6: Backend & Real-Time Detection

Endpoints:
  - GET  /api/v1/health: Service health, model provenance, observe-only confirmation.
  - POST /api/v1/predict: Low-latency network flow inference with SHAP/LIME & MITRE enrichment.
  - GET  /api/v1/alerts: Paginated, filtered historical security alerts.
  - GET  /api/v1/alerts/{alert_id}: Detailed single alert retrieval.
  - GET  /api/v1/stats: SOC telemetry, threat distributions, and top MITRE tactics.
  - POST /api/v1/alerts/simulate: Real-time simulation streaming from authentic benchmark test flows.
  - WS   /ws/alerts: High-throughput WebSocket alert stream for SOC dashboard.
"""

import time
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.backend.config import settings
from src.backend.schemas import (
    PredictRequest, PredictBatchResponse, HealthResponse, StatsResponse,
    SimulationRequest, AlertResponse
)
from src.backend.pipeline import RealTimeDetectionPipeline
from src.backend.alert_manager import alert_store
from src.backend.websocket_manager import ws_manager
from src.models.inference_engine import ModelInferenceError

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("neural_breach.backend.app")

# Global pipeline instance initialized on startup
pipeline: Optional[RealTimeDetectionPipeline] = None
start_time_epoch: float = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager preloading models and XAI explainers."""
    global pipeline, start_time_epoch
    start_time_epoch = time.time()
    logger.info("Initializing Neural Breach Real-Time Detection Pipeline...")
    pipeline = RealTimeDetectionPipeline(
        classifier_type=settings.DEFAULT_CLASSIFIER,
        fpr_budget=settings.FPR_BUDGET,
        alert_manager=alert_store,
        websocket_manager=ws_manager
    )
    logger.info("Neural Breach Backend initialized successfully in OBSERVE-ONLY mode!")
    yield
    logger.info("Shutting down Neural Breach Backend...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production AI/ML Cyber Defense Platform Backend & SOC Alert Delivery Service. "
        "Strictly operated in Observe-Only mode without automated packet dropping."
    ),
    lifespan=lifespan
)

# Enable CORS for external dashboard interfaces
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["General"])
async def root():
    """Root endpoint verifying API operational status."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "observe_only_mode": True,
        "action_enforced": settings.ACTION_ENFORCED,
        "docs_url": "/docs"
    }


@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Comprehensive health-check endpoint confirming model provenance,
    observe-only posture, and active WebSocket subscriber count.
    """
    global pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Inference engine pipeline not initialized")

    uptime = time.time() - start_time_epoch
    stats = alert_store.get_stats()

    return HealthResponse(
        status="HEALTHY",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        observe_only_mode=settings.OBSERVE_ONLY_MODE,
        action_enforced=settings.ACTION_ENFORCED,
        classifier_type=pipeline.engine.clf_type,
        fpr_budget=pipeline.fpr_budget,
        expected_features_count=len(pipeline.expected_features),
        models_loaded={
            "supervised_classifier": pipeline.engine.classifier is not None,
            "isolation_forest": pipeline.engine.iso_forest is not None,
            "deep_autoencoder": pipeline.engine.autoencoder is not None,
            "scaler": pipeline.engine.scaler is not None,
            "shap_explainer": pipeline.threat_service.explainer.shap_ready if pipeline.threat_service.explainer else False,
            "mitre_stix_catalog": True
        },
        uptime_seconds=round(uptime, 2),
        active_websocket_connections=ws_manager.connection_count,
        stored_alerts_count=stats["total_alerts_stored"]
    )


@app.post("/api/v1/predict", response_model=PredictBatchResponse, tags=["Inference"])
async def predict_network_flows(request: PredictRequest):
    """
    Evaluates one or more network flows, runs supervised + unsupervised anomaly inference,
    attaches Role 5 XAI feature attribution (SHAP/LIME), verified MITRE ATT&CK mapping,
    and transparent threat prioritization.
    """
    global pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Inference pipeline not initialized")

    if not request.flows:
        raise HTTPException(status_code=400, detail="Flows list cannot be empty")

    if len(request.flows) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "BatchSizeExceeded",
                "max_batch_size": settings.MAX_BATCH_SIZE,
                "received_batch_size": len(request.flows),
                "message": f"Batch size of {len(request.flows)} flows exceeds maximum permitted limit of {settings.MAX_BATCH_SIZE} flows."
            }
        )

    try:
        # Construct DataFrame
        df_flows = pd.DataFrame(request.flows)
        
        # Verify required features contract
        missing_cols = [c for c in pipeline.expected_features if c not in df_flows.columns]
        if missing_cols:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "SchemaValidationViolation",
                    "missing_features_count": len(missing_cols),
                    "missing_features": missing_cols[:10],
                    "message": f"Input flows violate schema contract. Missing {len(missing_cols)} required features."
                }
            )

        # Execute detection pipeline
        alerts = await pipeline.process_flows(
            df=df_flows,
            explain=request.explain,
            explainer_type=request.explainer_type,
            top_k=request.top_k,
            broadcast_ws=True
        )

        n_attacks = sum(1 for a in alerts if a["prediction"]["is_attack"])
        n_anomalies = sum(1 for a in alerts if a["anomaly_detection"]["is_anomaly"])

        return PredictBatchResponse(
            total_flows=len(alerts),
            attacks_detected=n_attacks,
            anomalies_detected=n_anomalies,
            observe_only_mode=settings.OBSERVE_ONLY_MODE,
            action_enforced=settings.ACTION_ENFORCED,
            alerts=alerts
        )

    except HTTPException:
        raise
    except ModelInferenceError as mie:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(mie))
    except Exception as e:
        logger.error(f"Inference pipeline execution error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")


@app.get("/api/v1/alerts", tags=["Alerts"])
async def get_alerts(
    threat_level: Optional[str] = Query(None, description="Filter by threat level: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    attack_category: Optional[str] = Query(None, description="Filter by attack category, e.g. Infiltration"),
    min_score: Optional[float] = Query(None, description="Filter by minimum composite priority score (0 - 100)"),
    limit: int = Query(50, ge=1, le=500, description="Pagination limit"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """Retrieves paginated, filtered historical security alerts."""
    paginated_alerts, total_count = alert_store.list_alerts(
        threat_level=threat_level,
        attack_category=attack_category,
        min_score=min_score,
        limit=limit,
        offset=offset
    )

    return {
        "total_matching": total_count,
        "limit": limit,
        "offset": offset,
        "observe_only_mode": settings.OBSERVE_ONLY_MODE,
        "alerts": paginated_alerts
    }


@app.get("/api/v1/alerts/{alert_id}", response_model=AlertResponse, tags=["Alerts"])
async def get_alert_by_id(alert_id: str):
    """Retrieves complete details for a single security alert."""
    alert = alert_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")
    return alert


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_soc_statistics():
    """Retrieves real-time SOC threat metrics, severity distributions, and top MITRE techniques."""
    stats = alert_store.get_stats()
    return StatsResponse(**stats)


@app.post("/api/v1/alerts/simulate", tags=["Simulation"])
async def simulate_traffic_stream(request: SimulationRequest):
    """
    Streams authentic flows from the benchmark test split (CSE-CIC-IDS2018),
    executing real-time inference, attaching XAI and MITRE mappings, and broadcasting
    live alerts to active SOC dashboard WebSockets.
    """
    global pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Inference pipeline not initialized")

    try:
        simulated_alerts = await pipeline.simulate_stream(
            sample_size=request.sample_size,
            attack_ratio=request.attack_ratio,
            stream_delay_seconds=request.stream_delay_seconds,
            broadcast_ws=request.broadcast_websocket,
            test_split_path=request.test_split_path
        )

        n_attacks = sum(1 for a in simulated_alerts if a["prediction"]["is_attack"])
        n_anomalies = sum(1 for a in simulated_alerts if a["anomaly_detection"]["is_anomaly"])

        return {
            "status": "COMPLETED",
            "sample_size": len(simulated_alerts),
            "attacks_detected": n_attacks,
            "anomalies_detected": n_anomalies,
            "broadcast_websocket": request.broadcast_websocket,
            "observe_only_mode": settings.OBSERVE_ONLY_MODE,
            "alerts": simulated_alerts
        }
    except FileNotFoundError as fnfe:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "TestDatasetUnavailable",
                "message": str(fnfe),
                "setup_instructions": (
                    "The benchmark test dataset is not available at the configured path. "
                    "Run 'python scripts/sync_data_drive.py' to download the CSE-CIC-IDS2018 test.parquet "
                    "dataset or specify a valid path via the NEURAL_BREACH_TEST_SPLIT_PATH environment variable."
                )
            }
        )
    except Exception as e:
        logger.error(f"Simulation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")


@app.websocket("/ws/alerts")
async def websocket_alert_feed(websocket: WebSocket):
    """
    Real-time WebSocket endpoint streaming security alerts
    directly to active SOC analyst dashboards.
    """
    await ws_manager.connect(websocket)
    # Send welcome handshake
    handshake = {
        "event": "CONNECTED",
        "service": settings.APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "observe_only_mode": True,
        "action_enforced": settings.ACTION_ENFORCED,
        "message": "Connected to Neural Breach Real-Time Alert Stream (Observe-Only Mode)"
    }
    await websocket.send_text(pd.Series(handshake).to_json())

    try:
        while True:
            # Keep connection alive; accept optional ping/filter commands from dashboard
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event": "PONG"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket session exception: {e}")
        ws_manager.disconnect(websocket)
