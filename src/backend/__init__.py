"""
Role 6: Backend & Real-Time Detection
Team Neural Breach — AI/ML Cyber Defense Platform
"""

from src.backend.config import settings
from src.backend.app import app
from src.backend.pipeline import RealTimeDetectionPipeline
from src.backend.alert_manager import alert_store
from src.backend.websocket_manager import ws_manager

__all__ = ["app", "settings", "RealTimeDetectionPipeline", "alert_store", "ws_manager"]
