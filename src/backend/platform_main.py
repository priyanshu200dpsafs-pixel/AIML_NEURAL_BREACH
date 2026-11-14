#!/usr/bin/env python3
"""
Team Neural Breach — Platform Production & Container Server Entry Point
Integrates Role 6 Real-Time Detection Backend with Role 7 Multi-Tenant Platform Extension
and serves the React SOC Dashboard.
"""

from __future__ import annotations
import os
import logging
from src.backend.app import app
from src.backend.config import settings

logger = logging.getLogger("neural_breach.platform_main")

# Auto-mount platform extension if JWT secret is present in environment
if os.environ.get("NB_JWT_SECRET"):
    try:
        from src.backend.platform_ext.api.install import install_platform
        install_platform(app)
        logger.info("Neural Breach Platform Extension mounted successfully.")
    except Exception as e:
        logger.warning(f"Could not mount platform extension: {e}")

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("NEURAL_BREACH_HOST", settings.HOST)
    port = int(os.environ.get("NEURAL_BREACH_PORT", settings.PORT))
    uvicorn.run("src.backend.platform_main:app", host=host, port=port, log_level="info")

