#!/usr/bin/env python3
"""
WebSocket Connection & Alert Broadcast Manager
Team Neural Breach — Role 6: Backend & Real-Time Detection
"""

import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("neural_breach.backend.websocket")


class WebSocketManager:
    """
    Thread-safe, asynchronous WebSocket hub broadcasting live alerts
    to all active SOC analyst dashboard sessions.
    """
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accepts and registers a new WebSocket client session."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active sessions: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Unregisters a disconnected client session."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Active sessions: {len(self.active_connections)}")

    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        """
        Broadcasts a structured alert to all connected dashboard sessions.
        Gracefully catches and purges stale/broken connections.
        """
        if not self.active_connections:
            return

        payload = json.dumps(alert_data)
        stale = set()
        
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.warning(f"Failed to transmit alert to WebSocket client: {e}. Marking stale.")
                stale.add(connection)

        for s in stale:
            self.active_connections.discard(s)

    async def broadcast_message(self, message: Dict[str, Any]):
        """Broadcasts general operational or telemetry events."""
        await self.broadcast_alert(message)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


ws_manager = WebSocketManager()
