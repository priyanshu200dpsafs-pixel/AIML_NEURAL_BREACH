"""Authenticated, org-scoped alert stream. Cross-process delivery is by polling the alerts table (the worker is a separate
process), which avoids a message broker. Revocation is re-checked every REVALIDATE seconds and on every tick for devices."""
from __future__ import annotations
import asyncio, json, time
from collections import defaultdict
from typing import Dict, Optional
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from ..config import get_settings
from datetime import datetime
from ..db.base import as_utc, utcnow
from ..db.models import Alert, Device
from ..db.session import session_scope
from ..security import rbac
from ..services.alert_service import serialize
from .deps import principal_from_token
from fastapi import HTTPException

router = APIRouter()
REVALIDATE = 15.0
PING_EVERY = 20.0
_conns: Dict[str, int] = defaultdict(int)


def _auth(ticket: str):
    s = get_settings()
    with session_scope() as db:
        p = principal_from_token(db, s, ticket, typ="ws")
        if not rbac.has_permission(p.role, rbac.P_ALERTS_READ):
            raise HTTPException(403, "forbidden")
        return p


def _still_valid(p) -> bool:
    try:
        with session_scope() as db:
            from ..db.models import AuthSession, Membership
            sess = db.get(AuthSession, p.session_id)
            m = db.scalar(select(Membership).where(Membership.user_id == p.user_id, Membership.org_id == p.org_id))
            return bool(sess and sess.revoked_at is None and as_utc(sess.expires_at) > utcnow() and m and rbac.has_permission(m.role, rbac.P_ALERTS_READ))
    except Exception:
        return False


def _fetch(org_id: str, cursor, device_id: Optional[str]):
    with session_scope() as db:
        q = select(Alert).where(Alert.org_id == org_id, Alert.last_seen > cursor)     # org filter is mandatory
        if device_id:
            q = q.where(Alert.device_id == device_id)
        rows = db.scalars(q.order_by(Alert.last_seen).limit(100)).all()
        return [serialize(a) for a in rows]


def _device_ok(org_id: str, device_id: str) -> bool:
    with session_scope() as db:
        d = db.scalar(select(Device).where(Device.id == device_id, Device.org_id == org_id))
        return d is not None and d.status == "active"


from ..services.broadcaster import broadcaster

@router.websocket("/ws/v2/alerts")
async def alerts_ws(ws: WebSocket, ticket: str = Query(...), device_id: Optional[str] = Query(None)):
    s = get_settings()
    try:
        p = await run_in_threadpool(_auth, ticket)
    except Exception:
        await ws.close(code=4401)
        return
    if device_id and not await run_in_threadpool(_device_ok, p.org_id, device_id):
        await ws.close(code=4404)      # other org's / unknown device is indistinguishable
        return
    if _conns[p.org_id] >= s.ws_max_connections_per_org:
        await ws.close(code=4429)
        return
    await ws.accept()
    _conns[p.org_id] += 1
    cursor = utcnow()
    last_val = last_ping = time.monotonic()
    queue = broadcaster.subscribe(p.org_id, device_id)
    try:
        await ws.send_json({"event": "CONNECTED", "org_id": p.org_id, "observe_only_mode": True, "action_enforced": "NONE_OBSERVE_ONLY",
                            "server_time": cursor.isoformat()})
        # Single initial catch-up query on connect for alerts generated before websocket was established
        items = await run_in_threadpool(_fetch, p.org_id, cursor, device_id)
        for it in items:
            await ws.send_json({"event": "ALERT", "alert": it})
            cursor = max(cursor, as_utc(datetime.fromisoformat(it["last_seen"])))

        while True:
            now = time.monotonic()
            if now - last_val > REVALIDATE:
                last_val = now
                if not await run_in_threadpool(_still_valid, p):
                    await ws.close(code=4403)
                    return
                if device_id and not await run_in_threadpool(_device_ok, p.org_id, device_id):
                    await ws.close(code=4403)
                    return

            if now - last_ping > PING_EVERY:
                last_ping = now
                await ws.send_json({"event": "PING"})

            # Push-based delivery: await in-memory broadcaster queue (zero database polling in loop)
            try:
                alert_item = await asyncio.wait_for(queue.get(), timeout=s.ws_poll_interval_seconds)
                await ws.send_json({"event": "ALERT", "alert": alert_item})
                if "last_seen" in alert_item:
                    try:
                        cursor = max(cursor, as_utc(datetime.fromisoformat(alert_item["last_seen"])))
                    except Exception:
                        pass
            except asyncio.TimeoutError:
                pass

            # Check for client keepalive pings without blocking
            try:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=0.01)
                if msg.strip().lower() in ("ping", '{"event":"ping"}'):
                    await ws.send_json({"event": "PONG"})
            except asyncio.TimeoutError:
                pass
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        broadcaster.unsubscribe(p.org_id, queue)
        _conns[p.org_id] = max(0, _conns[p.org_id] - 1)
