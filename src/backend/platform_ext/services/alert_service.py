from __future__ import annotations
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..db.base import utcnow
from ..db.models import Alert, AlertNote
from .audit import audit

DEDUP_WINDOW_SECONDS = 60          # mirrors Role 6 DEDUPLICATION_WINDOW_SECONDS
STATUSES = ("new", "acknowledged", "investigating", "resolved", "false_positive")


class AlertError(Exception):
    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code, self.status = code, status


def signature_for(device_id: str, result: Dict[str, Any]) -> str:
    key = result.get("dedup_key") or f"{result.get('label')}|{result.get('attack_category')}"
    return hashlib.sha256(f"{device_id}|{key}".encode()).hexdigest()


from .broadcaster import broadcaster


def upsert_alert(db: Session, *, org_id: str, device_id: str, batch_id: Optional[str], result: Dict[str, Any],
                 now: Optional[datetime] = None) -> Tuple[Alert, bool]:
    """Persist one detection result produced by the EXISTING pipeline. Fields are copied, never recomputed.
    Duplicate aggregation: same (org, device, signature) inside the window bumps repeat_count/last_seen."""
    now = now or utcnow()
    sig = signature_for(device_id, result)
    cutoff = now - timedelta(seconds=DEDUP_WINDOW_SECONDS)
    existing = db.scalar(select(Alert).where(Alert.org_id == org_id, Alert.device_id == device_id, Alert.signature == sig,
                                             Alert.last_seen >= cutoff).order_by(Alert.last_seen.desc()).limit(1).with_for_update())
    if existing:
        existing.repeat_count += 1
        existing.last_seen = now
        payload = dict(existing.payload); payload["repeat_count"] = existing.repeat_count
        payload["last_seen"] = now.isoformat()
        existing.payload = payload                      # reassign so the JSON change is tracked
        broadcaster.publish_alert(org_id, serialize(existing), device_id=device_id)
        return existing, False
    a = Alert(org_id=org_id, device_id=device_id, batch_id=batch_id, signature=sig, label=str(result.get("label", "unknown"))[:100],
              attack_category=(result.get("attack_category") or None), threat_level=str(result.get("threat_level", "UNKNOWN"))[:20],
              priority_score=result.get("priority_score"), first_seen=now, last_seen=now, payload=dict(result.get("payload") or {}))
    db.add(a); db.flush()
    a.payload = {**a.payload, "alert_id": a.id, "org_id": org_id, "device_id": device_id, "repeat_count": 1,
                 "first_seen": now.isoformat(), "last_seen": now.isoformat(),
                 "observe_only_mode": True, "action_enforced": "NONE_OBSERVE_ONLY"}
    broadcaster.publish_alert(org_id, serialize(a), device_id=device_id)
    return a, True


def serialize(a: Alert) -> dict:
    return {"alert_id": a.id, "org_id": a.org_id, "device_id": a.device_id, "label": a.label, "attack_category": a.attack_category,
            "threat_level": a.threat_level, "priority_score": a.priority_score, "repeat_count": a.repeat_count,
            "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
            "investigation_status": a.investigation_status, "acknowledged_by": a.acknowledged_by,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None, "details": a.payload}


def list_alerts(db: Session, *, org_id: str, device_id=None, threat_level=None, attack_category=None, status=None,
                since: Optional[datetime] = None, until: Optional[datetime] = None, min_score: Optional[float] = None,
                limit: int = 50, offset: int = 0):
    q = select(Alert).where(Alert.org_id == org_id)                 # tenant filter is unconditional
    if device_id: q = q.where(Alert.device_id == device_id)
    if threat_level: q = q.where(Alert.threat_level == threat_level.upper())
    if attack_category: q = q.where(Alert.attack_category == attack_category)
    if status: q = q.where(Alert.investigation_status == status)
    if since: q = q.where(Alert.last_seen >= since)
    if until: q = q.where(Alert.last_seen <= until)
    if min_score is not None: q = q.where(Alert.priority_score >= min_score)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(Alert.last_seen.desc(), Alert.id).limit(min(max(limit, 1), 200)).offset(max(offset, 0))).all()
    return total, rows


def get_alert(db: Session, org_id: str, alert_id: str) -> Alert:
    a = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.org_id == org_id))
    if a is None:
        raise AlertError("not_found", 404)           # same response whether it exists in another org or not at all
    return a


def acknowledge(db: Session, a: Alert, user_id: str) -> Alert:
    if a.investigation_status == "new":
        a.investigation_status = "acknowledged"
    a.acknowledged_by, a.acknowledged_at = user_id, utcnow()
    audit(db, action="alert.acknowledge", actor_type="user", actor_id=user_id, org_id=a.org_id, target=a.id)
    return a


def set_status(db: Session, a: Alert, user_id: str, new_status: str) -> Alert:
    if new_status not in STATUSES:
        raise AlertError("invalid_status", 422)
    old = a.investigation_status
    a.investigation_status = new_status
    audit(db, action="alert.status_change", actor_type="user", actor_id=user_id, org_id=a.org_id, target=a.id, detail={"from": old, "to": new_status})
    return a


def add_note(db: Session, a: Alert, user_id: str, body: str) -> AlertNote:
    n = AlertNote(alert_id=a.id, org_id=a.org_id, author_id=user_id, body=body[:5000])
    db.add(n); db.flush()
    audit(db, action="alert.note", actor_type="user", actor_id=user_id, org_id=a.org_id, target=a.id)
    return n
