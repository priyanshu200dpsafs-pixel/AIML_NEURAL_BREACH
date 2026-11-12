from __future__ import annotations
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..db.models import AlertNote, AuditLog, Job
from ..db.session import get_db
from ..security import rbac
from ..services import alert_service as svc
from .deps import Principal, require

# Base router containing all alert endpoints without prefix
router_base = APIRouter(tags=["alerts"])


class StatusIn(BaseModel):
    status: str


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


def _get(db, p, alert_id):
    try:
        return svc.get_alert(db, p.org_id, alert_id)
    except svc.AlertError as e:
        raise HTTPException(e.status, e.code)


@router_base.get("/alerts")
def list_alerts(
    device_id: Optional[str] = None,
    threat_level: Optional[str] = None,
    attack_category: Optional[str] = None,
    status: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    min_score: Optional[float] = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    p: Principal = Depends(require(rbac.P_ALERTS_READ)),
    db: Session = Depends(get_db)
):
    total, rows = svc.list_alerts(
        db,
        org_id=p.org_id,
        device_id=device_id,
        threat_level=threat_level,
        attack_category=attack_category,
        status=status,
        since=since,
        until=until,
        min_score=min_score,
        limit=limit,
        offset=offset
    )
    return {"total": total, "limit": limit, "offset": offset, "items": [svc.serialize(a) for a in rows]}


@router_base.get("/alerts/{alert_id}")
def get_alert(alert_id: str, p: Principal = Depends(require(rbac.P_ALERTS_READ)), db: Session = Depends(get_db)):
    a = _get(db, p, alert_id)
    notes = db.scalars(
        select(AlertNote).where(AlertNote.alert_id == a.id, AlertNote.org_id == p.org_id).order_by(AlertNote.created_at)
    ).all()
    return {
        **svc.serialize(a),
        "notes": [{"id": n.id, "author_id": n.author_id, "body": n.body, "created_at": n.created_at.isoformat()} for n in notes]
    }


@router_base.post("/alerts/{alert_id}/acknowledge")
def ack(alert_id: str, p: Principal = Depends(require(rbac.P_ALERTS_WRITE)), db: Session = Depends(get_db)):
    return svc.serialize(svc.acknowledge(db, _get(db, p, alert_id), p.user_id))


@router_base.patch("/alerts/{alert_id}/status")
def status(alert_id: str, body: StatusIn, p: Principal = Depends(require(rbac.P_ALERTS_WRITE)), db: Session = Depends(get_db)):
    try:
        return svc.serialize(svc.set_status(db, _get(db, p, alert_id), p.user_id, body.status))
    except svc.AlertError as e:
        raise HTTPException(e.status, e.code)


@router_base.post("/alerts/{alert_id}/notes", status_code=201)
def note(alert_id: str, body: NoteIn, p: Principal = Depends(require(rbac.P_ALERTS_WRITE)), db: Session = Depends(get_db)):
    n = svc.add_note(db, _get(db, p, alert_id), p.user_id, body.body)
    return {"id": n.id, "created_at": n.created_at.isoformat()}


@router_base.get("/alerts/{alert_id}/history")
def history(alert_id: str, p: Principal = Depends(require(rbac.P_ALERTS_READ)), db: Session = Depends(get_db)):
    a = _get(db, p, alert_id)
    rows = db.scalars(
        select(AuditLog).where(AuditLog.org_id == p.org_id, AuditLog.target == a.id).order_by(AuditLog.created_at)
    ).all()
    return {"items": [{"action": r.action, "actor_id": r.actor_id, "detail": r.detail, "at": r.created_at.isoformat()} for r in rows]}


@router_base.get("/queue/stats")
def queue_stats(p: Principal = Depends(require(rbac.P_DEVICES_MANAGE)), db: Session = Depends(get_db)):
    rows = db.execute(select(Job.status, func.count()).where(Job.org_id == p.org_id).group_by(Job.status)).all()
    return {"jobs_by_status": {k: v for k, v in rows}}


# Primary routers: /api/v1 (candidate test compatibility) and /api/v2 (enterprise non-colliding route)
router = APIRouter(prefix="/api/v1")
router.include_router(router_base)

router_v2 = APIRouter(prefix="/api/v2")
router_v2.include_router(router_base)
