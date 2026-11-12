from __future__ import annotations
import json
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..config import PlatformSettings, get_settings
from ..db.base import utcnow
from ..db.models import Device, DeviceConfig, TelemetryBatch
from ..db.session import get_db
from ..ingest import contract
from ..security import rbac
from ..services import device_service, ingest_service
from ..services.audit import audit
from .deps import Principal, client_ip, current_device, current_principal, limit_ip, principal_from_token, request_id, require, _bearer

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])
_columns_cache: list[str] | None = None


def feature_columns(s: PlatformSettings) -> list[str]:
    global _columns_cache
    if _columns_cache is None:
        _columns_cache = contract.load_feature_columns(s.feature_columns_path)
    return _columns_cache


class EnrollIn(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=64)
    os_version: Optional[str] = Field(default=None, max_length=64)
    cpu_arch: str = Field(min_length=1, max_length=32)
    client_version: str = Field(min_length=1, max_length=32)


class HeartbeatIn(BaseModel):
    client_version: str = Field(min_length=1, max_length=32)
    status_info: Optional[dict] = None


class TokenIn(BaseModel):
    label: Optional[str] = Field(default=None, max_length=120)


class RevokeIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=255)


class ConfigIn(BaseModel):
    config: dict


def _dev_json(d: Device, s: PlatformSettings) -> dict:
    return {"agent_id": d.id, "hostname": d.hostname, "os_name": d.os_name, "os_version": d.os_version, "cpu_arch": d.cpu_arch,
            "client_version": d.client_version, "status": d.status, "connectivity": device_service.connectivity(d, s.device_online_window_seconds),
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None, "created_at": d.created_at.isoformat(),
            "revoked_at": d.revoked_at.isoformat() if d.revoked_at else None}


def _dev_err(e: device_service.DeviceError):
    return HTTPException(e.status, e.code)


@router.post("/enroll", status_code=201)
def enroll(body: EnrollIn, request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    limit_ip(request, "enroll", 20)
    try:
        out = device_service.enroll(db, token=body.enrollment_token, hostname=body.hostname, os_name=body.os_name, os_version=body.os_version,
                                    cpu_arch=body.cpu_arch, client_version=body.client_version, ip=client_ip(request), request_id=request_id(request))
        db.commit()
        return out
    except device_service.DeviceError as e:
        raise _dev_err(e)


@router.post("/enrollment-tokens", status_code=201)
def create_token(body: TokenIn, p: Principal = Depends(require(rbac.P_DEVICES_MANAGE)), db: Session = Depends(get_db),
                 s: PlatformSettings = Depends(get_settings)):
    plain, row = device_service.create_enrollment_token(db, s, org_id=p.org_id, user_id=p.user_id, label=body.label)
    return {"enrollment_token": plain, "expires_at": row.expires_at.isoformat(), "single_use": True}   # plaintext shown once


@router.post("/heartbeat")
def heartbeat(body: HeartbeatIn, dev: Device = Depends(current_device), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    device_service.record_heartbeat(db, dev, client_version=body.client_version, status_info=body.status_info)
    cfg = device_service.effective_config(db, dev)
    return {"status": "ok", "server_time": utcnow().isoformat(), "config_version": cfg["version"]}


@router.post("/credential/rotate")
def rotate(request: Request, dev: Device = Depends(current_device), db: Session = Depends(get_db)):
    return {"credential": device_service.rotate_credential(db, dev, ip=client_ip(request), request_id=request_id(request))}


@router.get("")
def list_agents(status: Optional[str] = Query(None, pattern="^(active|revoked)$"), os_name: Optional[str] = None,
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                p: Principal = Depends(require(rbac.P_DEVICES_READ)), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    q = select(Device).where(Device.org_id == p.org_id)
    if status: q = q.where(Device.status == status)
    if os_name: q = q.where(Device.os_name == os_name)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(Device.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [_dev_json(d, s) for d in rows]}


def _org_device(db: Session, org_id: str, agent_id: str) -> Device:
    d = db.scalar(select(Device).where(Device.id == agent_id, Device.org_id == org_id))
    if d is None:
        raise HTTPException(404, "not_found")
    return d


@router.get("/{agent_id}")
def get_agent(agent_id: str, p: Principal = Depends(require(rbac.P_DEVICES_READ)), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    return _dev_json(_org_device(db, p.org_id, agent_id), s)


@router.get("/{agent_id}/config")
def get_config(agent_id: str, request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    """Readable by the device itself (device credential) or by org members with devices:read."""
    tok = _bearer(request)
    if tok.count(".") == 2:                                   # JWT => user
        p = principal_from_token(db, s, tok)
        if not rbac.has_permission(p.role, rbac.P_DEVICES_READ):
            raise HTTPException(403, "forbidden")
        return effective(db, _org_device(db, p.org_id, agent_id))
    try:
        dev = device_service.authenticate_device(db, tok)
    except device_service.DeviceError as e:
        raise _dev_err(e)
    if dev.id != agent_id:
        raise HTTPException(403, "forbidden")
    return effective(db, dev)


def effective(db, dev):
    return device_service.effective_config(db, dev)


@router.put("/{agent_id}/config")
def put_config(agent_id: str, body: ConfigIn, p: Principal = Depends(require(rbac.P_DEVICES_MANAGE)), db: Session = Depends(get_db)):
    d = _org_device(db, p.org_id, agent_id)
    row = db.scalar(select(DeviceConfig).where(DeviceConfig.org_id == p.org_id, DeviceConfig.device_id == d.id))
    clean = {k: v for k, v in body.config.items() if k not in ("collect_payloads", "observe_only")}
    if row is None:
        db.add(DeviceConfig(org_id=p.org_id, device_id=d.id, config=clean, version=1))
    else:
        row.config, row.version, row.updated_at = clean, row.version + 1, utcnow()
    audit(db, action="agent.config.update", actor_type="user", actor_id=p.user_id, org_id=p.org_id, target=d.id)
    return {"status": "updated"}


@router.post("/{agent_id}/revoke")
def revoke(agent_id: str, body: RevokeIn, p: Principal = Depends(require(rbac.P_DEVICES_MANAGE)), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    try:
        d = device_service.revoke_device(db, org_id=p.org_id, device_id=agent_id, user_id=p.user_id, reason=body.reason)
    except device_service.DeviceError as e:
        raise _dev_err(e)
    return _dev_json(d, s)


@router.post("/{agent_id}/telemetry/batches", status_code=202)
async def ingest(agent_id: str, request: Request, idempotency_key: str = Header(..., alias="Idempotency-Key"),
                 dev: Device = Depends(current_device), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    if dev.id != agent_id:                                    # a device can only ever submit as itself
        raise HTTPException(403, "forbidden")
    raw = await request.body()
    if len(raw) > s.max_request_bytes:
        raise HTTPException(413, "payload_too_large")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise HTTPException(422, "invalid_json")
    if not isinstance(doc, dict) or set(doc.keys()) != {"flows"}:
        raise HTTPException(422, "body_must_be_object_with_only_flows")
    try:
        out = ingest_service.accept_batch(db, s, feature_columns(s), dev, idempotency_key=idempotency_key, raw_body=raw, flows_payload=doc["flows"])
        db.commit()
    except ingest_service.IngestError as e:
        raise HTTPException(e.status, detail={"code": e.code, **({"detail": e.detail} if e.detail else {})})
    dev.last_seen_at = utcnow()
    return out


@router.get("/{agent_id}/telemetry/batches")
def list_batches(agent_id: str, status: Optional[str] = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                 p: Principal = Depends(require(rbac.P_DEVICES_READ)), db: Session = Depends(get_db)):
    _org_device(db, p.org_id, agent_id)
    q = select(TelemetryBatch).where(TelemetryBatch.org_id == p.org_id, TelemetryBatch.device_id == agent_id)
    if status: q = q.where(TelemetryBatch.status == status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(TelemetryBatch.received_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [{"batch_id": b.id, "status": b.status, "flow_count": b.flow_count, "error": b.error,
                                       "received_at": b.received_at.isoformat()} for b in rows]}
