from __future__ import annotations
from datetime import timedelta
from typing import Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from ..config import PlatformSettings
from ..db.base import as_utc, utcnow
from ..db.models import Device, DeviceConfig, DeviceCredential, DeviceHeartbeat, EnrollmentToken
from ..security import tokens
from .audit import audit

DEFAULT_DEVICE_CONFIG = {"heartbeat_interval_seconds": 60, "batch_max_flows": 200, "batch_interval_seconds": 30,
                         "collect_payloads": False, "observe_only": True}


class DeviceError(Exception):
    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code, self.status = code, status


def create_enrollment_token(db: Session, s: PlatformSettings, *, org_id: str, user_id: str, label: Optional[str]) -> Tuple[str, EnrollmentToken]:
    plain, h = tokens.new_opaque_token(32)
    row = EnrollmentToken(org_id=org_id, token_hash=h, label=label, created_by=user_id,
                          expires_at=utcnow() + timedelta(seconds=s.enrollment_token_ttl_seconds))
    db.add(row); db.flush()
    audit(db, action="agent.enrollment_token.create", actor_type="user", actor_id=user_id, org_id=org_id, target=row.id)
    return plain, row


def enroll(db: Session, *, token: str, hostname: str, os_name: str, os_version: Optional[str], cpu_arch: str,
           client_version: str, ip: Optional[str], request_id: Optional[str]) -> dict:
    h = tokens.sha256_hex(token)
    now = utcnow()
    # Atomic single-use claim: only one concurrent request can flip used_at from NULL.
    claimed = db.execute(update(EnrollmentToken)
                         .where(EnrollmentToken.token_hash == h, EnrollmentToken.used_at.is_(None),
                                EnrollmentToken.revoked_at.is_(None), EnrollmentToken.expires_at > now)
                         .values(used_at=now))
    if claimed.rowcount != 1:
        audit(db, action="agent.enroll", actor_type="system", outcome="failure", ip=ip, request_id=request_id, detail={"reason": "bad_token"})
        db.commit()
        raise DeviceError("invalid_enrollment_token", 401)
    et = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == h))
    dev = Device(org_id=et.org_id, hostname=hostname[:255], os_name=os_name[:64], os_version=(os_version or "")[:64] or None,
                 cpu_arch=cpu_arch[:32], client_version=client_version[:32], last_seen_at=now)
    db.add(dev); db.flush()
    et.used_by_device = dev.id
    secret_plain, secret_hash = tokens.new_opaque_token(32)
    db.add(DeviceCredential(device_id=dev.id, secret_hash=secret_hash))
    audit(db, action="agent.enroll", actor_type="device", actor_id=dev.id, org_id=dev.org_id, target=dev.id, ip=ip, request_id=request_id)
    return {"agent_id": dev.id, "org_id": dev.org_id, "credential": tokens.make_device_bearer(dev.id, secret_plain)}


def authenticate_device(db: Session, bearer: str) -> Device:
    """Device auth is entirely separate from user JWTs. Revoked devices and revoked/old credentials fail here."""
    try:
        did, secret = tokens.parse_device_bearer(bearer)
    except tokens.TokenError:
        raise DeviceError("invalid_device_credential", 401)
    h = tokens.sha256_hex(secret)
    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.device_id == did, DeviceCredential.revoked_at.is_(None)))
    dev = db.get(Device, did)
    ok = cred is not None and tokens.constant_time_equal(cred.secret_hash, h)
    if not ok or dev is None:
        raise DeviceError("invalid_device_credential", 401)
    if dev.status != "active":
        raise DeviceError("device_revoked", 403)
    return dev


def rotate_credential(db: Session, dev: Device, *, ip: Optional[str], request_id: Optional[str]) -> str:
    now = utcnow()
    db.execute(update(DeviceCredential).where(DeviceCredential.device_id == dev.id, DeviceCredential.revoked_at.is_(None)).values(revoked_at=now))
    secret_plain, secret_hash = tokens.new_opaque_token(32)
    db.add(DeviceCredential(device_id=dev.id, secret_hash=secret_hash))
    audit(db, action="agent.credential.rotate", actor_type="device", actor_id=dev.id, org_id=dev.org_id, target=dev.id, ip=ip, request_id=request_id)
    return tokens.make_device_bearer(dev.id, secret_plain)


def record_heartbeat(db: Session, dev: Device, *, client_version: str, status_info: Optional[dict]) -> None:
    now = utcnow()
    dev.last_seen_at = now
    dev.client_version = client_version[:32]
    db.add(DeviceHeartbeat(org_id=dev.org_id, device_id=dev.id, client_version=client_version[:32], status_info=status_info))


def revoke_device(db: Session, *, org_id: str, device_id: str, user_id: str, reason: Optional[str]) -> Device:
    dev = db.scalar(select(Device).where(Device.id == device_id, Device.org_id == org_id))   # org-scoped: other org => 404
    if dev is None:
        raise DeviceError("not_found", 404)
    now = utcnow()
    dev.status, dev.revoked_at, dev.revoked_reason = "revoked", now, (reason or "")[:255] or None
    db.execute(update(DeviceCredential).where(DeviceCredential.device_id == dev.id, DeviceCredential.revoked_at.is_(None)).values(revoked_at=now))
    audit(db, action="agent.revoke", actor_type="user", actor_id=user_id, org_id=org_id, target=dev.id, detail={"reason": reason})
    return dev


def effective_config(db: Session, dev: Device) -> dict:
    row = db.scalar(select(DeviceConfig).where(DeviceConfig.org_id == dev.org_id, DeviceConfig.device_id == dev.id))
    if row is None:
        row = db.scalar(select(DeviceConfig).where(DeviceConfig.org_id == dev.org_id, DeviceConfig.device_id.is_(None)))
    cfg = {**DEFAULT_DEVICE_CONFIG, **(row.config if row else {})}
    cfg["collect_payloads"] = False   # platform invariant: never overridable
    cfg["observe_only"] = True
    return {"version": row.version if row else 0, "config": cfg}


def connectivity(dev: Device, window_seconds: int) -> str:
    if dev.status == "revoked":
        return "revoked"
    if dev.last_seen_at is None:
        return "never_seen"
    ls = as_utc(dev.last_seen_at)
    return "online" if (utcnow() - ls).total_seconds() <= window_seconds else "offline"
