from __future__ import annotations
from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..config import PlatformSettings, get_settings
from ..db.base import utcnow
from ..db.models import Device, Release, ReleasePolicy
from ..db.session import get_db
from ..releases import signing
from ..security import tokens
from ..services.audit import audit
from .deps import Principal, current_device, require_platform_admin

router = APIRouter(prefix="/api/v1", tags=["releases"])


class ReleaseIn(BaseModel):
    version: str
    channel: str = Field(pattern="^(stable|beta)$")
    os_name: str = Field(min_length=1, max_length=32)
    cpu_arch: str = Field(min_length=1, max_length=32)
    artifact_name: str = Field(min_length=1, max_length=255)
    artifact_size: int = Field(gt=0)
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    key_id: str
    signature: str
    signed_metadata: dict
    artifact_url: Optional[str] = Field(default=None, max_length=1000)


class RevokeIn(BaseModel):
    reason: str = Field(min_length=1, max_length=255)


class PolicyIn(BaseModel):
    channel: str = Field(pattern="^(stable|beta)$")
    min_supported_version: str


def _rel_json(r: Release) -> dict:
    return {"release_id": r.id, "version": r.version, "channel": r.channel, "os_name": r.os_name, "cpu_arch": r.cpu_arch,
            "artifact_name": r.artifact_name, "artifact_size": r.artifact_size, "sha256": r.sha256, "key_id": r.key_id,
            "signature": r.signature, "signed_metadata": r.signed_metadata, "revoked": r.revoked_at is not None}


@router.post("/releases", status_code=201)
def register_release(body: ReleaseIn, p: Principal = Depends(require_platform_admin), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    try:
        signing.parse_version(body.version)
        signing.verify_signed_metadata(body.signed_metadata, body.signature, body.key_id, s.release_trusted_keys)
        signing.check_artifact_binding(body.signed_metadata, sha256=body.sha256, size=body.artifact_size, version=body.version,
                                       channel=body.channel, os_name=body.os_name, cpu_arch=body.cpu_arch)
    except (signing.SignatureError, ValueError) as e:
        audit(db, action="release.register", actor_type="user", actor_id=p.user_id, outcome="failure", detail={"reason": str(e)})
        db.commit()
        raise HTTPException(422, detail={"code": "release_verification_failed", "detail": str(e)})
    latest = db.scalars(select(Release).where(Release.channel == body.channel, Release.os_name == body.os_name, Release.cpu_arch == body.cpu_arch)).all()
    if any(signing.parse_version(r.version) >= signing.parse_version(body.version) for r in latest):
        raise HTTPException(409, "version_must_increase")      # rollback protection at registration time
    r = Release(version=body.version, channel=body.channel, os_name=body.os_name, cpu_arch=body.cpu_arch, artifact_name=body.artifact_name,
                artifact_size=body.artifact_size, sha256=body.sha256, key_id=body.key_id, signature=body.signature,
                signed_metadata=body.signed_metadata, artifact_url=body.artifact_url)
    db.add(r); db.flush()
    audit(db, action="release.register", actor_type="user", actor_id=p.user_id, target=r.id)
    return _rel_json(r)


@router.post("/releases/{release_id}/revoke")
def revoke_release(release_id: str, body: RevokeIn, p: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    r = db.get(Release, release_id)
    if r is None:
        raise HTTPException(404, "not_found")
    r.revoked_at, r.revoked_reason = utcnow(), body.reason
    audit(db, action="release.revoke", actor_type="user", actor_id=p.user_id, target=r.id, detail={"reason": body.reason})
    return _rel_json(r)


@router.put("/releases/policy")
def set_policy(body: PolicyIn, p: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    signing.parse_version(body.min_supported_version)
    row = db.get(ReleasePolicy, body.channel)
    if row is None:
        db.add(ReleasePolicy(channel=body.channel, min_supported_version=body.min_supported_version))
    else:
        row.min_supported_version, row.updated_at = body.min_supported_version, utcnow()
    audit(db, action="release.policy", actor_type="user", actor_id=p.user_id, detail=body.model_dump())
    return {"status": "updated"}


@router.get("/updates/check")
def check_update(current_version: str = Query(...), channel: str = Query("stable", pattern="^(stable|beta)$"),
                 dev: Device = Depends(current_device), db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    try:
        cur = signing.parse_version(current_version)
    except ValueError:
        raise HTTPException(422, "invalid_version")
    rels = db.scalars(select(Release).where(Release.channel == channel, Release.os_name == dev.os_name, Release.cpu_arch == dev.cpu_arch,
                                            Release.revoked_at.is_(None))).all()
    rels = sorted(rels, key=lambda r: signing.parse_version(r.version), reverse=True)
    pol = db.get(ReleasePolicy, channel)
    below_min = bool(pol and cur < signing.parse_version(pol.min_supported_version))
    out = {"update_available": False, "update_required": below_min,
           "min_supported_version": pol.min_supported_version if pol else None}
    if rels and signing.parse_version(rels[0].version) > cur:
        r = rels[0]
        dl = tokens.encode_jwt({"sub": dev.id, "rel": r.id, "sha": r.sha256}, secret=s.jwt_secret, issuer=s.jwt_issuer,
                               audience=s.jwt_audience, ttl=s.download_token_ttl_seconds, typ="download")
        out.update(update_available=True, release=_rel_json(r), artifact_url=r.artifact_url, download_token=dl)
    return out
