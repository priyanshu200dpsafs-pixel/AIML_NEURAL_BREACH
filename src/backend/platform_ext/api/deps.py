from __future__ import annotations
import uuid
from dataclasses import dataclass
from typing import Optional
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..config import PlatformSettings, get_settings
from ..db.base import as_utc, utcnow
from ..db.models import AuthSession, Device, Membership, User
from ..db.session import get_db
from ..security import rbac, tokens
from ..security.ratelimit import RateLimiter
from ..services import device_service

limiter = RateLimiter()


@dataclass
class Principal:
    user_id: str
    org_id: str
    role: str
    session_id: str
    is_platform_admin: bool = False


def client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None   # behind a proxy, configure uvicorn --proxy-headers + trusted hosts


def request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None)


def _bearer(request: Request) -> str:
    h = request.headers.get("authorization", "")
    if not h.lower().startswith("bearer ") or len(h) < 15:
        raise HTTPException(401, "missing_credentials", headers={"WWW-Authenticate": "Bearer"})
    return h[7:].strip()


def principal_from_token(db: Session, s: PlatformSettings, token: str, typ: str = "access") -> Principal:
    try:
        c = tokens.decode_jwt(token, secret=s.jwt_secret, issuer=s.jwt_issuer, audience=s.jwt_audience, typ=typ)
    except tokens.TokenError:
        raise HTTPException(401, "invalid_or_expired_token", headers={"WWW-Authenticate": "Bearer"})
    sess = db.get(AuthSession, c.get("sid"))
    if sess is None or sess.revoked_at is not None or as_utc(sess.expires_at) <= utcnow() or sess.user_id != c["sub"]:
        raise HTTPException(401, "session_revoked_or_expired")
    user = db.get(User, c["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "account_disabled")
    m = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.org_id == c["org"]))
    if m is None:
        raise HTTPException(403, "not_a_member")               # role is re-read from the DB: demotion/removal is immediate
    return Principal(user.id, m.org_id, m.role, sess.id, user.is_platform_admin)


def current_principal(request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)) -> Principal:
    p = principal_from_token(db, s, _bearer(request))
    if not limiter.allow(f"u:{p.user_id}", s.api_rate_per_minute):
        raise HTTPException(429, "rate_limited", headers={"Retry-After": "30"})
    return p


def require(perm: str):
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if not rbac.has_permission(p.role, perm):
            raise HTTPException(403, "forbidden")
        return p
    return dep


def require_platform_admin(p: Principal = Depends(current_principal)) -> Principal:
    if not p.is_platform_admin:
        raise HTTPException(403, "forbidden")
    return p


def current_device(request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)) -> Device:
    try:
        dev = device_service.authenticate_device(db, _bearer(request))
    except device_service.DeviceError as e:
        raise HTTPException(e.status, e.code)
    if not limiter.allow(f"d:{dev.id}", s.ingest_rate_per_minute):
        raise HTTPException(429, "rate_limited", headers={"Retry-After": "10"})
    return dev


def limit_ip(request: Request, name: str, per_minute: int) -> None:
    if not limiter.allow(f"{name}:{client_ip(request)}", per_minute):
        raise HTTPException(429, "rate_limited", headers={"Retry-After": "30"})
