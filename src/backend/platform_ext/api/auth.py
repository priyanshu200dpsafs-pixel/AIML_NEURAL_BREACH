from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..config import PlatformSettings, get_settings
from ..db.models import Membership, Organization, User
from ..db.session import get_db
from ..security import rbac, tokens
from ..services import auth_service
from ..services.audit import audit
from ..security import passwords
from .deps import Principal, client_ip, current_principal, limit_ip, request_id, require

router = APIRouter(prefix="/api/v1", tags=["auth"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    org_name: str = Field(min_length=1, max_length=200)
    display_name: Optional[str] = Field(default=None, max_length=120)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    org_id: Optional[str] = None


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=512)


class MemberIn(BaseModel):
    email: EmailStr
    role: str


def _wrap(fn, *a, **k):
    try:
        return fn(*a, **k)
    except auth_service.AuthError as e:
        raise HTTPException(e.status, e.code)


@router.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    limit_ip(request, "register", s.login_rate_per_minute)
    return _wrap(auth_service.register, db, s, email=body.email, password=body.password, org_name=body.org_name,
                 display_name=body.display_name, ip=client_ip(request), request_id=request_id(request))


@router.post("/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    limit_ip(request, "login", s.login_rate_per_minute)
    return _wrap(auth_service.login, db, s, email=body.email, password=body.password, org_id=body.org_id,
                 ip=client_ip(request), request_id=request_id(request))


@router.post("/auth/refresh")
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db), s: PlatformSettings = Depends(get_settings)):
    limit_ip(request, "refresh", s.login_rate_per_minute * 3)
    return _wrap(auth_service.refresh, db, s, refresh_token=body.refresh_token, ip=client_ip(request), request_id=request_id(request))


@router.post("/auth/logout", status_code=204)
def logout(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    auth_service.logout_session(db, p.session_id, user_id=p.user_id, org_id=p.org_id, ip=client_ip(request), request_id=request_id(request))


@router.get("/auth/me")
def me(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    u = db.get(User, p.user_id)
    return {"user_id": u.id, "email": u.email, "display_name": u.display_name, "org_id": p.org_id, "role": p.role}


@router.post("/ws/ticket")
def ws_ticket(p: Principal = Depends(require("alerts:read")), s: PlatformSettings = Depends(get_settings)):
    """Short-lived single-purpose ticket so access tokens never appear in WebSocket URLs."""
    t = tokens.encode_jwt({"sub": p.user_id, "sid": p.session_id, "org": p.org_id}, secret=s.jwt_secret, issuer=s.jwt_issuer,
                          audience=s.jwt_audience, ttl=s.ws_ticket_ttl_seconds, typ="ws")
    return {"ticket": t, "expires_in": s.ws_ticket_ttl_seconds}


@router.post("/org/members", status_code=201)
def add_member(body: MemberIn, request: Request, p: Principal = Depends(require(rbac.P_MEMBERS_MANAGE)), db: Session = Depends(get_db)):
    if not rbac.can_assign_role(p.role, body.role):
        raise HTTPException(403, "cannot_assign_role")
    u = db.scalar(select(User).where(User.email == body.email.lower()))
    if u is None:
        raise HTTPException(404, "user_not_found")          # invitation flow (email) is out of scope for this increment
    if db.scalar(select(Membership).where(Membership.user_id == u.id, Membership.org_id == p.org_id)):
        raise HTTPException(409, "already_member")
    db.add(Membership(user_id=u.id, org_id=p.org_id, role=body.role))
    audit(db, action="org.member.add", actor_type="user", actor_id=p.user_id, org_id=p.org_id, target=u.id, detail={"role": body.role},
          ip=client_ip(request), request_id=request_id(request))
    return {"user_id": u.id, "role": body.role}


@router.delete("/org/members/{user_id}", status_code=204)
def remove_member(user_id: str, p: Principal = Depends(require(rbac.P_MEMBERS_MANAGE)), db: Session = Depends(get_db)):
    m = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id == p.org_id))
    if m is None:
        raise HTTPException(404, "not_found")
    if m.role == rbac.OWNER and p.role != rbac.OWNER:
        raise HTTPException(403, "forbidden")
    if m.role == rbac.OWNER:
        owners = db.scalars(select(Membership).where(Membership.org_id == p.org_id, Membership.role == rbac.OWNER)).all()
        if len(owners) <= 1:
            raise HTTPException(409, "cannot_remove_last_owner")
    db.delete(m)
    audit(db, action="org.member.remove", actor_type="user", actor_id=p.user_id, org_id=p.org_id, target=user_id)
