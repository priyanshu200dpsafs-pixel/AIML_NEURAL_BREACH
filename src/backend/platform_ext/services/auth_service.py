from __future__ import annotations
from datetime import timedelta
from typing import Optional, Tuple
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..config import PlatformSettings
from ..db.base import as_utc, utcnow
from ..db.models import AuthSession, Membership, Organization, User
from ..security import passwords, rbac, tokens
from .audit import audit
import uuid


class AuthError(Exception):
    def __init__(self, code: str, status: int = 401):
        super().__init__(code)
        self.code, self.status = code, status


def _issue(db: Session, s: PlatformSettings, user: User, org_id: str, family_id: Optional[str] = None) -> dict:
    refresh_plain, refresh_hash = tokens.new_opaque_token()
    sess = AuthSession(user_id=user.id, org_id=org_id, family_id=family_id or str(uuid.uuid4()), refresh_hash=refresh_hash,
                       expires_at=utcnow() + timedelta(seconds=s.refresh_token_ttl_seconds))
    db.add(sess)
    db.flush()
    access = tokens.encode_jwt({"sub": user.id, "sid": sess.id, "org": org_id}, secret=s.jwt_secret, issuer=s.jwt_issuer,
                               audience=s.jwt_audience, ttl=s.access_token_ttl_seconds, typ="access")
    return {"access_token": access, "refresh_token": refresh_plain, "token_type": "bearer",
            "expires_in": s.access_token_ttl_seconds, "org_id": org_id}


def register(db: Session, s: PlatformSettings, *, email: str, password: str, org_name: str, display_name: Optional[str],
             ip: Optional[str], request_id: Optional[str]) -> dict:
    email = email.strip().lower()
    try:
        passwords.validate_password_policy(password)
    except ValueError as e:
        raise AuthError(str(e), 422)
    if db.scalar(select(User).where(User.email == email)):
        # Generic message: do not confirm account existence to an anonymous caller.
        raise AuthError("registration_failed", 409)
    user = User(email=email, password_hash=passwords.hash_password(password), display_name=display_name)
    org = Organization(name=org_name.strip()[:200])
    db.add_all([user, org]); db.flush()
    db.add(Membership(user_id=user.id, org_id=org.id, role=rbac.OWNER))
    audit(db, action="auth.register", actor_type="user", actor_id=user.id, org_id=org.id, ip=ip, request_id=request_id)
    return {**_issue(db, s, user, org.id), "user_id": user.id}


def login(db: Session, s: PlatformSettings, *, email: str, password: str, org_id: Optional[str],
          ip: Optional[str], request_id: Optional[str]) -> dict:
    email = email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    now = utcnow()
    if user is None:
        passwords.verify_password(password, passwords.DUMMY_HASH)   # equalise timing
        audit(db, action="auth.login", outcome="failure", ip=ip, request_id=request_id, detail={"reason": "unknown_user"})
        raise AuthError("invalid_credentials")
    if user.locked_until and as_utc(user.locked_until) > now:
        audit(db, action="auth.login", actor_type="user", actor_id=user.id, outcome="failure", ip=ip, request_id=request_id, detail={"reason": "locked"})
        raise AuthError("invalid_credentials")
    if not user.is_active or not passwords.verify_password(password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_logins = 0
        audit(db, action="auth.login", actor_type="user", actor_id=user.id, outcome="failure", ip=ip, request_id=request_id, detail={"reason": "bad_password"})
        db.commit()   # persist the failure counter even though the request ends in an error
        raise AuthError("invalid_credentials")
    user.failed_logins = 0
    q = select(Membership).where(Membership.user_id == user.id)
    if org_id:
        q = q.where(Membership.org_id == org_id)
    m = db.scalars(q.order_by(Membership.created_at)).first()
    if m is None:
        raise AuthError("invalid_credentials")
    out = _issue(db, s, user, m.org_id)
    audit(db, action="auth.login", actor_type="user", actor_id=user.id, org_id=m.org_id, ip=ip, request_id=request_id)
    return out


def refresh(db: Session, s: PlatformSettings, *, refresh_token: str, ip: Optional[str], request_id: Optional[str]) -> dict:
    h = tokens.sha256_hex(refresh_token)
    sess = db.scalar(select(AuthSession).where(AuthSession.refresh_hash == h))
    now = utcnow()
    if sess is None:
        raise AuthError("invalid_refresh_token")
    if sess.rotated_at is not None or sess.revoked_at is not None:
        # Reuse of a rotated/revoked token => assume theft: kill the whole family.
        for x in db.scalars(select(AuthSession).where(AuthSession.family_id == sess.family_id)):
            x.revoked_at = x.revoked_at or now
        audit(db, action="auth.refresh_reuse_detected", actor_type="user", actor_id=sess.user_id, org_id=sess.org_id,
              outcome="failure", ip=ip, request_id=request_id)
        db.commit()
        raise AuthError("invalid_refresh_token")
    if as_utc(sess.expires_at) <= now:
        raise AuthError("invalid_refresh_token")
    user = db.get(User, sess.user_id)
    still_member = db.scalar(select(Membership).where(Membership.user_id == sess.user_id, Membership.org_id == sess.org_id))
    if not user or not user.is_active or not still_member:
        sess.revoked_at = now
        db.commit()
        raise AuthError("invalid_refresh_token")
    sess.rotated_at = now
    out = _issue(db, s, user, sess.org_id, family_id=sess.family_id)
    audit(db, action="auth.refresh", actor_type="user", actor_id=user.id, org_id=sess.org_id, ip=ip, request_id=request_id)
    return out


def logout_session(db: Session, session_id: str, *, user_id: str, org_id: str, ip: Optional[str], request_id: Optional[str]) -> None:
    sess = db.get(AuthSession, session_id)
    if sess and sess.user_id == user_id:
        for x in db.scalars(select(AuthSession).where(AuthSession.family_id == sess.family_id)):
            x.revoked_at = x.revoked_at or utcnow()
    audit(db, action="auth.logout", actor_type="user", actor_id=user_id, org_id=org_id, ip=ip, request_id=request_id)
