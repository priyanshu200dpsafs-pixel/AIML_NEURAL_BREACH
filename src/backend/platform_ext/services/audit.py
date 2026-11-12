from __future__ import annotations
from typing import Any, Optional
from sqlalchemy.orm import Session
from ..db.models import AuditLog


def audit(db: Session, *, action: str, actor_type: str = "system", actor_id: Optional[str] = None,
          org_id: Optional[str] = None, target: Optional[str] = None, outcome: str = "success",
          ip: Optional[str] = None, request_id: Optional[str] = None, detail: Optional[dict] = None) -> None:
    """Never put secrets, tokens, passwords or feature payloads in `detail`."""
    db.add(AuditLog(action=action, actor_type=actor_type, actor_id=actor_id, org_id=org_id, target=target,
                    outcome=outcome, ip=ip, request_id=request_id, detail=detail))
