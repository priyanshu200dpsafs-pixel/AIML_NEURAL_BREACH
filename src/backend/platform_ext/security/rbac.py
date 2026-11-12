"""Role -> permission matrix. Every protected endpoint declares exactly one required permission."""
from __future__ import annotations

OWNER, ADMIN, ANALYST, VIEWER = "owner", "admin", "analyst", "viewer"
ROLES = (OWNER, ADMIN, ANALYST, VIEWER)

P_ORG_MANAGE = "org:manage"            # rename org, change owners
P_MEMBERS_MANAGE = "members:manage"
P_DEVICES_READ = "devices:read"
P_DEVICES_MANAGE = "devices:manage"    # enrollment tokens, revoke, config
P_ALERTS_READ = "alerts:read"
P_ALERTS_WRITE = "alerts:write"        # ack, status, notes
P_AUDIT_READ = "audit:read"

_VIEW = {P_DEVICES_READ, P_ALERTS_READ}
_ANALYST = _VIEW | {P_ALERTS_WRITE}
_ADMIN = _ANALYST | {P_DEVICES_MANAGE, P_MEMBERS_MANAGE, P_AUDIT_READ}
_OWNER = _ADMIN | {P_ORG_MANAGE}

ROLE_PERMISSIONS = {OWNER: frozenset(_OWNER), ADMIN: frozenset(_ADMIN), ANALYST: frozenset(_ANALYST), VIEWER: frozenset(_VIEW)}


def has_permission(role: str, perm: str) -> bool:
    return perm in ROLE_PERMISSIONS.get(role, frozenset())


def can_assign_role(actor_role: str, target_role: str) -> bool:
    """Admins may assign analyst/viewer only; only owners may mint admins/owners."""
    if actor_role == OWNER:
        return target_role in ROLES
    if actor_role == ADMIN:
        return target_role in (ANALYST, VIEWER)
    return False
