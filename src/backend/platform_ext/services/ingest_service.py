from __future__ import annotations
import hashlib, json
from typing import List, Sequence
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ..config import PlatformSettings
from ..db.base import utcnow
from ..db.models import Device, Job, NetworkFlow, TelemetryBatch
from ..ingest import contract
from .audit import audit


class IngestError(Exception):
    def __init__(self, code: str, status: int, detail=None):
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


def accept_batch(db: Session, s: PlatformSettings, columns: Sequence[str], dev: Device, *, idempotency_key: str, raw_body: bytes,
                 flows_payload) -> dict:
    """Validate -> persist batch + flows + job in ONE transaction (atomic: no flows without a job, no job without flows).
    org_id/device_id come from the authenticated device row, never from the payload."""
    if not (8 <= len(idempotency_key) <= 128) or not idempotency_key.isprintable():
        raise IngestError("invalid_idempotency_key", 422)
    digest = hashlib.sha256(raw_body).hexdigest()
    existing = db.scalar(select(TelemetryBatch).where(TelemetryBatch.device_id == dev.id, TelemetryBatch.idempotency_key == idempotency_key))
    if existing:
        if existing.payload_sha256 != digest:
            raise IngestError("idempotency_key_reuse_with_different_payload", 409)
        return {"batch_id": existing.id, "status": existing.status, "flow_count": existing.flow_count, "duplicate": True}
    try:
        clean = contract.validate_batch(flows_payload, columns, max_flows=s.max_batch_flows, max_skew_seconds=s.max_timestamp_skew_seconds)
    except contract.ContractError as e:
        # Track rejected batches (metadata only; the rejected payload is not stored).
        db.add(TelemetryBatch(org_id=dev.org_id, device_id=dev.id, idempotency_key=idempotency_key, payload_sha256=digest,
                              flow_count=0, status="rejected", error=str(e)[:500]))
        audit(db, action="telemetry.reject", actor_type="device", actor_id=dev.id, org_id=dev.org_id, outcome="failure", detail={"reason": str(e)[:200], "index": e.index})
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        raise IngestError("schema_validation_failed", 422, {"message": str(e), "flow_index": e.index})
    batch = TelemetryBatch(org_id=dev.org_id, device_id=dev.id, idempotency_key=idempotency_key, payload_sha256=digest,
                           flow_count=len(clean), status="accepted")
    db.add(batch)
    try:
        db.flush()
    except IntegrityError:           # concurrent duplicate lost the race: return the winner
        db.rollback()
        win = db.scalar(select(TelemetryBatch).where(TelemetryBatch.device_id == dev.id, TelemetryBatch.idempotency_key == idempotency_key))
        return {"batch_id": win.id, "status": win.status, "flow_count": win.flow_count, "duplicate": True}
    db.add_all([NetworkFlow(org_id=dev.org_id, device_id=dev.id, batch_id=batch.id, seq=i, observed_at=f["observed_at"], features=f["features"])
                for i, f in enumerate(clean)])
    db.add(Job(kind="infer_batch", org_id=dev.org_id, batch_id=batch.id, max_attempts=s.job_max_attempts))
    return {"batch_id": batch.id, "status": "accepted", "flow_count": len(clean), "duplicate": False}
