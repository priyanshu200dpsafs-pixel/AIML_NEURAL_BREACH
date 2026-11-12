"""Postgres-backed worker. Claim with FOR UPDATE SKIP LOCKED, process in one transaction, retry with exponential backoff."""
from __future__ import annotations
import importlib, logging, os, signal, socket, threading, time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Protocol
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from ..config import PlatformSettings
from ..db.base import utcnow
from ..db.models import Job, NetworkFlow, TelemetryBatch
from .alert_service import upsert_alert

log = logging.getLogger("neural_breach.worker")


class DetectionAdapter(Protocol):
    def process(self, flows: List[Dict[str, float]]) -> List[Dict[str, Any]]:
        """Run the EXISTING Role 3/5/6 pipeline. Return one dict per alert-worthy flow:
        {flow_index, label, attack_category, threat_level, priority_score, dedup_key?, payload:<Role 6 alert dict>}.
        Benign flows may be omitted. Must not retrain, mutate models, or enforce actions."""


DEFAULT_ADAPTER = "src.backend.platform_ext.adapters.detection_adapter:create_detection_adapter"


def load_adapter(path: str = "") -> DetectionAdapter:
    path = path or os.environ.get("NB_DETECTION_ADAPTER") or DEFAULT_ADAPTER
    mod, _, fn = path.partition(":")
    if not fn:
        factory = getattr(importlib.import_module(mod), "create_detection_adapter")
        return factory()
    return getattr(importlib.import_module(mod), fn)()


def reclaim_stale(db: Session, s: PlatformSettings) -> int:
    cutoff = utcnow() - timedelta(seconds=s.job_lock_timeout_seconds)
    r = db.execute(update(Job).where(Job.status == "running", Job.locked_at < cutoff).values(status="queued", locked_by=None))
    return r.rowcount or 0


def claim_job(db: Session, worker_id: str) -> Job | None:
    job = db.scalar(select(Job).where(Job.status == "queued", Job.run_after <= utcnow())
                    .order_by(Job.run_after).limit(1).with_for_update(skip_locked=True))
    if job is None:
        return None
    job.status, job.locked_at, job.locked_by = "running", utcnow(), worker_id
    job.attempts += 1
    db.flush()
    return job


def _process(db: Session, job: Job, adapter: DetectionAdapter) -> int:
    batch = db.get(TelemetryBatch, job.batch_id)
    rows = db.scalars(select(NetworkFlow).where(NetworkFlow.batch_id == batch.id).order_by(NetworkFlow.seq)).all()
    results = adapter.process([r.features for r in rows])
    n = 0
    for res in results:
        upsert_alert(db, org_id=batch.org_id, device_id=batch.device_id, batch_id=batch.id, result=res)
        n += 1
    batch.status = "processed"
    return n


def run_one(session_factory: Callable[[], Session], s: PlatformSettings, adapter: DetectionAdapter, worker_id: str) -> bool:
    """Returns True if a job was handled. Alert writes + job completion commit atomically, so a crash mid-job leaves no
    partial alerts and the job is re-queued by reclaim_stale (idempotent processing)."""
    db = session_factory()
    try:
        reclaim_stale(db, s)
        job = claim_job(db, worker_id)
        db.commit()
        if job is None:
            return False
        job_id = job.id
    finally:
        db.close()

    db = session_factory()
    try:
        job = db.get(Job, job_id)
        try:
            _process(db, job, adapter)
            job.status, job.finished_at, job.last_error = "done", utcnow(), None
            db.commit()
        except Exception as e:   # noqa: BLE001 - any failure must be recorded and retried
            db.rollback()
            job = db.get(Job, job_id)
            job.last_error = f"{type(e).__name__}: {e}"[:1000]
            if job.attempts >= job.max_attempts:
                job.status, job.finished_at = "failed", utcnow()
                b = db.get(TelemetryBatch, job.batch_id)
                if b:
                    b.status, b.error = "failed", job.last_error
            else:
                job.status, job.locked_by, job.locked_at = "queued", None, None
                job.run_after = utcnow() + timedelta(seconds=s.job_backoff_base_seconds * (2 ** (job.attempts - 1)))
            db.commit()
            log.warning("job %s failed (attempt %s): %s", job_id, job.attempts, job.last_error)
        return True
    finally:
        db.close()


def worker_loop(session_factory, s: PlatformSettings, adapter: DetectionAdapter, *, idle_sleep: float = 1.0,
                liveness_file: str = "/tmp/nb_worker_alive") -> None:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())     # graceful: finish the current job, then exit
    wid = f"{socket.gethostname()}:{os.getpid()}"
    while not stop.is_set():
        try:
            busy = run_one(session_factory, s, adapter, wid)
        except Exception:                             # DB outage etc: back off, keep the process alive
            log.exception("worker iteration failed")
            busy = False
            time.sleep(2.0)
        try:
            open(liveness_file, "w").write(str(time.time()))
        except OSError:
            pass
        if not busy:
            stop.wait(idle_sleep)
