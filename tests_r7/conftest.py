"""API/integration fixtures. NOT executed in the authoring environment (no fastapi/sqlalchemy/pytest installed there).
Run with: pip install -r requirements-platform.txt && pytest tests_r7 -v"""
import json, os, sys, tempfile
import pytest

_tmp = tempfile.mkdtemp()
COLS = [f"f{i}" for i in range(77)]
_cols_path = os.path.join(_tmp, "feature_columns.json")
json.dump(COLS, open(_cols_path, "w"))
DB_PATH = os.path.join(_tmp, "test.db")
os.environ.update({"NB_JWT_SECRET": "t" * 48, "NB_DATABASE_URL": f"sqlite:///{DB_PATH}", "NB_FEATURE_COLUMNS_PATH": _cols_path,
                   "NB_MAX_BATCH_FLOWS": "5", "NB_LOGIN_RATE_PER_MINUTE": "1000", "NB_JOB_BACKOFF_BASE_SECONDS": "0"})
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class FakeAdapter:
    """Test double standing in for the real Role 3/5/6 pipeline."""
    fail_times = 0
    def process(self, flows):
        if FakeAdapter.fail_times > 0:
            FakeAdapter.fail_times -= 1
            raise RuntimeError("simulated inference failure")
        return [{"flow_index": i, "label": "DDoS", "attack_category": "DoS/DDoS", "threat_level": "HIGH", "priority_score": 80.0,
                 "dedup_key": "ddos-a", "payload": {"prediction": {"label": "DDoS"}}} for i, _ in enumerate(flows)][:1]


@pytest.fixture()
def env():
    from platform_ext.config import get_settings
    from platform_ext.db.base import Base
    from platform_ext.db import session as sess, models  # noqa: F401
    from platform_ext.api import deps, agents
    from platform_ext.api.install import install_platform
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    get_settings.cache_clear(); agents._columns_cache = None; deps.limiter.__init__()
    if sess._engine is not None:
        sess._engine.dispose()
        sess._engine = None
        sess._Session = None
    os.environ["NB_DATABASE_URL"] = f"sqlite:///{DB_PATH}"
    os.environ["NB_FEATURE_COLUMNS_PATH"] = _cols_path
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    app = FastAPI()
    install_platform(app)
    Base.metadata.create_all(sess.get_engine())
    FakeAdapter.fail_times = 0
    c = TestClient(app)
    yield type("Env", (), {"client": c, "app": app, "settings": get_settings(), "sess": sess, "cols": COLS})
    c.close()
    if sess._engine is not None:
        sess.get_engine().dispose()
        sess._engine = None
        sess._Session = None


def register(client, email, org="Org", pw="a-long-password-1"):
    r = client.post("/api/v1/auth/register", json={"email": email, "password": pw, "org_name": org})
    assert r.status_code == 201, r.text
    d = r.json()
    return d, {"Authorization": f"Bearer {d['access_token']}"}


def enroll(client, hdr, host="h1"):
    t = client.post("/api/v1/agents/enrollment-tokens", json={}, headers=hdr).json()["enrollment_token"]
    r = client.post("/api/v1/agents/enroll", json={"enrollment_token": t, "hostname": host, "os_name": "windows", "cpu_arch": "x86_64", "client_version": "1.0.0"})
    assert r.status_code == 201, r.text
    d = r.json()
    return d, {"Authorization": f"Bearer {d['credential']}"}, t


def batch(cols, n=1, ts="now"):
    from datetime import datetime, timezone
    t = datetime.now(timezone.utc).isoformat()
    return {"flows": [{"observed_at": t, "features": {c: 1.0 for c in cols}} for _ in range(n)]}
