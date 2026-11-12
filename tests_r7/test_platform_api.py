import json, time
from datetime import timedelta
import pytest
from .conftest import FakeAdapter, batch, enroll, register


# ---- registration / auth / sessions -------------------------------------------------------------------------------
def test_register_login_me(env):
    d, h = register(env.client, "a@x.io")
    assert env.client.get("/api/v1/auth/me", headers=h).json()["role"] == "owner"
    r = env.client.post("/api/v1/auth/login", json={"email": "a@x.io", "password": "a-long-password-1"})
    assert r.status_code == 200 and "refresh_token" in r.json()


def test_bad_password_generic_and_weak_password_rejected(env):
    register(env.client, "a@x.io")
    r1 = env.client.post("/api/v1/auth/login", json={"email": "a@x.io", "password": "wrong-password-xx"})
    r2 = env.client.post("/api/v1/auth/login", json={"email": "nobody@x.io", "password": "wrong-password-xx"})
    assert r1.status_code == r2.status_code == 401 and r1.json()["error"]["code"] == r2.json()["error"]["code"]
    assert env.client.post("/api/v1/auth/register", json={"email": "b@x.io", "password": "short", "org_name": "O"}).status_code == 422


def test_account_lockout(env):
    register(env.client, "a@x.io")
    for _ in range(5):
        env.client.post("/api/v1/auth/login", json={"email": "a@x.io", "password": "wrong-password-xx"})
    assert env.client.post("/api/v1/auth/login", json={"email": "a@x.io", "password": "a-long-password-1"}).status_code == 401


def test_refresh_rotation_and_reuse_detection(env):
    d, _ = register(env.client, "a@x.io")
    r1 = env.client.post("/api/v1/auth/refresh", json={"refresh_token": d["refresh_token"]})
    assert r1.status_code == 200
    assert env.client.post("/api/v1/auth/refresh", json={"refresh_token": d["refresh_token"]}).status_code == 401   # reuse
    assert env.client.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]}).status_code == 401  # family killed


def test_logout_revokes_session(env):
    d, h = register(env.client, "a@x.io")
    assert env.client.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert env.client.get("/api/v1/auth/me", headers=h).status_code == 401
    assert env.client.post("/api/v1/auth/refresh", json={"refresh_token": d["refresh_token"]}).status_code == 401


def test_expired_access_token(env, monkeypatch):
    from platform_ext.security import tokens
    d, _ = register(env.client, "a@x.io")
    s = env.settings
    old = tokens.encode_jwt({"sub": "x", "sid": "y", "org": "z"}, secret=s.jwt_secret, issuer=s.jwt_issuer, audience=s.jwt_audience, ttl=60, typ="access", now=time.time() - 3600)
    assert env.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_unauthenticated_and_garbage_tokens(env):
    assert env.client.get("/api/v1/alerts").status_code == 401
    assert env.client.get("/api/v1/agents", headers={"Authorization": "Bearer garbage.garbage.garbage"}).status_code == 401


# ---- RBAC + isolation ---------------------------------------------------------------------------------------------
def _add_member(env, owner_hdr, email, role):
    d, h = register(env.client, email, org=f"Own-{email}")
    r = env.client.post("/api/v1/org/members", json={"email": email, "role": role}, headers=owner_hdr)
    assert r.status_code == 201, r.text
    login = env.client.post("/api/v1/auth/login", json={"email": email, "password": "a-long-password-1", "org_id": None}).json()
    # choose the owner's org explicitly
    me = env.client.get("/api/v1/auth/me", headers=owner_hdr).json()
    login = env.client.post("/api/v1/auth/login", json={"email": email, "password": "a-long-password-1", "org_id": me["org_id"]}).json()
    return {"Authorization": f"Bearer {login['access_token']}"}


def test_permission_matrix_enforced(env):
    _, owner = register(env.client, "o@x.io")
    viewer = _add_member(env, owner, "v@x.io", "viewer")
    analyst = _add_member(env, owner, "an@x.io", "analyst")
    assert env.client.get("/api/v1/alerts", headers=viewer).status_code == 200
    assert env.client.post("/api/v1/agents/enrollment-tokens", json={}, headers=viewer).status_code == 403
    assert env.client.post("/api/v1/agents/enrollment-tokens", json={}, headers=analyst).status_code == 403
    assert env.client.post("/api/v1/org/members", json={"email": "z@x.io", "role": "viewer"}, headers=analyst).status_code == 403


def test_admin_cannot_mint_owner(env):
    _, owner = register(env.client, "o@x.io")
    admin = _add_member(env, owner, "ad@x.io", "admin")
    register(env.client, "t@x.io", org="T")
    assert env.client.post("/api/v1/org/members", json={"email": "t@x.io", "role": "owner"}, headers=admin).status_code == 403


def test_cross_org_isolation_devices_alerts_config_revoke(env):
    _, h1 = register(env.client, "o1@x.io", org="Org1")
    _, h2 = register(env.client, "o2@x.io", org="Org2")
    d1, dh1, _ = enroll(env.client, h1)
    aid = d1["agent_id"]
    # Org2 cannot see, read config of, revoke, or list batches of Org1's device
    assert env.client.get(f"/api/v1/agents/{aid}", headers=h2).status_code == 404
    assert env.client.get(f"/api/v1/agents/{aid}/config", headers=h2).status_code == 404
    assert env.client.post(f"/api/v1/agents/{aid}/revoke", json={}, headers=h2).status_code == 404
    assert env.client.get(f"/api/v1/agents/{aid}/telemetry/batches", headers=h2).status_code == 404
    assert env.client.get("/api/v1/agents", headers=h2).json()["total"] == 0
    # Org1 device is intact
    assert env.client.get(f"/api/v1/agents/{aid}", headers=h1).status_code == 200


def test_cross_org_alert_leak(env):
    from platform_ext.services.worker import run_one
    _, h1 = register(env.client, "o1@x.io", org="Org1")
    _, h2 = register(env.client, "o2@x.io", org="Org2")
    d1, dh1, _ = enroll(env.client, h1)
    assert env.client.post(f"/api/v1/agents/{d1['agent_id']}/telemetry/batches", json=batch(env.cols), headers={**dh1, "Idempotency-Key": "key-0001-abcd"}).status_code == 202
    run_one(env.sess._Session, env.settings, FakeAdapter(), "w1")
    a = env.client.get("/api/v1/alerts", headers=h1).json()
    assert a["total"] == 1
    assert env.client.get("/api/v1/alerts", headers=h2).json()["total"] == 0
    assert env.client.get(f"/api/v1/alerts/{a['items'][0]['alert_id']}", headers=h2).status_code == 404
    assert env.client.post(f"/api/v1/alerts/{a['items'][0]['alert_id']}/acknowledge", headers=h2).status_code == 404


# ---- enrollment / revocation / rotation / heartbeat ----------------------------------------------------------------
def test_enrollment_token_single_use_and_expiry(env):
    _, h = register(env.client, "o@x.io")
    d, dh, tok = enroll(env.client, h)
    body = {"enrollment_token": tok, "hostname": "h2", "os_name": "windows", "cpu_arch": "x86_64", "client_version": "1.0.0"}
    assert env.client.post("/api/v1/agents/enroll", json=body).status_code == 401           # already used
    t2 = env.client.post("/api/v1/agents/enrollment-tokens", json={}, headers=h).json()["enrollment_token"]
    from sqlalchemy import update
    from platform_ext.db.models import EnrollmentToken
    from platform_ext.db.base import utcnow
    with env.sess.session_scope() as db:
        db.execute(update(EnrollmentToken).values(expires_at=utcnow() - timedelta(seconds=1)))
    assert env.client.post("/api/v1/agents/enroll", json={**body, "enrollment_token": t2}).status_code == 401
    assert env.client.post("/api/v1/agents/enroll", json={**body, "enrollment_token": "x" * 30}).status_code == 401


def test_heartbeat_and_connectivity(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    r = env.client.post("/api/v1/agents/heartbeat", json={"client_version": "1.0.1"}, headers=dh)
    assert r.status_code == 200
    got = env.client.get(f"/api/v1/agents/{d['agent_id']}", headers=h).json()
    assert got["connectivity"] == "online" and got["client_version"] == "1.0.1"


def test_revoked_device_cannot_submit_or_heartbeat(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    assert env.client.post(f"/api/v1/agents/{d['agent_id']}/revoke", json={"reason": "stolen"}, headers=h).status_code == 200
    ik = {"Idempotency-Key": "key-0001-abcd"}
    assert env.client.post(f"/api/v1/agents/{d['agent_id']}/telemetry/batches", json=batch(env.cols), headers={**dh, **ik}).status_code in (401, 403)
    assert env.client.post("/api/v1/agents/heartbeat", json={"client_version": "1"}, headers=dh).status_code in (401, 403)


def test_credential_rotation_invalidates_old(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    new = env.client.post("/api/v1/agents/credential/rotate", headers=dh).json()["credential"]
    assert env.client.post("/api/v1/agents/heartbeat", json={"client_version": "1"}, headers=dh).status_code == 401
    assert env.client.post("/api/v1/agents/heartbeat", json={"client_version": "1"}, headers={"Authorization": f"Bearer {new}"}).status_code == 200


def test_user_jwt_cannot_act_as_device_and_vice_versa(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    assert env.client.post("/api/v1/agents/heartbeat", json={"client_version": "1"}, headers=h).status_code == 401
    assert env.client.get("/api/v1/alerts", headers=dh).status_code == 401


def test_device_cannot_submit_as_another_device(env):
    _, h = register(env.client, "o@x.io")
    d1, dh1, _ = enroll(env.client, h, "a")
    d2, dh2, _ = enroll(env.client, h, "b")
    r = env.client.post(f"/api/v1/agents/{d2['agent_id']}/telemetry/batches", json=batch(env.cols), headers={**dh1, "Idempotency-Key": "key-0001-abcd"})
    assert r.status_code == 403


# ---- telemetry validation / idempotency ---------------------------------------------------------------------------
def _post(env, d, dh, body, key="key-0001-abcd"):
    return env.client.post(f"/api/v1/agents/{d['agent_id']}/telemetry/batches", json=body, headers={**dh, "Idempotency-Key": key})


def test_invalid_telemetry_rejected(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    b = batch(env.cols); b["flows"][0]["features"].pop("f5")
    assert _post(env, d, dh, b, "key-aaaa-0001").status_code == 422
    b = batch(env.cols); b["flows"][0]["features"]["payload"] = "AAAA"
    assert _post(env, d, dh, b, "key-aaaa-0002").status_code == 422
    b = batch(env.cols); b["flows"][0]["features"]["f1"] = "str"
    assert _post(env, d, dh, b, "key-aaaa-0003").status_code == 422
    b = batch(env.cols); b["flows"][0]["observed_at"] = "2001-01-01T00:00:00Z"
    assert _post(env, d, dh, b, "key-aaaa-0004").status_code == 422
    b = batch(env.cols); b["extra"] = 1
    assert _post(env, d, dh, b, "key-aaaa-0005").status_code == 422
    assert env.client.post(f"/api/v1/agents/{d['agent_id']}/telemetry/batches", content=b"{not json", headers={**dh, "Idempotency-Key": "key-aaaa-0006", "Content-Type": "application/json"}).status_code == 422
    rejected = env.client.get(f"/api/v1/agents/{d['agent_id']}/telemetry/batches?status=rejected", headers=h).json()
    assert rejected["total"] >= 4


def test_oversized_batch_and_body_rejected(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    assert _post(env, d, dh, batch(env.cols, n=6), "key-big-0001").status_code == 422          # NB_MAX_BATCH_FLOWS=5
    big = {"flows": [], "pad": "x" * (env.settings.max_request_bytes + 10)}
    assert env.client.post(f"/api/v1/agents/{d['agent_id']}/telemetry/batches", json=big, headers={**dh, "Idempotency-Key": "key-big-0002"}).status_code == 413


def test_duplicate_ingestion_is_idempotent(env):
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    b = batch(env.cols, 2)
    r1, r2 = _post(env, d, dh, b), _post(env, d, dh, b)
    assert r1.status_code == r2.status_code == 202
    assert r1.json()["batch_id"] == r2.json()["batch_id"] and r2.json()["duplicate"] is True
    assert _post(env, d, dh, batch(env.cols, 1)).status_code == 409                          # same key, different payload
    from sqlalchemy import func, select
    from platform_ext.db.models import Job
    with env.sess.session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Job)) == 1


# ---- worker -------------------------------------------------------------------------------------------------------
def test_worker_processes_and_dedups(env):
    from platform_ext.services.worker import run_one
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    _post(env, d, dh, batch(env.cols, 3), "key-w-00001"); _post(env, d, dh, batch(env.cols, 3), "key-w-00002")
    assert run_one(env.sess._Session, env.settings, FakeAdapter(), "w") and run_one(env.sess._Session, env.settings, FakeAdapter(), "w")
    items = env.client.get("/api/v1/alerts", headers=h).json()["items"]
    assert len(items) == 1 and items[0]["repeat_count"] == 2 and items[0]["details"]["action_enforced"] == "NONE_OBSERVE_ONLY"


def test_worker_retry_then_success_and_dead_letter(env):
    from platform_ext.services.worker import run_one
    from platform_ext.db.models import Job, TelemetryBatch
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    _post(env, d, dh, batch(env.cols), "key-r-00001")
    FakeAdapter.fail_times = 2
    for _ in range(3):
        run_one(env.sess._Session, env.settings, FakeAdapter(), "w")
    with env.sess.session_scope() as db:
        j = db.query(Job).one()
        assert j.status == "done" and j.attempts == 3
    _post(env, d, dh, batch(env.cols), "key-r-00002")
    FakeAdapter.fail_times = 99
    for _ in range(env.settings.job_max_attempts + 1):
        run_one(env.sess._Session, env.settings, FakeAdapter(), "w")
    with env.sess.session_scope() as db:
        assert db.query(Job).filter(Job.status == "failed").count() == 1
        assert db.query(TelemetryBatch).filter(TelemetryBatch.status == "failed").count() == 1


def test_alerts_persist_across_restart(env):
    from platform_ext.services.worker import run_one
    from platform_ext.db.session import init_engine
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    _post(env, d, dh, batch(env.cols), "key-p-00001")
    run_one(env.sess._Session, env.settings, FakeAdapter(), "w")
    env.sess.get_engine().dispose()
    init_engine(env.settings.database_url)                         # simulate process restart
    assert env.client.get("/api/v1/alerts", headers=h).json()["total"] == 1


def test_alert_workflow_and_filters(env):
    from platform_ext.services.worker import run_one
    _, h = register(env.client, "o@x.io")
    d, dh, _ = enroll(env.client, h)
    _post(env, d, dh, batch(env.cols), "key-f-00001")
    run_one(env.sess._Session, env.settings, FakeAdapter(), "w")
    aid = env.client.get("/api/v1/alerts?threat_level=high&attack_category=DoS/DDoS&limit=1&offset=0", headers=h).json()["items"][0]["alert_id"]
    assert env.client.get("/api/v1/alerts?threat_level=low", headers=h).json()["total"] == 0
    assert env.client.post(f"/api/v1/alerts/{aid}/acknowledge", headers=h).json()["investigation_status"] == "acknowledged"
    assert env.client.patch(f"/api/v1/alerts/{aid}/status", json={"status": "bogus"}, headers=h).status_code == 422
    assert env.client.patch(f"/api/v1/alerts/{aid}/status", json={"status": "investigating"}, headers=h).status_code == 200
    assert env.client.post(f"/api/v1/alerts/{aid}/notes", json={"body": "looks real"}, headers=h).status_code == 201
    assert len(env.client.get(f"/api/v1/alerts/{aid}/history", headers=h).json()["items"]) >= 3


# ---- websocket ----------------------------------------------------------------------------------------------------
def test_websocket_requires_valid_ticket(env):
    from starlette.websockets import WebSocketDisconnect
    _, h = register(env.client, "o@x.io")
    with pytest.raises(WebSocketDisconnect):
        with env.client.websocket_connect("/ws/v2/alerts?ticket=garbage"):
            pass
    access = h["Authorization"].split()[1]
    with pytest.raises(WebSocketDisconnect):                       # an access token is not a ws ticket
        with env.client.websocket_connect(f"/ws/v2/alerts?ticket={access}"):
            pass
    t = env.client.post("/api/v1/ws/ticket", headers=h).json()["ticket"]
    with env.client.websocket_connect(f"/ws/v2/alerts?ticket={t}") as ws:
        assert ws.receive_json()["event"] == "CONNECTED"


def test_websocket_rejects_other_orgs_device_filter(env):
    from starlette.websockets import WebSocketDisconnect
    _, h1 = register(env.client, "o1@x.io", org="A"); _, h2 = register(env.client, "o2@x.io", org="B")
    d, _, _ = enroll(env.client, h1)
    t = env.client.post("/api/v1/ws/ticket", headers=h2).json()["ticket"]
    with pytest.raises(WebSocketDisconnect):
        with env.client.websocket_connect(f"/ws/v2/alerts?ticket={t}&device_id={d['agent_id']}"):
            pass


def test_websocket_revoked_session_ticket_rejected(env):
    from starlette.websockets import WebSocketDisconnect
    _, h = register(env.client, "o@x.io")
    t = env.client.post("/api/v1/ws/ticket", headers=h).json()["ticket"]
    env.client.post("/api/v1/auth/logout", headers=h)
    with pytest.raises(WebSocketDisconnect):
        with env.client.websocket_connect(f"/ws/v2/alerts?ticket={t}"):
            pass


# ---- rate limiting / errors / headers -----------------------------------------------------------------------------
def test_login_rate_limit(env):
    from platform_ext.api import deps
    deps.limiter.__init__()
    env.settings.__dict__["login_rate_per_minute"] = 3
    codes = [env.client.post("/api/v1/auth/login", json={"email": "n@x.io", "password": "wrong-password-xx"}).status_code for _ in range(6)]
    assert 429 in codes


def test_error_format_and_security_headers(env):
    r = env.client.get("/api/v1/alerts")
    assert r.status_code == 401 and set(r.json()["error"]) >= {"code", "request_id"}
    assert r.headers["x-content-type-options"] == "nosniff" and "x-request-id" in r.headers
    r = env.client.post("/api/v1/auth/login", json={"email": "not-an-email"})
    assert r.status_code == 422 and "not-an-email" not in r.text


# ---- releases -----------------------------------------------------------------------------------------------------
def _promote(env, email):
    from platform_ext.db.models import User
    with env.sess.session_scope() as db:
        db.query(User).filter(User.email == email).update({"is_platform_admin": True})


def test_release_registration_verification_and_update_check(env):
    from platform_ext.releases import signing as S
    priv, pub = S.generate_keypair_b64()
    env.settings.release_trusted_keys["k1"] = pub
    _, h = register(env.client, "root@x.io"); _promote(env, "root@x.io")
    sha = S.sha256_bytes(b"binary")
    meta = {"version": "1.2.0", "channel": "stable", "os": "windows", "arch": "x86_64", "sha256": sha, "size": 6, "expires": "2099-01-01T00:00:00Z"}
    body = {"version": "1.2.0", "channel": "stable", "os_name": "windows", "cpu_arch": "x86_64", "artifact_name": "nb.exe", "artifact_size": 6,
            "sha256": sha, "key_id": "k1", "signature": S.sign_metadata(meta, priv), "signed_metadata": meta, "artifact_url": "https://dl.example/nb.exe"}
    assert env.client.post("/api/v1/releases", json=body, headers=h).status_code == 201
    assert env.client.post("/api/v1/releases", json=body, headers=h).status_code == 409                   # no re-register / rollback
    bad = {**body, "version": "1.3.0", "signature": S.sign_metadata({**meta, "sha256": "0" * 64}, priv)}
    assert env.client.post("/api/v1/releases", json=bad, headers=h).status_code == 422                    # signature mismatch
    _, h2 = register(env.client, "user@x.io")
    assert env.client.post("/api/v1/releases", json=body, headers=h2).status_code == 403                  # not platform admin
    d, dh, _ = enroll(env.client, h2)
    r = env.client.get("/api/v1/updates/check?current_version=1.0.0", headers=dh).json()
    assert r["update_available"] and r["release"]["version"] == "1.2.0" and r["download_token"]
    rid = r["release"]["release_id"]
    assert env.client.post(f"/api/v1/releases/{rid}/revoke", json={"reason": "bad build"}, headers=h).status_code == 200
    assert env.client.get("/api/v1/updates/check?current_version=1.0.0", headers=dh).json()["update_available"] is False
    env.client.put("/api/v1/releases/policy", json={"channel": "stable", "min_supported_version": "1.1.0"}, headers=h)
    assert env.client.get("/api/v1/updates/check?current_version=1.0.0", headers=dh).json()["update_required"] is True


# ---- migrations ---------------------------------------------------------------------------------------------------
def test_alembic_upgrade_downgrade(tmp_path):
    import os, subprocess, sys
    root = os.path.join(os.path.dirname(__file__), "..")
    envv = {**os.environ, "NB_DATABASE_URL": f"sqlite:///{tmp_path}/mig.db"}
    for args in (["upgrade", "head"], ["downgrade", "base"], ["upgrade", "head"]):
        r = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=root, env=envv, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
