# Backend Threat Model (initial)

Assets: org alerts/telemetry, device credentials, user sessions, release signing trust, model/feature contract integrity.
Trust boundaries: Internet <-> TLS proxy <-> API; API <-> PostgreSQL; API/worker <-> detection pipeline; agent <-> API (device credential); operator <-> signing keys (offline, outside this repo).

| Threat | Mitigation implemented | Residual / not done |
|---|---|---|
| Cross-tenant data access | every query filtered by `org_id` from the verified principal/device row; other-org IDs return 404; tests written | Postgres row-level security not added; tests not yet executed |
| Stolen refresh token | rotation + reuse detection revokes family | no device/IP binding |
| Credential stuffing | per-IP login limit, 5-fail lockout (15 min), generic errors, timing equalisation | in-process limiter only |
| Compromised/stolen device | revoke endpoint kills credential + status check on every request; rotation endpoint | no mTLS/attestation |
| Telemetry spoofing/misattribution | path id must equal authenticated device; org/device taken from DB not payload | -- |
| Replay / duplicate ingestion | idempotency key + payload hash, unique constraint | -- |
| Payload/PII collection creep | extra fields rejected; config flag forced false; features only | -- |
| Resource exhaustion | body limit, batch limit, per-user/device rate limits, WS connection cap, bounded pagination, job concurrency = worker count | no upstream WAF/DDoS protection; worker memory limits via container settings only |
| Malicious update | signed metadata, trusted key IDs, hash binding, expiry, revocation, monotonic versions | not full TUF; no threshold/root rotation; artifact hosting/serving not implemented |
| Secrets in repo | all secrets via env; compose requires them; `.env` git-ignored (verify in your repo) | secret manager integration not done |
| Info leakage via errors | uniform error format, no stack traces, validation errors don't echo input | -- |
| Dependency vulns | `pip-audit` step in CI | not yet run |
| Legacy unauthenticated routes | alerts/ws routes replaced; predict/stats gated by JWT | `/health` and `/` remain public; simulate removed by prefix match |

The service must not be exposed publicly without TLS termination, network controls and a completed security review. No penetration test has been performed.
