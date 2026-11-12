# Backend Platform Architecture (Role 7)

Status: first increment. See `ROLE7_IMPLEMENTATION_REPORT.md` for exactly what is implemented vs. tested vs. pending.

## Shape
```
Agent --(device credential)--> API /agents/*/telemetry/batches --> validate 77-feature contract
                                   | one DB transaction: batch + flows + job
                                   v
                              PostgreSQL  <--claim FOR UPDATE SKIP LOCKED--  Worker(s)
                                   ^                                           | DetectionAdapter -> existing Role 3/5/6 pipeline
                                   |                                           v  alerts (org-scoped, deduplicated)
Users (JWT) --> REST /api/v1/*  <---- alerts table ----polled by----> /ws/v2/alerts (ticket-authenticated, org-scoped)
```
Role 7 code lives in `src/backend/platform_ext/` and is attached to the unmodified Role 6 app by `install_platform(app)`.
`src/models/`, `src/xai/`, model artifacts and the feature contract are not touched.

## Technology choices and why
| Decision | Choice | Reason |
|---|---|---|
| Queue | PostgreSQL table + `FOR UPDATE SKIP LOCKED` | Already required for persistence; ingest batch + job are created in one atomic transaction (no lost/orphan jobs); no extra service to secure/operate. Trade-off: lower peak throughput than Redis. Revisit (Dramatiq/Redis) if load tests show queue contention. |
| Cross-process alert push | WS handler polls `alerts` (1 s) | Worker and API are separate processes; avoids a broker. Latency <= poll interval. LISTEN/NOTIFY or Redis pub/sub is the upgrade path. |
| Access tokens | HS256 JWT, 15 min, `sid` bound to a revocable server-side session | Revocation and role changes take effect immediately because sid/membership are re-read per request. RS256/JWKS is the upgrade path for external OIDC consumers. |
| Refresh tokens | Opaque, SHA-256 at rest, rotation + reuse detection (family revoke) | Stolen-token replay kills the family. |
| Passwords | argon2id (argon2-cffi), scrypt fallback | Established memory-hard algorithms. |
| Device auth | `<device_id>.<random secret>`, SHA-256 at rest, separate code path from user JWT | Secrets are 256-bit random so fast hashing is appropriate; user tokens cannot act as devices and vice versa. |
| Updates | Ed25519-signed metadata + SHA-256 + expiry + revocation + min-version + monotonic versions | TUF-*inspired* only. Not full TUF (no root/snapshot/timestamp chain, no thresholds). Adopt python-tuf before shipping real clients. |

## Invariants preserved
Observe-only (`action_enforced: NONE_OBSERVE_ONLY`), no payload collection (extra fields rejected; device config `collect_payloads` forced false),
frozen 77-feature contract read from `feature_columns.json` (never modified), Role 6 alert payload stored verbatim in `alerts.payload`.

## Known limits
In-process rate limiter (single replica); WS connection counters per process; `install_platform` removes legacy unauthenticated routes by path prefix
and has not been run against the real `app.py`; Alembic 0001 is a bootstrap migration; no TLS (terminate at the proxy).
