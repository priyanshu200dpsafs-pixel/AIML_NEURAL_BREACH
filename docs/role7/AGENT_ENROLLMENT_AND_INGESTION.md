# Agent Enrollment and Telemetry Ingestion

Error format (all endpoints): `{"error":{"code":"...","request_id":"...","detail":...}}`

## 1. Enrollment
1. Admin/Owner: `POST /api/v1/agents/enrollment-tokens` (JWT, `devices:manage`) -> `{"enrollment_token":"<shown once>","expires_at":...,"single_use":true}`
2. Agent: `POST /api/v1/agents/enroll` (no auth)
```json
{"enrollment_token":"...","hostname":"LAPTOP-01","os_name":"windows","os_version":"11","cpu_arch":"x86_64","client_version":"1.0.0"}
```
-> `201 {"agent_id":"<uuid>","org_id":"<uuid>","credential":"<agent_id>.<secret>"}`. The credential is returned once; store it in the OS secret store.
Token claim is an atomic conditional UPDATE, so concurrent use of one token yields exactly one device.

## 2. Device calls (header `Authorization: Bearer <credential>`)
| Endpoint | Purpose |
|---|---|
| `POST /api/v1/agents/heartbeat` `{"client_version","status_info"}` | updates last_seen; returns `config_version` |
| `GET /api/v1/agents/{agent_id}/config` | own config only |
| `POST /api/v1/agents/credential/rotate` | issues a new credential, old one dies immediately |
| `POST /api/v1/agents/{agent_id}/telemetry/batches` | ingest (path id must equal authenticated device) |
| `GET /api/v1/updates/check?current_version=&channel=` | update availability |

Revoked device: `403 device_revoked` on every call. Unknown/rotated credential: `401`.

## 3. Telemetry batch
Headers: `Idempotency-Key: <8-128 chars>` (required). Body:
```json
{"flows":[{"observed_at":"2026-11-09T10:00:00Z","features":{"<77 names from feature_columns.json>":1.0}}]}
```
Rules: top-level key `flows` only; each flow has only `observed_at` (ISO-8601 with timezone, within +-24h) and `features`; features must be exactly
the frozen contract names, numeric (no bool/str/NaN/Inf). Max flows `NB_MAX_BATCH_FLOWS` (500), max body `NB_MAX_REQUEST_BYTES`.
Responses: `202 {"batch_id","status":"accepted","flow_count","duplicate":false}`; same key + same body -> `202` with `duplicate:true` (no second job);
same key + different body -> `409`; invalid -> `422 schema_validation_failed` (batch recorded as `rejected`, payload not stored); too large -> `413`.
Retry guidance: reuse the same Idempotency-Key and body for network retries; use a new key for new data.
Note: the existing Role 6 pipeline imputes NaN/Inf; ingestion rejects them instead (stricter, deliberate). Confirm with the team.
