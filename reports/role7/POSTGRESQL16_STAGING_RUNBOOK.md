# Team Neural Breach — PostgreSQL 16 Staging Verification Runbook

**Document Role:** Senior Database Reliability Engineer & Release Engineer Runbook  
**Target Platform:** Neural Breach Platform Extension (Role 7)  
**Target Infrastructure:** Isolated PostgreSQL 16 Staging Database  
**Applicable Branch:** `integration/role7-remediation`  
**Safety Classification:** Strictly Observe-Only (`observe_only_mode: True`, `action_enforced: "NONE_OBSERVE_ONLY"`)

---

## 1. Overview & Operational Scope

This runbook defines the exact, reproducible operational procedures required to verify the Role 7 platform extension against a dedicated PostgreSQL 16 staging instance.

### Mandatory Operational Safety Rules
1. **Never Target Production:** Verify that the database name and hostname explicitly denote staging/testing. Never execute against production databases or with production credentials.
2. **PostgreSQL 16 Strictly Required:** Do not substitute PostgreSQL 14 or SQLite. If the server version reports anything less than PostgreSQL 16.0 (`server_version_num < 160000`), the verification must fail safely and immediately.
3. **Observe-Only Invariant:** Under no circumstances should active blocking, host quarantine, TCP reset, or firewall manipulation be enabled or executed.
4. **Preserve Shared Staging Data:** Do not issue `alembic downgrade base` or `DROP TABLE` against shared staging databases. All test assertions must use isolated test fixtures keyed by disposable UUIDs.
5. **No Secret Leakage:** Never print, commit, or log raw connection strings containing passwords or private signing keys.

---

## 2. Prerequisites & Driver Specifications

### 2.1 Driver & Dialect Format
The platform requires SQLAlchemy 2.0+ with **Psycopg 3** (binary package `psycopg[binary]>=3.2.0`).

- **Connection URL Format:**  
  `postgresql+psycopg://<username>:<password>@<host>:<port>/<database_name>`
- **Explicit Driver Specification:** Always specify `postgresql+psycopg://`. Do not use `postgresql+psycopg2://` (legacy Psycopg 2 is not installed or supported).
- **SSL / TLS Configuration:** For cloud-managed staging databases (AWS RDS, GCP Cloud SQL, Supabase, Neon), append SSL parameters if required:  
  `postgresql+psycopg://<user>:<password>@<host>:5432/<dbname>?sslmode=require`

### 2.2 Environment Variables
Ensure the following environment variables are set in the shell before beginning:

```bash
# 1. Target staging PostgreSQL 16 connection URL
export NB_DATABASE_URL="postgresql+psycopg://staging_user:staging_secret@staging-pg16.internal:5432/neural_breach_staging"

# 2. JWT Signing Secret (minimum 32 characters)
export NB_JWT_SECRET="staging-super-secret-jwt-key-minimum-32-chars-long!"

# 3. Feature columns contract definition path
export NB_FEATURE_COLUMNS_PATH="models/role3_retrain_v2/supervised/feature_columns.json"

# 4. Optional: Real detection adapter path
export NB_DETECTION_ADAPTER="src.backend.platform_ext.adapters.detection_adapter:create_detection_adapter"
```

---

## 3. Step-by-Step Staging Verification Procedure

```
+-------------------------------------------------------------------------------+
|                      PostgreSQL 16 Staging Verification                       |
+-------------------------------------------------------------------------------+
   |
   v
[Step 1: Version & Staging Guard] ----(Fail if < 16.0 or Prod)----> [ABORT]
   |
   v (Pass: Version >= 160000)
[Step 2: Alembic Upgrade Head] -------(Migration Error)-----------> [FAIL & LOG]
   |
   v (18 tables created)
[Step 3: Schema & DDL Audit] ---------(Missing Tables/Bad Types)--> [FAIL & LOG]
   |
   v (Schema Validated)
[Step 4: Concurrency & Reliability] --(Lock/Rollback Failure)-----> [FAIL & LOG]
   |  - FOR UPDATE SKIP LOCKED
   |  - Concurrent Dedup (.with_for_update)
   |  - Transaction Rollback & Dead-Letter
   v (All Scenarios Pass)
[Step 5: Disposable Resource Cleanup] (Preserves Shared Staging)
   |
   v
[Step 6: Publish Smoke Test Report] -> Authorizes Final Merge Review
```

### Step 3.1 — Server Version & Connectivity Check
Before applying migrations, verify connectivity and confirm the server is genuine PostgreSQL 16:

```bash
python3 -c "
import os, sys
from sqlalchemy import create_engine, text
url = os.environ['NB_DATABASE_URL']
engine = create_engine(url)
with engine.connect() as conn:
    version_str = conn.execute(text('SELECT version();')).scalar()
    num = conn.execute(text(\"SELECT current_setting('server_version_num')::int;\")).scalar()
    print(f'Server: {version_str}')
    print(f'Version Num: {num}')
    assert num >= 160000, f'ABORT: Target is not PostgreSQL 16 (server_version_num={num})'
print('Pre-flight version check PASSED.')
"
```
**Expected Output:**
- `Server: PostgreSQL 16.x ...`
- `Version Num: >= 160000`
- Exit Code: `0`

---

### Step 3.2 — Execute Alembic Migrations
Apply the initial migration schema ([alembic/versions/0001_initial.py](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/alembic/versions/0001_initial.py)):

```bash
alembic upgrade head
```

**Expected Result:**
- Alembic applies revision `0001` (Initial Role 7 schema).
- Command exits with code `0`.
- Standard SQL boolean defaults (`server_default=sa.text("true")` / `sa.text("false")`) execute cleanly without `psycopg.errors.DatatypeMismatch`.

---

### Step 3.3 — Schema & Constraint Verification
Verify that all 18 tables and required indexes exist on the staging database:

```bash
python3 -c "
import os
from sqlalchemy import create_engine, inspect
url = os.environ['NB_DATABASE_URL']
engine = create_engine(url)
inspector = inspect(engine)
tables = set(inspector.get_table_names())
expected = {
    'users', 'organizations', 'memberships', 'auth_sessions', 'devices',
    'device_credentials', 'device_configs', 'device_heartbeats', 'enrollment_tokens',
    'telemetry_batches', 'network_flows', 'jobs', 'alerts', 'alert_notes',
    'audit_log', 'model_versions', 'releases', 'release_policies', 'alembic_version'
}
missing = expected - tables
assert not missing, f'Missing tables in staging: {missing}'
print(f'All {len(expected)} tables verified on staging PostgreSQL 16.')
"
```

---

### Step 3.4 — Concurrency, Row-Locking & Failure Verification
Execute the automated staging verification script ([scripts/verify_postgres16_staging.py](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/scripts/verify_postgres16_staging.py)):

```bash
python3 scripts/verify_postgres16_staging.py --confirm-isolated-staging
```

**What this executes:**
1. **Target & Version Guard:** Verifies `server_version_num >= 160000` and validates non-production naming.
2. **`FOR UPDATE SKIP LOCKED` Worker Test:** Dispatches 12 queued jobs across 4 concurrent worker threads. Verifies that all 12 jobs complete with zero double-processing and zero deadlocks.
3. **Alert Deduplication Under Contention:** Executes 6 concurrent threads inserting duplicate detections for the same flow signature. Verifies that `.with_for_update()` row-locking eliminates lost updates and increments `repeat_count` to exactly 7.
4. **Transaction Rollback & Dead-Letter:** Injects an ML inference failure. Verifies that the worker rolls back the transaction, records the failure, and dead-letters after reaching `max_attempts`.
5. **Observe-Only Verification:** Confirms alerts have `observe_only_mode: True` and `action_enforced: "NONE_OBSERVE_ONLY"`.
6. **Isolated Cleanup:** Deletes only the disposable test organization by UUID (cascading across foreign keys), preserving all pre-existing staging data.

**Expected Output:**
```
================ VERIFICATION SUMMARY ================
Status:             ALL_CHECKS_PASSED
Target:             postgresql+psycopg://staging_user:***@staging-pg16:5432/neural_breach_staging
PostgreSQL Version: PostgreSQL 16.x ...
All concurrency, locking, and rollback checks passed on PostgreSQL 16.
```
- Exit Code: `0`

---

## 4. Failure Modes & Incident Troubleshooting

| Symptom / Error | Root Cause | Remediation Procedure |
|---|---|---|
| `VERSION CHECK FAILED (server_version_num < 160000)` | Target database is PostgreSQL 14 or 15. | Stop immediately. Provision genuine PostgreSQL 16 instance. Never bypass this check. |
| `SAFETY ABORT: Matches production naming patterns` | Database name or host contains `prod` or `production`. | Verify staging URL. If staging is misnamed, migrate to a dedicated staging cluster. |
| `psycopg.OperationalError: connection refused` | Database host is unreachable or port 5432 is blocked. | Verify security groups, VPC peering, and PostgreSQL `pg_hba.conf` allow connection. |
| `psycopg.errors.DatatypeMismatch: column "is_active" ...` | Outdated migration script using integer defaults. | Verify branch contains commit `31d6f4e` (`server_default=sa.text("true")`). |
| `AssertionError: Expected repeat_count 7, got 3` | Lost-update race condition during concurrent upsert. | Verify `src/backend/platform_ext/services/alert_service.py` contains `.with_for_update()`. |
| `AssertionError: Missing tables` | Alembic migration did not run or ran against wrong DB. | Re-run `alembic upgrade head` and verify target schema. |

---

## 5. Evidence Collection & Sanitized Audit Reporting

To update the official audit report without exposing database passwords or private keys:

1. **Capture Sanitized Output:**
   Run the verification and pipe to a log file:
   ```bash
   python3 scripts/verify_postgres16_staging.py --confirm-isolated-staging > /tmp/pg16_staging_run.log 2>&1
   ```
2. **Inspect for Secrets:**
   Ensure password strings are masked (`***`).
3. **Record Verified Metadata:**
   - Server version string (e.g., `PostgreSQL 16.2 on x86_64-pc-linux-gnu`).
   - Alembic head revision (`0001`).
   - Test execution duration and exit code (`0`).
4. **Update Audit Record:**
   Record findings in `reports/role7/POSTGRESQL16_STAGING_SMOKE_TEST.md`.

---

## 6. Staging Unblocking Checklist for Authorized Engineers

To unblock the final merge review for Role 7:

- [ ] **Provision Isolated PostgreSQL 16 Instance:** Ensure PostgreSQL 16.x is running and accessible from the deployment environment.
- [ ] **Export `NB_DATABASE_URL`:** Configure non-production credentials using `postgresql+psycopg://`.
- [ ] **Run Pre-Flight Version Check:** Confirm server reports version 16.x (`server_version_num >= 160000`).
- [ ] **Run Alembic Migration:** Execute `alembic upgrade head` (exit code `0`).
- [ ] **Run Staging Concurrency Suite:** Execute `python3 scripts/verify_postgres16_staging.py --confirm-isolated-staging` (exit code `0`).
- [ ] **Record Results:** Update [reports/role7/POSTGRESQL16_STAGING_SMOKE_TEST.md](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/role7/POSTGRESQL16_STAGING_SMOKE_TEST.md) with sanitized execution output and update verdict to `READY FOR MERGE REVIEW`.
- [ ] **Request Merge Review:** Notify team lead to execute fast-forward merge into `main`.

