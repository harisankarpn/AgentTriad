---
name: agent-triad-ops
description: >-
  Operational runbook, live GCP Cloud Run topology, Zero-Trust OIDC A2A specialist setup,
  15-minute JIT IAM impersonation rules, Scenario 1 (agent-triad sandbox to HSBC_Target)
  demo workflow, and refresh-bot Git/Cloud Run deployment procedures for AgentTriad.
  Use this skill whenever deploying or debugging Cloud Run services, ADK specialist agents,
  GCP IAM bindings, Scenario 1 demos, or pushing commits in AgentTriad.
---

# AgentTriad Live GCP & Operations Runbook

## 1. Live GCP Environment & Cloud Run Topology
- **GCP Project:** `agent-triad` (Project Number: `1041190629307`, Primary Region: `us-central1`, Scenario 1 Region: `europe-west2`)
- **Public Control Plane (`agent-triad-control-plane`):**
  - URL: `https://agent-triad-control-plane-qq3mp7ftqq-uc.a.run.app`
  - Runtime SA: `1041190629307-compute@developer.gserviceaccount.com` (Zero Standing Privilege for `setIamPolicy`)
  - Required Env Vars (always preserve on deploy): `GCP_PROJECT_ID=agent-triad`, `GCP_LOCATION=us-central1`, `DATABASE_AGENT_URL`, `INFRA_AGENT_URL`, `SECURITY_AGENT_URL`, `GOOGLE_OAUTH_CLIENT_ID`
- **3 Live Private Google ADK Specialist Services (`--no-allow-unauthenticated`, Zero-Trust OIDC A2A):**
  1. **Database Agent** (`agent-triad-db-agent`, source `agents/db_agent`):
     - URL: `https://agent-triad-db-agent-qq3mp7ftqq-uc.a.run.app`
     - SA: `aaas-database-agent-sa@agent-triad.iam.gserviceaccount.com` (`roles/cloudsql.viewer`, `roles/logging.viewer`, `roles/monitoring.viewer`, `roles/aiplatform.user`)
  2. **Infra Agent** (`agent-triad-infra-agent`, source `agents/infra_agent`):
     - URL: `https://agent-triad-infra-agent-qq3mp7ftqq-uc.a.run.app`
     - SA: `aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com` (`roles/compute.viewer`, `roles/logging.viewer`, `roles/monitoring.viewer`, `roles/aiplatform.user`)
  3. **Security Agent** (`agent-triad-security-agent`, source `agents/security_agent`):
     - URL: `https://agent-triad-security-agent-qq3mp7ftqq-uc.a.run.app`
     - SA: `aaas-security-agent-sa@agent-triad.iam.gserviceaccount.com` (`roles/iam.securityReviewer`, `roles/logging.viewer`, `roles/aiplatform.user`)
  - Invoker Policy: Grant `roles/run.invoker` on each specialist service strictly to `serviceAccount:1041190629307-compute@developer.gserviceaccount.com`.
- **Supporting Services:** `agent-triad-gke-assist` (deterministic remediation harness), `agent-triad-watcher` (telemetry & watchdog).
- **15-Minute JIT Execution Sandbox SA:** `sa-aaas-execution-sandbox@agent-triad.iam.gserviceaccount.com` (holds `roles/resourcemanager.projectIamAdmin`; impersonated via `iamcredentials.googleapis.com:generateAccessToken` only after human Stage 2 HITL `I Accept`).

## 2. Hard-Won GCP, Cloud Run & Google ADK Gotchas
1. **GCP IAM `serviceAccountTokenCreator` CEL Limitation:**
   - `iam.googleapis.com/ServiceAccount` does **not** support `resource.name` CEL conditions matching SA email addresses in project-level IAM bindings (causes silent `403` on `generateAccessToken` and fallback to `1041190629307-compute`, which then fails `setIamPolicy` with `403`).
   - Grant `roles/iam.serviceAccountTokenCreator` to `1041190629307-compute@developer.gserviceaccount.com` either directly on the `sa-aaas-execution-sandbox` SA resource (requires `iam.serviceAccounts.setIamPolicy`) or unconditionally at project level (`--condition=None`).
2. **Cloud Run GFE Reserves `/healthz`:**
   - Google Front End intercepts `GET /healthz` on `*.run.app` and returns `404`. Always smoke-test live Cloud Run revisions via `GET /` and `GET /api/state` (or `GET /.well-known/agent.json` with an OIDC Bearer token for private ADK services).
3. **Google ADK `LlmAgent` ThinkingConfig:**
   - Do not pass `thinking_config` inside `generate_content_config`; use `planner=BuiltInPlanner(thinking_config=types.ThinkingConfig(thinking_budget=0))`.
4. **Container Path Depth (`/app/agent.py`):**
   - Inside Cloud Run containers (`/app/agent.py`), `Path(__file__).resolve().parents` has length `2` (`['/app', '/']`). Always guard `parents[2]` checks with `if len(_HERE_PARENTS) > 2`.
5. **FastAPI/Pydantic Dynamic `importlib` Loading in Tests:**
   - When loading `agents/*/server.py` via `importlib.util.spec_from_file_location` in `poc/test_poc.py`, register `sys.modules[spec.name] = mod` **before** `spec.loader.exec_module(mod)` to avoid `PydanticUserError`.

## 3. Scenario 1 Repeatable Demo Workflow (`agent-triad` Sandbox → `HSBC_Target`)
- **Fault Subject:** Datastream Service Agent `service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com` missing `roles/compute.networkAdmin` on host project (`generic::FAILED_PRECONDITION` creating Datastream private connectivity in `europe-west2`).
- **UI Story (`Support Ticket` Modal):**
  - **Sandbox Preset (Default):** `Sandbox: agent-triad (1041190629307)` reproduces & validates live against real GCP `getIamPolicy`, Cloud Audit `SetIamPolicy` logs, and live 15m JIT `setIamPolicy`.
  - **Destination Preset:** `HSBC_Target Project` (`projects/HSBC_Target`) demonstrates promoting the sandbox-verified CLI remediation to the customer destination project (`SANDBOX_VALIDATED` dry-run).
- **1-Click Fault Re-Creation (Repeatable Demos):**
  - UI buttons (`#btnQuickRecreateScenario1` flask icon in header, `#btnRecreateScenario1Card` on resolved card, `#btnRecreateScenario1Modal` in ticket modal) call `POST /api/scenarios/datastream-iam-drift/recreate` (`{"execute_live": true}`).
  - Strips `roles/compute.networkAdmin` / `roles/datastream.serviceAgent` from `service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com` on `agent-triad` and writes a fresh `SetIamPolicy REMOVE` Cloud Audit Log.
  - Optional full Datastream API error generator script: `bash poc/scripts/trigger_datastream_iam_drift.sh`.

## 4. Verification, Git Push (`refresh-bot`) & Cloud Run Deploy Recipes

### Local Verification Gate (Mandatory Before Any Commit/Deploy)
```bash
node -e 'const fs=require("fs"),h=fs.readFileSync("poc/static/index.html","utf8");[...h.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi)].forEach(m=>new Function(m[1]));'
.venv/bin/python poc/test_poc.py
```

### Leak-Free Git Push via `refresh-bot` (Requires User `"go"` Confirmation)
```bash
git remote set-url origin https://github.com/harisankarpn/AgentTriad.git
source ~/.bashrc 2>/dev/null || true
TOKEN=$(.venv/bin/python get_token.py)
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${AUTH}" push origin main
unset TOKEN AUTH
```

### Control Plane Cloud Run Redeploy & Live Smoke Test (Requires User `"go"` Confirmation)
```bash
gcloud run deploy agent-triad-control-plane \
  --source=poc \
  --region=us-central1 \
  --project=agent-triad \
  --allow-unauthenticated \
  --quiet
# Smoke test via GET / and GET /api/state (never /healthz on *.run.app)
curl -fsS https://agent-triad-control-plane-qq3mp7ftqq-uc.a.run.app/ >/dev/null
curl -fsS https://agent-triad-control-plane-qq3mp7ftqq-uc.a.run.app/api/state | head -c 300
```
