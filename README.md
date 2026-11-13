# Agent-Triad: Autonomous Cloud Operations (AaaS)

Agent-Triad is an autonomous, outcome-driven cloud support and operations platform built on the **Google Cloud Agent as a Service (AaaS)** architecture. Built using the **Agent Development Kit (ADK)** and the **Agent2Agent (A2A) protocol** on Vertex AI, it transforms traditional reactive SRE into a closed-loop perception-reasoning-action-validation framework with deterministic guardrails, **Google Identity Services (OAuth 2.0 / IAP) SSO**, **Cloud Firestore multi-session persistence**, and Human-in-the-Loop (HITL) authorization.

---

## High-Level Executive Summary

**AgentTriad (AaaS Control Plane)** provides an autonomous, zero-trust Google Cloud operations co-pilot (**Atlas**) that continuously observes live GCP telemetry, diagnoses root causes using live **Google ADK (`google-adk`)** specialist microservices on **Cloud Run**, persists per-user operational sessions in **Cloud Firestore**, and executes human-approved remediations with built-in safety guardrails and automatic rollback protection.

### Key Executive Highlights
* **3-Stage Autonomous Triad Architecture**:
  1. **Step 1 — Observe (`Heartbeat & Telemetry`)**: Continuously polls and SAIF-sanitizes live Google Cloud Logging entries (`resource.type="cloudsql_database"`, `cloud-sql-proxy`, `gce_instance`, `cloud_run_revision`, `cloud_function`, `aiplatform.googleapis.com/ReasoningEngine`), suppresses routine GKE Composer / `GCEGuestAgent` / `ops-agent-health` noise at the edge, prioritizes newly occurring anomalies by newest timestamp, and streams 15-second health heartbeats.
  2. **Step 2 — Reason & Gate (`Atlas • AaaS Lead Orchestrator`)**: Single authorizing **Vertex AI Gemini (`gemini-2.5-flash` default via `AAAS_GEMINI_MODEL`)** root orchestrator that correlates anomalies against Golden Remediation Playbooks (RAG), delegates deep domain diagnostics over **JSON-RPC 2.0 A2A** to live Cloud Run ADK Specialist Agents, and gates all changes behind **Human-in-the-Loop (`I accept`)** approval tied to the authenticated Google SSO user.
  3. **Step 3 — Remediate (`7-Agent Specialist Roster`)**: Combines live **Google ADK Cloud Run Specialist Agents** (**Database Agent** & **Infra Agent**) with 5 deterministic domain execution harnesses (**Serverless**, **Networking**, **Data Analytics**, **Security**, and **Billing**) operating under **Zero-Standing Privilege** (`$0` extra LLM token cost during execution).
* **All 4 Cloud Operations Scenarios Supported**:
  * **Scenario 1 (1-Line CLI / API Fix)**: Rapid root-cause analysis and single-command `gcloud` / API remediation.
  * **Scenario 2 (Multi-Service Terraform Fix)**: Coordinated cross-domain remediation (e.g., IAM + VPC Firewall + Cloud SQL) via a pre-validated **Terraform (`.tf`)** bundle.
  * **Scenario 3 (Terraform Stack Generator)**: On-demand generation, dry-run validation, and harnessed execution of production-ready **Terraform (`.tf`)** stacks from natural language chat.
  * **Scenario 4 (GCP How-To & Advisory)**: Instant architectural and operational guidance with `$0` sandbox overhead.
* **Enterprise Identity & Cloud Firestore Multi-Session Workspace**:
  * **Google Identity Services (OAuth 2.0) & IAP SSO**: Real Google Workspace sign-in with cryptographic ID Token JWT / OAuth2 UserInfo verification, GCP IAP header auto-detection, and dynamic user identity propagation across Atlas conversations, HITL approvals, and the Audit & Event Tracker.
  * **Cloud Firestore Chat History**: Persists up to **25 chat sessions per signed-in user** in Cloud Firestore (`aaas_user_sessions`) with instant session switching, auto-generated titles, reset/delete/clear-all controls, and local JSON fallback caching.
  * **Google Visual Identity (Material 3) Command Center**: Official 4-color Google palette (`#4285F4`, `#EA4335`, `#FBBC04`, `#34A853`), Left Sidebar Navigation Rail (`Command Center`, `Specialist Roster`, `Audit & Events`, `View Logs & A2A`), and **Auto / Dark / Light** theme switcher.
* **4-Layer Safety Guardrails**:
  * **Pre-Flight Safety Check (OPA Policy Gate)**: Blocks destructive commands (`delete`, `drop`, `destroy`) and strictly protects external/shared teammate services (such as `testdbconnect` in `us-west1`).
  * **10-Minute Resource Lease (`.tflock`)**: Prevents concurrent or conflicting modifications to the same cloud resource.
  * **15-Minute Single-Use WIF JIT Token**: Specialists have **read-only** standing permissions; mutations require an ephemeral token (`jit-wif-*`) minted only when the operator clicks **`I accept`**.
  * **Two-Stage Post-Fix Verification & Bifurcated Rollback (`45s` Liveness + `3m` Metrics)**: Pairs a **45-second direct Control-Plane API liveness probe** (with strict `timestamp > execution_completed_at` filtering to ignore delayed pre-fix logs) with a **3-minute (180s) Cloud Monitoring stabilization window** and **45-minute anti-flapping hysteresis freeze**. Stateless workloads (`Cloud Run`/`GKE`) auto-revert on regression, while stateful workloads (`Cloud SQL`/Disks) enforce **Stateful Safe-Mode Isolation** (`deletion_protection = true`, `prevent_destroy = true`).

---

## Live Production Deployment & Service Topology (`agent-triad`)

### 1. How the Platform Is Deployed
The entire stack is provisioned reproducibly in Google Cloud project **`agent-triad`** (`us-central1`) using **Terraform (`>= 1.5`)** in [`terraform/main.tf`](./terraform/main.tf):
1. **Container Build & Registry**: Source code changes in `agents/database_agent/`, `agents/infra_agent/`, and `poc/` are automatically hashed (`filesha256`), built via **Google Cloud Build** (`gcloud builds submit`), and pushed to **Artifact Registry** (`us-central1-docker.pkg.dev/agent-triad/agent-triad-repo/...`).
2. **Serverless Microservices on Cloud Run v2**: Deployed as independent, scale-to-zero (`min_instance_count = 0`, `max_instance_count = 3`, `cpu_idle = true`) Cloud Run v2 services with pre-compiled Python bytecode (`python -m compileall`) for fast cold-start responsiveness and `$0` idle compute cost.
3. **1-Command Deployment**:
   ```bash
   cd terraform
   GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" ../.venv/bin/terraform apply -auto-approve
   ```

### 2. List of Deployed Cloud Services & Monitored Resources

| Service / Resource | Type | Region / Zone | Live Endpoint / Identifier | Architectural Role |
| :--- | :--- | :--- | :--- | :--- |
| **`agent-triad-control-plane`** | Cloud Run v2 Service | `us-central1` | `https://agent-triad-control-plane-1041190629307.us-central1.run.app` | **AaaS Command Center UI + Atlas Root Orchestrator** (`poc/app.py`, `poc/agents/lead_orchestrator.py`) |
| **`agent-triad-db-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-db-agent-1041190629307.us-central1.run.app` | **Live Google ADK Database Specialist Agent** (`agents/database_agent/agent.py`) for Cloud SQL & `cloud-sql-proxy` diagnostics |
| **`agent-triad-infra-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-infra-agent-1041190629307.us-central1.run.app` | **Live Google ADK Infra Specialist Agent** (`agents/infra_agent/agent.py`) for Compute Engine, GKE & Terraform |
| **Cloud Firestore `(default)`** | Cloud Firestore Database | `agent-triad` | `projects/agent-triad/databases/(default)` (`aaas_user_sessions`) | **Per-User Multi-Session Chat Persistence** (`poc/services/session_store_service.py`) storing up to 25 Atlas sessions per Google SSO user |
| **`testdbinstance1`** | Cloud SQL (`POSTGRES_18`) | `us-central1-f` | `agent-triad:us-central1:testdbinstance1` | Live Enterprise Plus (`db-perf-optimized-N-2`) PostgreSQL instance inspected by the ADK Database Agent |
| **`testinstance1` & Workstations VM** | Compute Engine VMs | `us-west1-b` / `us-central1-c` | `2276555501399631720` (`e2-medium`) / `workstations-...` (`e2-standard-4`) | Live Compute Engine instances inspected by the ADK Infra Agent |
| **`testdbconnect`** | Cloud Run Service (Protected) | `us-west1` | `testdbconnect` | Teammate service protected by the Agent Harness read-only external-resource guardrail |

### 3. How Services Connect & Communicate (Zero-Trust A2A Protocol)
All inter-agent communication follows the **A2A 1.0 JSON-RPC 2.0 specification** over HTTPS with **OIDC Service-to-Service Authentication**:
1. **Agent Discovery (`GET /.well-known/agent.json`)**: Every specialist exposes a machine-readable `AgentCard` declaring its capabilities, `ZeroStandingPrivilege: true` posture, and skills (`diagnose_database_anomaly`, `diagnose_infra_anomaly`).
2. **Zero-Trust OIDC Handshake**: Because GCP Organization Policy (`iam.allowedPolicyMemberDomains`) blocks public `allUsers` ingress, **Atlas** (`agent-triad-control-plane`) mints a Google-signed **OIDC Identity Token** targeting the specialist's Cloud Run URI (`DATABASE_AGENT_URL` or `INFRA_AGENT_URL`) and sends it in `Authorization: Bearer <OIDC_ID_TOKEN>`.
3. **JSON-RPC 2.0 Task Dispatch (`POST /a2a`)**:
   * When **Poll Live Logs** detects a `cloudsql_database`, `cloud-sql-proxy`, or `gce_instance` error—or when the user asks a question in **Chat with Atlas**—Atlas sends a `tasks/send` JSON-RPC 2.0 payload to `agent-triad-db-agent/a2a` or `agent-triad-infra-agent/a2a`.
   * The specialist executes its **Google ADK `Runner`** loop (`google.adk.runners.Runner`), invokes its live read-only GCP tools, and returns both the structured GCP API telemetry (`instance_inspection`, `performance_metrics`, `log_analysis`, `runtime_identity`, `remediation_proposal`) and the synthesized report back to Atlas.

### 4. How GCP APIs & ADK Tools Are Invoked (Out-of-Band Control Plane Telemetry)
Crucially, the ADK Specialist Agents **never open direct database socket connections (port `5432`) or direct SSH sessions into VMs** during read-only triage. Instead, they fetch short-lived OAuth2 access tokens from the **Cloud Run Metadata Server** (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`) and query official Google Cloud Control Plane REST APIs:

| ADK Specialist Agent | ADK Tool Function | Live GCP API Invoked | Telemetry & State Retrieved |
| :--- | :--- | :--- | :--- |
| **Database Agent** (`agent-triad-db-agent`) | `inspect_cloudsql_instance` | `sqladmin.googleapis.com/v1/projects/agent-triad/instances/{instance}` | Live `state` (`RUNNABLE`/`STOPPED`), `activationPolicy` (`ALWAYS`/`NEVER`), `databaseVersion` (`POSTGRES_18`), tier, HA, SSL mode, backups |
| **Database Agent** (`agent-triad-db-agent`) | `get_cloudsql_performance_metrics` | `monitoring.googleapis.com/v3/projects/agent-triad/timeSeries` | Live `cloudsql.googleapis.com/database/cpu/utilization`, `memory/utilization`, `disk/utilization`, `postgresql/num_backends`, `network/connections` |
| **Database Agent** (`agent-triad-db-agent`) | `analyze_db_logs_and_connections` | `logging.googleapis.com/v2/entries:list` | Live `resource.type="cloudsql_database"` and `logName:"cloud-sql-proxy"` entries (classifying `direct_ip_or_proxy_connection_timeouts`, SSL rejections, auth failures, pool exhaustion, and shutdowns) |
| **Infra Agent** (`agent-triad-infra-agent`) | `inspect_compute_instances` | `compute.googleapis.com/compute/v1/projects/agent-triad/aggregated/instances` | Discovers all VMs across all zones (`instance_id`, `machineType`, `status`, disks, IPs) and flags terminated ephemeral VM IDs |
| **Infra Agent** (`agent-triad-infra-agent`) | `get_compute_performance_metrics` | `monitoring.googleapis.com/v3/projects/agent-triad/timeSeries` | Live `compute.googleapis.com/instance/cpu/utilization`, `uptime`, `network/received_bytes_count`, `sent_bytes_count`, `disk/read_bytes_count` |
| **Infra Agent** (`agent-triad-infra-agent`) | `analyze_infra_logs` | `logging.googleapis.com/v2/entries:list` | Live `resource.type="gce_instance"` Guest Agent metadata watcher errors (`context canceled`), manifest warnings & gRPC stream logs |
| **Both ADK Agents** | `inspect_agent_runtime_identity` / `inspect_infra_agent_runtime_identity` | `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/` | Live introspection of the active Cloud Run Service Account email, OAuth scopes, and read-only IAM role bindings |
| **Both ADK Agents** | `generate_remediation_proposal` / `generate_infra_remediation_proposal` | Read-only deterministic synthesis | Generates safe `gcloud` CLI remediations and `deletion_protection = true` / `prevent_destroy = true` Terraform HCL proposals |

### 5. IAM Service Accounts & Least-Privilege Permissions Matrix
AgentTriad enforces **Zero-Standing Privilege** across all deployed identities managed in [`terraform/main.tf`](./terraform/main.tf):

| Identity / Service Account | Attached Service | Assigned GCP IAM Roles | Security & Access Scope |
| :--- | :--- | :--- | :--- |
| **`aaas-database-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-db-agent` | `roles/cloudsql.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Cloud SQL metadata, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **`aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-infra-agent` | `roles/compute.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Compute Engine VM/disk inventory, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **Control Plane Runtime SA** (`1041190629307-compute@developer.gserviceaccount.com`) | `agent-triad-control-plane` | `roles/run.invoker` *(on `agent-triad-db-agent` & `agent-triad-infra-agent`)*<br>Cloud Logging, Monitoring, Firestore (`aaas_user_sessions`), Run, SQL & Compute API access | Authorizes Atlas to invoke specialist Cloud Run endpoints via OIDC tokens, persist per-user chat sessions in Cloud Firestore, and execute human-approved remediations only after minting a 15-minute JIT token. |

### 6. Production Resilience & Enterprise Architecture Guarantees
To prevent common autonomous SRE failure modes in production, the Agent Harness ([`poc/services/agent_harness.py`](./poc/services/agent_harness.py)) and ADK Specialist Agents enforce four additional architectural guarantees:

1. **Two-Stage Post-Fix Verification Window (Accounting for GCP Metric Ingestion Latency)**:
   * Because Google Cloud Monitoring (`monitoring.googleapis.com/v3`) time-series pipelines can take 60–180 seconds to aggregate, a single 45-second check could miss delayed metric spikes or react to pre-fix log entries.
   * AgentTriad therefore uses a **3-Stage Verification Pipeline**:
     * **Stage 1 (`45s` Direct API Liveness + Timestamp Guard)**: Immediately polls the live GCP Control Plane REST API (`sqladmin`, `compute`, `run`) and filters Cloud Logging strictly to `timestamp > execution_completed_at` so delayed pre-fix logs are never mistaken for post-fix regressions.
     * **Stage 2 (`180s` / `3-Minute` Cloud Monitoring Stabilization Window)**: Evaluates aggregated CPU, memory, and connection time-series across a full 3-minute window.
     * **Stage 3 (`45-Minute` Temporal Hysteresis Freeze)**: Applies a 45-minute cooldown (`temporal_hysteresis_freezes`) per workload to prevent oscillation/flapping.
2. **Bifurcated Rollback Engine (Stateless Auto-Rollback vs. Stateful Safe-Mode Isolation)**:
   * **Stateless Workloads (`STATELESS_CANARY_ROLLBACK`)**: Cloud Run revisions, GKE deployments, and VM guest metadata support atomic rollback to the prior healthy revision/state.
   * **Stateful Workloads (`STATEFUL_SAFE_MODE_ISOLATION`)**: Automated destructive rollbacks are **strictly forbidden** on stateful resources (`Cloud SQL`, `AlloyDB`, `Spanner`, Persistent Disks). All generated Terraform HCL in [`agents/database_agent/agent.py`](./agents/database_agent/agent.py) enforces `deletion_protection = true` and `lifecycle { prevent_destroy = true }`, and [`validate_terraform_dry_run()`](./poc/services/agent_harness.py) rejects (`FAILED`) any HCL with `deletion_protection = false` or `force_destroy = true`.
3. **Zero-SPOF Degraded Mode (`$0` LLM Deterministic Fallback & Direct Specialist Endpoints)**:
   * If the regional Vertex AI Gemini endpoint (`us-central1`) experiences quota exhaustion (`429`) or an outage, `Atlas`, `agent-triad-db-agent`, and `agent-triad-infra-agent` automatically bypass the LLM and execute their **deterministic GCP REST API tools and Golden Playbooks at `0` LLM tokens**.
   * Furthermore, each specialist microservice exposes an independent `POST /diagnose` endpoint so Cloud Monitoring webhooks or SREs can invoke domain diagnostics directly even if `agent-triad-control-plane` is unreachable.
4. **Hub-and-Spoke Multi-Project & Shared VPC / VPC-SC Readiness**:
   * While deployed in a single project (`agent-triad`) for this reference implementation, every ADK tool function (`inspect_cloudsql_instance`, `inspect_compute_instances`, `get_cloudsql_performance_metrics`, `get_compute_performance_metrics`, `analyze_db_logs_and_connections`, `analyze_infra_logs`) accepts a dynamic `project_id` parameter.
   * In a multi-project enterprise **Hub-and-Spoke** topology, the Cloud Run ADK agents reside in the central **AaaS Hub Project** and inspect **Spoke Projects** via cross-project read-only IAM bindings (`roles/cloudsql.viewer`, `roles/compute.viewer`, `roles/monitoring.viewer`, `roles/logging.viewer`), Aggregated Organization Log Sinks, and VPC Service Controls (VPC-SC) ingress/egress rules.

---

## AaaS Command Center UI, Google SSO & Multi-Session History

Recent releases expanded the Control Plane ([`poc/app.py`](./poc/app.py), [`poc/static/index.html`](./poc/static/index.html), [`poc/services/session_store_service.py`](./poc/services/session_store_service.py), [`poc/services/cloud_logging_service.py`](./poc/services/cloud_logging_service.py)) into a full multi-user operational workspace:

### 1. Google Identity Services (OAuth 2.0) & GCP IAP Authentication
* **Real Google SSO Modal**: Uses Google Identity Services (`accounts.google.com/gsi/client`) in Material 3 Google Workspace styling with an On-Call Role option (`Cloud SRE Lead` / `sre-lead@google.com`) and runtime OAuth 2.0 Web Client ID configuration (`GOOGLE_OAUTH_CLIENT_ID` or `POST /api/auth/config`).
* **3-Tier Backend Identity Verification (`GET /api/auth/me`, `POST /api/auth/google`)**:
  1. **Google Cloud IAP Auto-Detection**: Reads `X-Goog-Authenticated-User-Email` automatically when deployed behind IAP (`gcp-iap`).
  2. **OAuth 2.0 Access Token Verification**: Validates live access tokens against `https://www.googleapis.com/oauth2/v3/userinfo` (`google-oauth2-verified`).
  3. **Cryptographic ID Token (JWT) Verification**: Verifies Google ID tokens via `google.oauth2.id_token.verify_oauth2_token` (`google-id-token-verified`), rejecting forged or invalid credentials with HTTP `401`.
* **End-to-End Dynamic Identity Propagation**: The active authenticated user dynamically personalizes Atlas greetings, labels HITL approvals (`approved_by`), populates the immutable **Audit & Event Tracker**, tags Terraform deployments, and scopes Cloud Firestore chat history.

### 2. Cloud Firestore Multi-Session Chat Manager
* **Durable Per-User Persistence**: [`poc/services/session_store_service.py`](./poc/services/session_store_service.py) stores up to **25 conversation threads per Google SSO user** in Cloud Firestore (`projects/agent-triad/databases/(default)`, collection `aaas_user_sessions/{user_key}`), backed by an in-memory and local JSON cache (`/tmp/aaas_firestore_sessions_cache.json`) for sub-millisecond reads and offline/test resilience.
* **Full Session Lifecycle Controls**: Users can start a **New Session**, browse and switch between saved conversations in the expandable **History** drawer (with auto-derived titles, message counts, and last consulted specialist), **Reset** the active thread, delete individual sessions, or **Clear All** sessions.

### 3. Google Visual Identity UI & Theme Controls
* **Material 3 4-Color Design System**: Uses the official Google Visual Identity palette (`#4285F4` Blue, `#EA4335` Red, `#FBBC04` Yellow, `#34A853` Green), `Google Sans` typography, custom **Atlas Holding GCP Cloud** SVG branding, and streamlined `Gemini latest` / `A2A v1.0` chrome.
* **Left Sidebar Navigation Rail (4 Dedicated Views)**:
  1. **AaaS Command Center**: Compact 4-Metric Status Strip (`GCP Discovery: 5 APIs Live`, `Cloud Run ADK: 2 Agents Online`, `Safety Policy: Guardrails Active`, `Post-Fix Verify: 45s + 3m Watchdog`), action-first Center Stage (Incident Approval & Atlas Chat), and collapsible `How It Works (Step 1–3)` and `Key Features` drawers.
  2. **Specialist Roster**: Live status of all 7 domain specialists (2 live Cloud Run ADK agents + 5 deterministic execution harnesses).
  3. **Audit & Events**: Chronological tracker of detected anomalies, assigned specialists, approving users, timestamps, and `jit-wif-*` token IDs.
  4. **View Logs & A2A**: Live GCP Cloud Logging stream paired with the real-time A2A JSON-RPC 2.0 message ledger.
* **Auto / Dark / Light Theme Switcher**: Icon-only segmented control supporting system preference (`prefers-color-scheme: dark`), Dark mode, and Light mode.

### 4. Enhanced Live Cloud Logging Triage & Edge Noise Filtering
* **`cloud-sql-proxy` Error Capture**: Both [`poc/services/cloud_logging_service.py`](./poc/services/cloud_logging_service.py) and `analyze_db_logs_and_connections` in [`agents/database_agent/agent.py`](./agents/database_agent/agent.py) capture `logName:"cloud-sql-proxy"` connectivity failures (`CLOUDSQL_PROXY_CONNECTION_TIMEOUT`, `Connection Refused`, `timeout expired`, `Re-occured`, port `3306` / direct-IP timeouts) alongside `cloudsql_database` `FATAL`/`ERROR` logs.
* **Edge Noise Suppression & Deduplication**: Suppresses routine GKE Composer noise, `GCEGuestAgent`, `ops-agent-health`, `LogPingOpsAgent`, unauthenticated probe noise, library deprecation warnings, and internal `AAAS_AUDIT_EVENT` loops at `$0` LLM cost while deduplicating burst stack traces by `signature_key`.
* **Newest-First Anomaly Prioritization**: `POST /api/poll-cloud-logging` sorts live GCP anomalies by **newest timestamp descending** (with Cloud SQL priority tie-breaking) so freshly occurring incidents surface immediately.

---

## 1. System Architecture

The architecture enforces a strict decoupling between the **Central SaaS Control Plane** (multi-tenant orchestration, model inference, and customer dashboard) and the **Customer Data Plane** (localized telemetry ingestion and isolated execution endpoints).

```text
+---------------------------------------------------------------------------------------------------------------+
|                                      GCP CENTRAL SAAS CONTROL PLANE                                           |
|                                                                                                               |
|   +---------------------------------------+       2. REASONING (A2A Protocol)      +----------------------+   |
|   |       Multi-Tenant UI Dashboard       |<-------------------------------------->|  ADK Multi-Agent     |   |
|   |  * Google SSO (OAuth 2.0 / IAP)       |                                        |  Core (Triad)        |   |
|   |  * Cloud Firestore Multi-Sessions     |         3. HITL APPROVAL               |  * Frontline Watcher |   |
|   |  * Incident Triage & RCA / Chat       |--------------------------------------->|  * Atlas Orchestrator|   |
|   |  * HITL Gate (Scope & JIT Minting)    |                                        |  * Specialist Roster |   |
|   +---------------------------------------+                                        +----------+-----------+   |
|                                                                                               |               |
|                                                                                    4. CONTROLLED EXECUTION    |
|                                                                                    (OIDC via WIF + JIT Token) |
+-----------------------------------------------------------------------------------------------|---------------+
                                                ^                                               |
                                                | 1. INGESTION & DETECTION                      |
+-----------------------------------------------|-----------------------------------------------|---------------+
|                                               |                                               v               |
|   +---------------------------------------+   |                                    +----------------------+   |
|   |        Telemetry & Observation        |---+                                    |   Remediation Layer  |   |
|   |  * Cloud Logging Sinks (Edge Filter)  |                                        |  * Cloud Run Webhook |   |
|   |  * Cloud Monitoring Alerting          |                                        |  * OPA / Sanitizer   |   |
|   |  * Read-Only Service Account          |                                        |  * Ephemeral JIT SA  |   |
|   +---------------------------------------+                                        +----------+-----------+   |
|                       ^                                                                       |               |
|                       |                                                                       |               |
|                       +-------------------- 5. POST-VERIFICATION (Loop) ----------------------+               |
|                                                                                                               |
|   +-------------------------------------------------------------------------------------------------------+   |
|   |                   GCP Resources (GKE / Compute Engine / Cloud SQL / Cloud Storage)                    |   |
|   +-------------------------------------------------------------------------------------------------------+   |
|                                         CUSTOMER GCP DATA PLANE (TENANT)                                      |
+---------------------------------------------------------------------------------------------------------------+
```

---

## 2. The Agent Triad Lifecycle

```text
System Incident Occurs
│
▼
INGESTION & DETECTION
Heartbeat & Telemetry streams Cloud Logging (including cloud-sql-proxy) with SAIF sanitization & edge noise filtering.
│
▼
REASONING & RCA
Atlas correlates logs with Golden Playbooks (RAG) & delegates deep read-only triage over A2A to live ADK Specialist Agents.
│
▼
HUMAN-IN-THE-LOOP APPROVAL
AaaS Command Center authenticates the operator via Google SSO/IAP and gates execution behind "I accept" + a 15-min WIF JIT token.
│
▼
CONTROLLED EXECUTION
Agent Harness enforces OPA policy checks, 10-min .tflock leases, Terraform dry-run validation, and deterministic specialist execution.
│
▼
STABILIZATION & POST-VERIFICATION
Two-stage verification runs a 45s direct API liveness probe + 3-minute Cloud Monitoring window + 45-minute hysteresis freeze,
with Stateless Canary Auto-Rollback or Stateful Safe-Mode Isolation.
```

---

## 3. Control Plane REST & A2A API Reference

All Control Plane endpoints are served by [`poc/app.py`](./poc/app.py):

| Category | Endpoint | Description |
| :--- | :--- | :--- |
| **Authentication (SSO / IAP)** | `GET /api/auth/me`<br>`POST /api/auth/google`<br>`POST /api/auth/config`<br>`POST /api/auth/logout` | Detects GCP IAP headers, verifies Google OAuth 2.0 access tokens / ID token JWTs (`401` on invalid tokens), sets runtime OAuth Client ID, and manages sign-out. |
| **Telemetry & State** | `GET /api/state`<br>`POST /api/poll-cloud-logging`<br>`GET /api/harness/status`<br>`GET /api/audit-events` | Returns live triad state, polls newest-first real GCP Cloud Logging anomalies, reports Agent Harness guardrails, and lists immutable audit trail records. |
| **Incident Triage & HITL** | `POST /api/incidents/{id}/chat`<br>`POST /api/incidents/{id}/approve`<br>`POST /api/incidents/{id}/skip`<br>`POST /api/incidents/{id}/reopen` | Interactive pre-approval Q&A with Atlas, HITL approval & JIT-gated execution, manual skip, and reopen lifecycle controls. |
| **Direct Atlas Chat & IaC** | `POST /api/atlas/chat`<br>`POST /api/atlas/chat/deploy-terraform`<br>`POST /api/atlas/chat/reset` | On-demand Atlas chat across all 4 operational scenarios, harnessed Terraform `.tf` execution, and active session message reset. |
| **Firestore Sessions** | `GET /api/atlas/sessions`<br>`POST /api/atlas/sessions/new`<br>`POST /api/atlas/sessions/{id}/select`<br>`DELETE /api/atlas/sessions/{id}`<br>`DELETE /api/atlas/sessions` (`POST /api/atlas/sessions/clear`) | Full per-user multi-session chat history management backed by Cloud Firestore (`aaas_user_sessions`). |
| **A2A Protocol (1.0)** | `GET /a2a/{agent_id}/.well-known/agent.json`<br>`POST /a2a/{agent_id}` | Standard AgentCard discovery and JSON-RPC 2.0 `tasks/send` dispatch for `log-watcher-agent`, `lead-orchestrator-agent`, and `gke-assist-agent` (plus `/healthz`, `/.well-known/agent.json`, `/diagnose`, and `/a2a` on the standalone ADK Database and Infra agents). |

---

## 4. Repository Structure

```text
AgentTriad/
├── poc/                                   # AaaS Control Plane & Command Center (Cloud Run)
│   ├── app.py                             # FastAPI server (Auth, Firestore Sessions, Incidents, A2A)
│   ├── agents/
│   │   ├── lead_orchestrator.py           # Atlas • ADK Root Orchestrator + 7-Agent Roster Router
│   │   ├── watcher_agent.py               # Heartbeat & Telemetry Agent (Edge Filter + SAIF)
│   │   ├── gke_assist_agent.py            # Deterministic Specialist Execution Hub (A2A Worker)
│   │   └── a2a_protocol.py                # A2A 1.0 AgentCard & JSON-RPC 2.0 Hub
│   ├── services/
│   │   ├── session_store_service.py       # Cloud Firestore multi-session store + local fallback
│   │   ├── cloud_logging_service.py       # Live GCP Cloud Logging + cloud-sql-proxy & edge filter
│   │   ├── agent_harness.py               # SAIF IPI guard, .tflock, OPA gate, TF dry-run, Watchdog
│   │   ├── playbook_rag.py                # Vertex AI text-embedding-004 / BM25 Golden Playbooks
│   │   ├── gke_remediator.py              # Deterministic GCP REST / CLI remediation engine
│   │   └── gcp_auth.py                    # ADC & OIDC token authentication helpers
│   ├── static/index.html                  # Material 3 Google Visual Identity AaaS Command Center UI
│   ├── test_poc.py                        # End-to-end integration test suite
│   └── Dockerfile                         # Cloud Run container image for Control Plane
├── agents/
│   ├── database_agent/                    # Standalone Live ADK Database Specialist Agent (Cloud Run)
│   │   ├── agent.py                       # Cloud SQL Admin, Monitoring & cloud-sql-proxy ADK tools
│   │   ├── server.py                      # FastAPI /healthz, /.well-known/agent.json, /diagnose, /a2a
│   │   └── Dockerfile
│   └── infra_agent/                       # Standalone Live ADK Infra Specialist Agent (Cloud Run)
│       ├── agent.py                       # Compute Engine, Monitoring & GCE Logs ADK tools
│       ├── server.py                      # FastAPI /healthz, /.well-known/agent.json, /diagnose, /a2a
│       └── Dockerfile
├── terraform/                             # Reproducible IaC Stack (Cloud Run v2, IAM, Cloud Build)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── versions.tf
├── architecture.svg                       # Reference architecture diagram
├── a3s-flow.html                          # Interactive AaaS architectural workflow diagram
├── visualizer.html                        # Interactive platform visualizer
└── AaaS_Google Cloud_WhitePaper.pdf       # Reference Google Cloud AaaS Whitepaper
```

---

## 5. Local Development & End-to-End Testing

### Run the AaaS Control Plane Locally
```bash
cd poc
../.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```
Open `http://localhost:8080` to access the AaaS Command Center UI. Set `GOOGLE_OAUTH_CLIENT_ID` (optional) to enable real Google Identity Services popup sign-in, or configure it at runtime via the Sign-In modal.

### Execute the End-to-End Test Suite
[`poc/test_poc.py`](./poc/test_poc.py) validates the full platform stack — Google Visual Identity UI & theme switcher, Google SSO token rejection (`401`) & dynamic identity, all 4 Atlas operational scenarios, Cloud Firestore multi-session lifecycle (`new`/`select`/`delete`/`clear`), OPA external-resource guardrails (`testdbconnect`), A2A AgentCards, live Cloud Logging polling, conversational HITL approval, zero-standing privilege rejection, Audit Tracker entries, and the standalone ADK Infra Specialist Agent:
```bash
.venv/bin/python poc/test_poc.py
```

---

