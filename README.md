# AgentTriad

# Agent-Triad: Autonomous Cloud Operations (AaaS)

Agent-Triad is an autonomous, outcome-driven cloud support and operations platform built on the **Google Cloud Agent as a Service (AaaS)** architecture. Built using the **Agent Development Kit (ADK)** and the **Agent2Agent (A2A) protocol** on Vertex AI, it transforms traditional reactive SRE into a closed-loop perception-reasoning-action-validation framework with deterministic guardrails and Human-in-the-Loop (HITL) authorization.

---

## High-Level Executive Summary

**AgentTriad (AaaS Control Plane)** provides an autonomous, zero-trust Google Cloud operations co-pilot (**Atlas**) that continuously observes live GCP telemetry, diagnoses root causes using live **Google ADK (`google-adk`)** specialist microservices on **Cloud Run**, and executes human-approved remediations with built-in safety guardrails and automatic rollback protection.

### Key Executive Highlights
* **3-Stage Autonomous Triad Architecture**:
  1. **Step 1 — Observe (`Heartbeat & Telemetry`)**: Continuously polls and SAIF-sanitizes live Google Cloud Logging entries (`resource.type="cloudsql_database"`, `gce_instance`, `cloud_run_revision`, `cloud_function`, `aiplatform.googleapis.com/ReasoningEngine`) and streams 15-second health heartbeats.
  2. **Step 2 — Reason & Gate (`Atlas • AaaS Lead Orchestrator`)**: Single authorizing **Vertex AI Gemini (`gemini-2.5-flash`)** root orchestrator that correlates anomalies against Golden Remediation Playbooks (RAG), delegates deep domain diagnostics over **JSON-RPC 2.0 A2A** to live Cloud Run ADK Specialist Agents, and gates all changes behind **Human-in-the-Loop (`I accept`)** approval.
  3. **Step 3 — Remediate (`7-Agent Specialist Roster`)**: Combines live **Google ADK Cloud Run Specialist Agents** (**Database Agent** & **Infra Agent**) with 5 deterministic domain execution harnesses (**Serverless**, **Networking**, **Data Analytics**, **Security**, and **Billing**) operating under **Zero-Standing Privilege**.
* **All 4 Cloud Operations Scenarios Supported**:
  * **Scenario 1 (1-Line CLI / API Fix)**: Rapid root-cause analysis and single-command `gcloud` / API remediation.
  * **Scenario 2 (Multi-Service Terraform Fix)**: Coordinated cross-domain remediation (e.g., IAM + VPC Firewall + Cloud SQL) via a pre-validated **Terraform (`.tf`)** bundle.
  * **Scenario 3 (Terraform Stack Generator)**: On-demand generation, dry-run validation, and harnessed execution of production-ready **Terraform (`.tf`)** stacks from natural language chat.
  * **Scenario 4 (GCP How-To & Advisory)**: Instant architectural and operational guidance with `$0` sandbox overhead.
* **4-Layer Safety Guardrails**:
  * **Pre-Flight Safety Check (OPA Policy Gate)**: Blocks destructive commands (`delete`, `drop`, `destroy`) and strictly protects external/shared teammate services (such as `testdbconnect` in `us-west1`).
  * **10-Minute Resource Lease (`.tflock`)**: Prevents concurrent or conflicting modifications to the same cloud resource.
  * **15-Minute Single-Use WIF JIT Token**: Specialists have **read-only** standing permissions; mutations require an ephemeral token minted only when the operator clicks **`I accept`**.
  * **45-Second Post-Fix Auto-Rollback Monitor**: Watches live logs and metrics for 45 seconds after any change and automatically reverts the configuration if errors spike.

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
| **`agent-triad-db-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-db-agent-1041190629307.us-central1.run.app` | **Live Google ADK Database Specialist Agent** (`agents/database_agent/agent.py`) for Cloud SQL diagnostics |
| **`agent-triad-infra-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-infra-agent-1041190629307.us-central1.run.app` | **Live Google ADK Infra Specialist Agent** (`agents/infra_agent/agent.py`) for Compute Engine, GKE & Terraform |
| **`testdbinstance1`** | Cloud SQL (`POSTGRES_18`) | `us-central1-f` | `agent-triad:us-central1:testdbinstance1` | Live Enterprise Plus (`db-perf-optimized-N-2`) PostgreSQL instance inspected by the ADK Database Agent |
| **`testinstance1` & Workstations VM** | Compute Engine VMs | `us-west1-b` / `us-central1-c` | `2276555501399631720` (`e2-medium`) / `workstations-...` (`e2-standard-4`) | Live Compute Engine instances inspected by the ADK Infra Agent |
| **`testdbconnect`** | Cloud Run Service (Protected) | `us-west1` | `testdbconnect` | Teammate service protected by the Agent Harness read-only external-resource guardrail |

### 3. How Services Connect & Communicate (Zero-Trust A2A Protocol)
All inter-agent communication follows the **A2A 1.0 JSON-RPC 2.0 specification** over HTTPS with **OIDC Service-to-Service Authentication**:
1. **Agent Discovery (`GET /.well-known/agent.json`)**: Every specialist exposes a machine-readable `AgentCard` declaring its capabilities, `ZeroStandingPrivilege: true` posture, and skills (`diagnose_database_anomaly`, `diagnose_infra_anomaly`).
2. **Zero-Trust OIDC Handshake**: Because GCP Organization Policy (`iam.allowedPolicyMemberDomains`) blocks public `allUsers` ingress, **Atlas** (`agent-triad-control-plane`) mints a Google-signed **OIDC Identity Token** targeting the specialist's Cloud Run URI (`DATABASE_AGENT_URL` or `INFRA_AGENT_URL`) and sends it in `Authorization: Bearer <OIDC_ID_TOKEN>`.
3. **JSON-RPC 2.0 Task Dispatch (`POST /a2a`)**:
   * When **Poll Live Logs** detects a `cloudsql_database` or `gce_instance` error—or when the user asks a question in **Chat with Atlas**—Atlas sends a `tasks/send` JSON-RPC 2.0 payload to `agent-triad-db-agent/a2a` or `agent-triad-infra-agent/a2a`.
   * The specialist executes its **Google ADK `Runner`** loop (`google.adk.runners.Runner`), invokes its live read-only GCP tools, and returns both the structured GCP API telemetry (`instance_inspection`, `performance_metrics`, `log_analysis`, `runtime_identity`, `remediation_proposal`) and the synthesized report back to Atlas.

### 4. How GCP APIs & ADK Tools Are Invoked (Out-of-Band Control Plane Telemetry)
Crucially, the ADK Specialist Agents **never open direct database socket connections (port `5432`) or direct SSH sessions into VMs** during read-only triage. Instead, they fetch short-lived OAuth2 access tokens from the **Cloud Run Metadata Server** (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`) and query official Google Cloud Control Plane REST APIs:

| ADK Specialist Agent | ADK Tool Function | Live GCP API Invoked | Telemetry & State Retrieved |
| :--- | :--- | :--- | :--- |
| **Database Agent** (`agent-triad-db-agent`) | `inspect_cloudsql_instance` | `sqladmin.googleapis.com/v1/projects/agent-triad/instances/{instance}` | Live `state` (`RUNNABLE`/`STOPPED`), `activationPolicy` (`ALWAYS`/`NEVER`), `databaseVersion` (`POSTGRES_18`), tier, HA, SSL mode, backups |
| **Database Agent** (`agent-triad-db-agent`) | `get_database_performance_metrics` | `monitoring.googleapis.com/v3/projects/agent-triad/timeSeries` | Live `cloudsql.googleapis.com/database/cpu/utilization`, `memory/utilization`, `disk/utilization`, `postgresql/num_backends`, `network/connections` |
| **Database Agent** (`agent-triad-db-agent`) | `analyze_postgres_logs` | `logging.googleapis.com/v2/entries:list` | Live `resource.type="cloudsql_database"` entries (`postgres.log`, audit logs, connection handshakes, shut-down events) |
| **Infra Agent** (`agent-triad-infra-agent`) | `inspect_compute_instances` | `compute.googleapis.com/compute/v1/projects/agent-triad/aggregated/instances` | Discovers all VMs across all zones (`instance_id`, `machineType`, `status`, disks, IPs) and flags terminated ephemeral VM IDs |
| **Infra Agent** (`agent-triad-infra-agent`) | `get_compute_performance_metrics` | `monitoring.googleapis.com/v3/projects/agent-triad/timeSeries` | Live `compute.googleapis.com/instance/cpu/utilization`, `uptime`, `network/received_bytes_count`, `sent_bytes_count`, `disk/read_bytes_count` |
| **Infra Agent** (`agent-triad-infra-agent`) | `analyze_infra_logs` | `logging.googleapis.com/v2/entries:list` | Live `resource.type="gce_instance"` Guest Agent metadata watcher errors (`context canceled`), manifest warnings & gRPC stream logs |
| **Both ADK Agents** | `inspect_*_runtime_identity` | `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/` | Live introspection of the active Cloud Run Service Account email, OAuth scopes, and read-only IAM role bindings |

### 5. IAM Service Accounts & Least-Privilege Permissions Matrix
AgentTriad enforces **Zero-Standing Privilege** across all deployed identities managed in [`terraform/main.tf`](./terraform/main.tf):

| Identity / Service Account | Attached Service | Assigned GCP IAM Roles | Security & Access Scope |
| :--- | :--- | :--- | :--- |
| **`aaas-database-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-db-agent` | `roles/cloudsql.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Cloud SQL metadata, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **`aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-infra-agent` | `roles/compute.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Compute Engine VM/disk inventory, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **Control Plane Runtime SA** (`1041190629307-compute@developer.gserviceaccount.com`) | `agent-triad-control-plane` | `roles/run.invoker` *(on `agent-triad-db-agent` & `agent-triad-infra-agent`)*<br>Cloud Logging, Monitoring, Run, SQL & Compute API inspection | Authorizes Atlas to invoke specialist Cloud Run endpoints via OIDC tokens and execute human-approved remediations only after minting a 15-minute JIT token. |

---

## 1. System Architecture

The architecture enforces a strict decoupling between the **Central SaaS Control Plane** (multi-tenant orchestration, model inference, and customer dashboard) and the **Customer Data Plane** (localized telemetry ingestion and isolated execution endpoints).

+---------------------------------------------------------------------------------------------------------------+
|                                      GCP CENTRAL SAAS CONTROL PLANE                                           |
|                                                                                                               |
|   +---------------------------------------+       2. REASONING (A2A Protocol)      +----------------------+   |
|   |       Multi-Tenant UI Dashboard       |<-------------------------------------->|  ADK Multi-Agent     |   |
|   |  * Incident Triage View               |                                        |  Core (Triad)        |   |
|   |  * RCA / Proposed Fix                 |         3. HITL APPROVAL               |  * Frontline Watcher |   |
|   |  * HITL Authorization Gate            |--------------------------------------->|  * Reasoning Agent   |   |
|   |    (Approves Scope & JIT minting)     |                                        |  * Exec Orchestrator |   |
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

---

## 2. The Agent Triad Lifecycle

System Incident Occurs
|
▼
INGESTION & DETECTION 
Front line Watcher continuously streams error telemetry and anomaly triggers.
|
▼
REASONING & RCA 
Troubleshooting Agent correlates logs with run books and generates a strictly typed JSON remediation payload.
|
▼
HUMAN-IN-THE-LOOP APPROVAL
UI presents the diagnosis, target resources, and action plan with a cryptographic, expiring authorization token.
|
▼
CONTROLLED EXECUTION 
Executioner Webhook validates parameters against an explicit allowlist and invokes target GCP APIs.
│
▼  
STABILIZATION & POST-VERIFICATION 
System enforces a 45s stabilization window, after which the Front line Watcher validates telemetry recovery.

---

