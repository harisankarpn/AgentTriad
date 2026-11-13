# Agent-Triad: Autonomous Cloud Operations (AaaS)

Agent-Triad is an autonomous, cloud-agnostic, outcome-driven cloud support and operations platform built on the **Agent as a Service (AaaS)** architecture. Originally built on Google Cloud using the **Agent Development Kit (ADK)** and the **Agent2Agent (A2A) protocol**, it has evolved into a **Ports & Adapters multi-cloud platform** that runs seamlessly on **Google Cloud (Cloud Run / GKE)**, **AWS (EKS / RDS / EC2 / Bedrock)**, **Microsoft Azure (AKS / Azure SQL / VMs / Azure OpenAI)**, **Red Hat OpenShift**, or **zero-cloud local Docker Compose**. It transforms reactive SRE into a closed-loop perception-reasoning-action-validation framework with deterministic guardrails, **Google Identity Services / OIDC SSO**, **pluggable multi-session persistence (Firestore / PostgreSQL / Redis)**, **Proactive SRE Intelligence**, and Human-in-the-Loop (HITL) authorization.

---

## High-Level Executive Summary

**AgentTriad (AaaS Control Plane)** provides an autonomous, zero-trust cloud operations co-pilot (**Atlas**) that continuously observes live telemetry (Google Cloud Logging or OpenTelemetry / Loki / Prometheus), diagnoses root causes using live **Google ADK (`google-adk`)** specialist microservices across **GCP, AWS, and Azure**, correlates incidents with GitOps releases and cloud provider status feeds, persists per-user operational sessions (**Cloud Firestore**, **PostgreSQL**, or **Redis**), and executes human-approved remediations with built-in safety guardrails and automatic rollback protection.

### Key Executive Highlights
* **3-Stage Autonomous Triad Architecture**:
  1. **Step 1 — Observe (`Heartbeat & Telemetry`)**: Continuously polls and SAIF-sanitizes live telemetry via pluggable `TelemetryIngestionAdapter` backends — **Google Cloud Logging** (`cloudsql_database`, `cloud-sql-proxy`, `gce_instance`, `cloud_run_revision`, `cloud_function`, `aiplatform.googleapis.com/ReasoningEngine`) or **OpenTelemetry / Grafana Loki / Prometheus Alertmanager / CloudWatch OTel** — suppressing routine edge noise at `$0` LLM cost and streaming 15-second health heartbeats.
  2. **Step 2 — Reason & Gate (`Atlas • AaaS Lead Orchestrator`)**: Model-agnostic root orchestrator (`AAAS_LLM_PROVIDER=vertex|gemini|bedrock|azure_openai|openai|litellm`, defaulting to **Vertex AI Gemini `gemini-2.5-flash`**) that correlates anomalies against Golden Remediation Playbooks (RAG), checks cloud provider regional status pre-flight, delegates deep domain diagnostics over **JSON-RPC 2.0 A2A** to live ADK Specialist Agents, and gates all mutations behind **Human-in-the-Loop (`I accept`)** approval tied to the authenticated SSO user.
  3. **Step 3 — Remediate (`7-Agent Specialist Roster`)**: Combines live **ADK Specialist Microservices** (**Database Agent** for Cloud SQL / AWS RDS / Azure SQL & **Infra Agent** for GCE / AWS EC2 / Azure VMs / GKE / GitOps) with 5 deterministic domain execution harnesses (**Serverless**, **Networking**, **Data Analytics**, **Security**, and **Billing**) operating under **Zero-Standing Privilege** (`$0` extra LLM token cost during execution).
* **Cloud-Agnostic Ports & Adapters Portability (100% GCP Backward-Compatible)**:
  * **Zero Vendor Lock-In**: Swap telemetry (`gcp` | `otel`), session state (`firestore` | `postgres` | `redis` | `memory`), distributed locking (`local` | `redis` | `memory`), target cloud diagnostics (`gcp` | `aws` | `azure`), LLM inference (`vertex` | `gemini` | `bedrock` | `azure_openai` | `openai` | `litellm`), and identity federation (`GCP WIF` | `AWS STS` | `Azure Entra ID`) strictly via environment variables — while keeping **GCP Cloud Run + Vertex AI + Cloud Firestore** as the zero-config default.
  * **Run Anywhere**: Deploy on GCP Cloud Run via [`terraform/main.tf`](./terraform/main.tf), locally or on any VM with zero cloud dependencies via [`docker-compose.yml`](./docker-compose.yml), or one-click to **AWS EKS**, **Azure AKS**, **Google GKE**, and **Red Hat OpenShift** via the Helm chart in [`deploy/helm/agent-triad/`](./deploy/helm/agent-triad/).
* **All 4 Cloud Operations Scenarios Supported**:
  * **Scenario 1 (1-Line CLI / API Fix)**: Rapid root-cause analysis and single-command `gcloud` / `aws` / `az` / API remediation.
  * **Scenario 2 (Multi-Service Terraform Fix)**: Coordinated cross-domain remediation (e.g., IAM + VPC Firewall + Database) via a pre-validated **Terraform (`.tf`)** bundle and **Bidirectional GitOps Reconciliation PR** payloads.
  * **Scenario 3 (Terraform Stack Generator)**: On-demand generation, dry-run validation, and harnessed execution of production-ready **Terraform (`.tf`)** stacks from natural language chat.
  * **Scenario 4 (Cloud How-To & Advisory)**: Instant architectural and operational guidance with `$0` sandbox overhead.
* **Enterprise Identity & Pluggable Multi-Session Workspace**:
  * **Google Identity Services (OAuth 2.0), IAP & Standard OIDC SSO**: Real Google Workspace sign-in, GCP IAP header auto-detection, and pluggable standard OIDC JWT verification (RS256/ES256 via JWKS or HS256) with dynamic user identity propagation across Atlas conversations, HITL approvals, and the Audit & Event Tracker.
  * **Multi-Session Chat History**: Persists up to **25 chat sessions per signed-in user** in **Cloud Firestore** (`aaas_user_sessions`, default), **PostgreSQL**, or **Redis** with instant session switching, auto-generated titles, reset/delete/clear-all controls, and local fallback caching.
  * **Google Visual Identity (Material 3) Command Center**: Official 4-color Google palette (`#4285F4`, `#EA4335`, `#FBBC04`, `#34A853`), Left Sidebar Navigation Rail (`Command Center`, `Specialist Roster`, `Audit & Events`, `View Logs & A2A`), and **Auto / Dark / Light** theme switcher.
* **5-Layer Safety & Proactive SRE Guardrails**:
  * **Cloud Provider Outage Pre-Flight Gate**: Checks live GCP, AWS, and Azure regional status feeds before allowing infrastructure mutations; automatically blocks changes (`BLOCKED_PROVIDER_OUTAGE`) and withholds JIT token minting during active provider outages.
  * **Pre-Flight Safety Check (OPA Policy Gate)**: Blocks destructive commands (`delete`, `drop`, `destroy`) and strictly protects external/shared teammate services (such as `testdbconnect` in `us-west1`).
  * **10-Minute Distributed Resource Lease (`.tflock` / Redis TTL)**: Prevents concurrent or conflicting modifications across single-instance or multi-replica deployments.
  * **15-Minute Single-Use WIF JIT Token**: Specialists have **read-only** standing permissions; mutations require an ephemeral token (`jit-wif-*` + OIDC `web_identity_token`) minted only when the operator clicks **`I accept`**, federated across GCP WIF STS, AWS STS `AssumeRoleWithWebIdentity`, or Azure Entra ID `jwt-bearer`.
  * **Two-Stage Post-Fix Verification & Bifurcated Rollback (`45s` Liveness + `3m` Metrics)**: Pairs a **45-second direct Control-Plane API liveness probe** (with strict `timestamp > execution_completed_at` filtering) with a **3-minute (180s) monitoring stabilization window** and **45-minute anti-flapping hysteresis freeze**. Stateless workloads (`Cloud Run`/`GKE`/`EKS`/`AKS`) auto-revert on regression, while stateful workloads (`Cloud SQL`/`RDS`/`Azure SQL`/Disks) enforce **Stateful Safe-Mode Isolation** (`deletion_protection = true`, `prevent_destroy = true`).

---

## Cloud-Agnostic Architecture & 5-Phase Evolution

Agent-Triad was refactored across **5 engineering phases** into a clean **Ports & Adapters (Hexagonal) architecture** inside [`poc/providers/`](./poc/providers/) and [`poc/services/`](./poc/services/), preserving 100% backward compatibility with the existing GCP Cloud Run deployment while unlocking full multi-cloud and zero-cloud portability.

### Phase 1 — Pluggable Telemetry, State Persistence & Distributed Locking Ports
Decoupled GCP-specific logging, Firestore session storage, and local `.tflock` locking behind abstract ports:

| Port Interface | File | Default Adapter (GCP-Compatible) | Cloud-Agnostic / Portable Adapters | Env Selector |
| :--- | :--- | :--- | :--- | :--- |
| **`TelemetryIngestionAdapter`** (`TelemetryProvider`) | [`poc/providers/base_telemetry.py`](./poc/providers/base_telemetry.py) | `GCPCloudLoggingAdapter` ([`poc/providers/gcp/cloud_logging_adapter.py`](./poc/providers/gcp/cloud_logging_adapter.py)) | `OTelLokiLogAdapter` ([`poc/providers/generic/otel_loki_adapter.py`](./poc/providers/generic/otel_loki_adapter.py)) — pulls Grafana Loki (`/loki/api/v1/query_range`), Prometheus Alertmanager (`/api/v2/alerts`), and ingests OTLP / AWS CloudWatch / Azure Monitor OTel logs normalized via `normalize_otel_anomaly()` | `AAAS_TELEMETRY_PROVIDER=gcp\|otel` |
| **`SessionStoreAdapter`** | [`poc/providers/base_state.py`](./poc/providers/base_state.py) | `GCPFirestoreSessionAdapter` ([`poc/providers/gcp/firestore_session_adapter.py`](./poc/providers/gcp/firestore_session_adapter.py)) | `PostgresSessionAdapter` ([`poc/providers/generic/postgres_session_adapter.py`](./poc/providers/generic/postgres_session_adapter.py), `psycopg`/`psycopg2`/`sqlalchemy`), `RedisSessionAdapter` ([`poc/providers/generic/redis_lock_adapter.py`](./poc/providers/generic/redis_lock_adapter.py)), `InMemorySessionAdapter` ([`poc/providers/generic/memory_state_adapters.py`](./poc/providers/generic/memory_state_adapters.py)) | `AAAS_STATE_BACKEND=firestore\|postgres\|redis\|memory` |
| **`DistributedLockAdapter`** | [`poc/providers/base_state.py`](./poc/providers/base_state.py) | `LocalFileLockAdapter` ([`poc/providers/generic/memory_state_adapters.py`](./poc/providers/generic/memory_state_adapters.py)) | `RedisLockAdapter` ([`poc/providers/generic/redis_lock_adapter.py`](./poc/providers/generic/redis_lock_adapter.py)) — atomic Redis `EX` TTL for multi-replica `.tflock` leases & 45-min hysteresis freezes; `InMemoryLockAdapter` | `AAAS_LOCK_BACKEND=local\|redis\|memory` |

### Phase 2 — Model-Agnostic LLM Routing & Pluggable OIDC / Multi-Cloud Auth Broker
* **Model-Agnostic LLM Router** ([`poc/providers/model_router.py`](./poc/providers/model_router.py)):
  * Unified `resolve_adk_model()` and `ModelAgnosticLLMClient` shared across Atlas ([`poc/agents/lead_orchestrator.py`](./poc/agents/lead_orchestrator.py)) and both standalone ADK specialist agents ([`agents/database_agent/agent.py`](./agents/database_agent/agent.py), [`agents/infra_agent/agent.py`](./agents/infra_agent/agent.py)).
  * Supports **`vertex`** (default, `gemini-2.5-flash`), **`gemini`** (Google AI Studio), **`bedrock`** (AWS Bedrock Claude/Llama), **`azure_openai`** (Azure OpenAI Service), **`openai`**, and **`litellm`** (any LiteLLM / Ollama OpenAI-compatible proxy).
  * Automatically degrades to **zero-key deterministic RAG/Playbook mode** when no API key or cloud credential is configured.
* **Pluggable Identity & Auth Broker** ([`poc/services/auth_broker.py`](./poc/services/auth_broker.py)):
  * Implements `IdentityBrokerProvider` and `CloudAuthBroker` (`AAAS_AUTH_PROVIDER=oidc|gcp`), wrapped cleanly by backward-compatible [`poc/services/gcp_auth.py`](./poc/services/gcp_auth.py).
  * Verifies **Google ID tokens**, standard **OIDC JWTs** (RS256/ES256 via `AAAS_OIDC_JWKS_URL` or HS256 via `AAAS_OIDC_HS256_SECRET`), and **OAuth 2.0 UserInfo** endpoints.
  * Mints single-action 15-minute HITL JIT tokens (`jit-wif-*` + OIDC `web_identity_token`) and supports multi-cloud Workload Identity federation exchanges:
    * **GCP**: Workload Identity Federation STS (`urn:ietf:params:oauth:grant-type:token-exchange`)
    * **AWS**: STS `AssumeRoleWithWebIdentity`
    * **Azure**: Microsoft Entra ID Federated Credentials (`jwt-bearer` client assertion)

### Phase 3 — Multi-Cloud Specialist Cloud Strategy Adapters (GCP / AWS / Azure)
Refactored both live ADK specialist agents to delegate all cloud API telemetry and safe HCL proposal generation through pluggable strategy adapters in [`poc/providers/base_cloud.py`](./poc/providers/base_cloud.py) and [`poc/providers/cloud_factory.py`](./poc/providers/cloud_factory.py) (selected via `CLOUD_PROVIDER=gcp|aws|azure` or per-request `target_cloud`):

| Target Cloud | Database Strategy (`DatabaseCloudAdapter`) | Compute Strategy (`ComputeCloudAdapter`) | SDK / API Layer |
| :--- | :--- | :--- | :--- |
| **`gcp`** *(default)* | `GCPDatabaseCloudAdapter` ([`poc/providers/gcp/cloud_adapters.py`](./poc/providers/gcp/cloud_adapters.py)) — Cloud SQL Admin, Cloud Monitoring, `cloudsql_database` & `cloud-sql-proxy` logs | `GCPComputeCloudAdapter` ([`poc/providers/gcp/cloud_adapters.py`](./poc/providers/gcp/cloud_adapters.py)) — Compute Engine VMs, Cloud Monitoring, GCE Guest Agent logs | Official GCP Control Plane REST APIs + Metadata Server |
| **`aws`** | `AWSDatabaseCloudAdapter` ([`poc/providers/aws/cloud_adapters.py`](./poc/providers/aws/cloud_adapters.py)) — AWS RDS (`describe_db_instances`), CloudWatch metrics & RDS logs | `AWSComputeCloudAdapter` ([`poc/providers/aws/cloud_adapters.py`](./poc/providers/aws/cloud_adapters.py)) — AWS EC2 (`describe_instances`), CloudWatch metrics & system logs | Lazy `boto3` with client injection & IRSA support |
| **`azure`** | `AzureDatabaseCloudAdapter` ([`poc/providers/azure/cloud_adapters.py`](./poc/providers/azure/cloud_adapters.py)) — Azure SQL (`azure-mgmt-sql`) & Azure Monitor | `AzureComputeCloudAdapter` ([`poc/providers/azure/cloud_adapters.py`](./poc/providers/azure/cloud_adapters.py)) — Azure Virtual Machines (`azure-mgmt-compute`) & Azure Monitor | Lazy `azure-mgmt-*` + `DefaultAzureCredential` / AKS Workload Identity |

### Phase 4 — Proactive SRE Intelligence & Bidirectional GitOps
Added three production SRE intelligence engines wired directly into Watcher, Atlas, the Infra Agent, and the Database Agent:

1. **Cloud Provider Regional Outage Pre-Flight Gate** ([`poc/services/cloud_status_service.py`](./poc/services/cloud_status_service.py)):
   * Exposed via `GET /api/preflight/cloud-status?cloud={gcp|aws|azure}&region={region}` and Watcher A2A skill `check_cloud_provider_status`.
   * Inspects live provider status feeds (`https://status.cloud.google.com/incidents.json`, `AAAS_AWS_STATUS_URL`, `AAAS_AZURE_STATUS_URL`) before allowing infrastructure mutations.
   * When an active regional outage is detected, Atlas blocks execution (`BLOCKED_PROVIDER_OUTAGE`) and **withholds JIT token minting** so the platform never makes destructive changes during an upstream cloud outage. Operates fail-safe (`STATUS_FEED_UNREACHABLE` advisory warning) if feeds are unreachable unless `AAAS_CLOUD_STATUS_FAIL_CLOSED=true`.
2. **GitOps Deployment Correlator & Bidirectional Reconciliation PRs** ([`poc/services/gitops_correlator.py`](./poc/services/gitops_correlator.py)):
   * Exposed as ADK tool `correlate_gitops_deployments` on the Infra Agent and invoked during incident triage & remediation.
   * Correlates incident timestamps against recent `git log` commits and CI/CD release metadata (Cloud Run revisions, ArgoCD/Flux syncs, GitHub deployments) to surface suspect commits and revert commands.
   * Generates structured GitHub/GitLab **Bidirectional GitOps Reconciliation PR** payloads (`BIDIRECTIONAL_GITOPS_PR`, declarative Terraform/manifest diff, branch name, PR title/body, and audit metadata targeting `AAAS_GITOPS_REPO` / `AAAS_GITOPS_BASE_BRANCH`) instead of relying solely on imperative CLI mutations.
3. **Strictly Read-Only Database Query Introspection** ([`poc/services/db_query_introspection.py`](./poc/services/db_query_introspection.py)):
   * Exposed as ADK tool `introspect_db_query_activity` on the Database Agent across Cloud SQL, AWS RDS, and Azure SQL.
   * Enforces `is_strictly_readonly_introspection_sql()` (blocking any DML/DDL or admin functions such as `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `GRANT`, `pg_terminate_backend`, `pg_cancel_backend`) and executes `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`.
   * Defaults to **Zero-Standing-Privilege out-of-band slow-query log inspection** (identifying long-running SQL, lock waits, and deadlocks without TCP/5432 socket access); optionally connects to live `pg_stat_activity` / `pg_stat_statements` only when `AAAS_DB_READONLY_DSN` is explicitly configured. Any recommended SQL fix (`CREATE INDEX CONCURRENTLY`, etc.) is returned strictly as an HITL-gated advisory proposal.

### Phase 5 — Portable Zero-Cloud Local & Multi-Cluster Kubernetes / OpenShift Deployment
* **Unified Health Probe (`GET /healthz`)**: Added to `agent-triad-control-plane` (matching `db-agent` and `infra-agent`), reporting live `state_backend`, `lock_backend`, `telemetry_provider`, and `llm_provider`.
* **Zero-Cloud Docker Compose Stack** ([`docker-compose.yml`](./docker-compose.yml) + [`.env.example`](./.env.example)): Runs all 5 services (`control-plane`, `db-agent`, `infra-agent`, `postgres:16-alpine`, `redis:7-alpine`) locally or on any VM with healthchecks and zero cloud accounts required.
* **Portable Kubernetes & Red Hat OpenShift Helm Chart** ([`deploy/helm/agent-triad/`](./deploy/helm/agent-triad/)): Production Helm v2 chart (17 templates) supporting **AWS EKS** (IRSA + Bedrock + ALB Ingress), **Azure AKS** (Workload Identity + Azure OpenAI + NGINX/AGIC), **Google GKE** (Workload Identity + Vertex AI + GCE Ingress), and **Red Hat OpenShift** (`openshift.enabled=true` for `restricted-v2` SCC compliance + edge-terminated TLS `Route`), plus optional `HorizontalPodAutoscaler`, `NetworkPolicy`, in-cluster or managed PostgreSQL/Redis, and `existingSecret` integration.

---

## Live Production Deployment & Service Topology (`agent-triad` on GCP)

### 1. How the GCP Reference Stack Is Deployed
The GCP reference deployment is provisioned reproducibly in project **`agent-triad`** (`us-central1`) using **Terraform (`>= 1.5`)** in [`terraform/main.tf`](./terraform/main.tf) (100% preserved and backward-compatible):
1. **Container Build & Registry**: Source code changes in `agents/database_agent/`, `agents/infra_agent/`, and `poc/` are automatically hashed (`filesha256`), built via **Google Cloud Build** (`gcloud builds submit`), and pushed to **Artifact Registry** (`us-central1-docker.pkg.dev/agent-triad/agent-triad-repo/...`).
2. **Serverless Microservices on Cloud Run v2**: Deployed as independent, scale-to-zero (`min_instance_count = 0`, `max_instance_count = 3`, `cpu_idle = true`) Cloud Run v2 services with pre-compiled Python bytecode (`python -m compileall`) for fast cold-start responsiveness and `$0` idle compute cost.
3. **1-Command GCP Deployment**:
   ```bash
   cd terraform
   GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" ../.venv/bin/terraform apply -auto-approve
   ```

### 2. List of Deployed GCP Services & Monitored Resources

| Service / Resource | Type | Region / Zone | Live Endpoint / Identifier | Architectural Role |
| :--- | :--- | :--- | :--- | :--- |
| **`agent-triad-control-plane`** | Cloud Run v2 Service | `us-central1` | `https://agent-triad-control-plane-1041190629307.us-central1.run.app` | **AaaS Command Center UI + Atlas Root Orchestrator** (`poc/app.py`, `poc/agents/lead_orchestrator.py`) |
| **`agent-triad-db-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-db-agent-1041190629307.us-central1.run.app` | **Live ADK Database Specialist Agent** (`agents/database_agent/agent.py`) for Cloud SQL / RDS / Azure SQL & query introspection |
| **`agent-triad-infra-agent`** | Cloud Run v2 ADK Agent | `us-central1` | `https://agent-triad-infra-agent-1041190629307.us-central1.run.app` | **Live ADK Infra Specialist Agent** (`agents/infra_agent/agent.py`) for Compute Engine / EC2 / Azure VMs, GKE, Terraform & GitOps correlation |
| **Cloud Firestore `(default)`** | Cloud Firestore Database | `agent-triad` | `projects/agent-triad/databases/(default)` (`aaas_user_sessions`) | **Default Per-User Multi-Session Chat Persistence** (`GCPFirestoreSessionAdapter`; swappable with PostgreSQL or Redis) |
| **`testdbinstance1`** | Cloud SQL (`POSTGRES_18`) | `us-central1-f` | `agent-triad:us-central1:testdbinstance1` | Live Enterprise Plus (`db-perf-optimized-N-2`) PostgreSQL instance inspected by the ADK Database Agent |
| **`testinstance1` & Workstations VM** | Compute Engine VMs | `us-west1-b` / `us-central1-c` | `2276555501399631720` (`e2-medium`) / `workstations-...` (`e2-standard-4`) | Live Compute Engine instances inspected by the ADK Infra Agent |
| **`testdbconnect`** | Cloud Run Service (Protected) | `us-west1` | `testdbconnect` | Teammate service protected by the Agent Harness read-only external-resource guardrail |

### 3. How Services Connect & Communicate (Zero-Trust A2A Protocol)
All inter-agent communication follows the **A2A 1.0 JSON-RPC 2.0 specification** over HTTPS with **OIDC Service-to-Service Authentication**:
1. **Agent Discovery (`GET /.well-known/agent.json`)**: Every specialist exposes a machine-readable `AgentCard` declaring its capabilities, `ZeroStandingPrivilege: true` posture, and skills (`diagnose_database_anomaly`, `execute_approved_db_remediation`, `diagnose_infra_anomaly`, `execute_approved_infra_remediation`, `check_cloud_provider_status`).
2. **Zero-Trust OIDC Handshake**: Because GCP Organization Policy (`iam.allowedPolicyMemberDomains`) blocks public `allUsers` ingress, **Atlas** (`agent-triad-control-plane`) mints an **OIDC Identity Token** targeting the specialist's URI (`DATABASE_AGENT_URL` or `INFRA_AGENT_URL`) via `CloudAuthBroker` and sends it in `Authorization: Bearer <OIDC_ID_TOKEN>`. In Kubernetes/Docker Compose deployments, specialists are reached over internal cluster DNS (`http://db-agent:8080`, `http://infra-agent:8080`) with NetworkPolicy isolation.
3. **JSON-RPC 2.0 Task Dispatch (`POST /a2a`)**:
   * When telemetry detects a database or compute anomaly—or when the user asks a question in **Chat with Atlas**—Atlas sends a `tasks/send` JSON-RPC 2.0 payload to `agent-triad-db-agent/a2a` or `agent-triad-infra-agent/a2a`.
   * The specialist executes its **Google ADK `Runner`** loop (`google.adk.runners.Runner`), dispatches live read-only cloud tools via the active `DatabaseCloudAdapter` / `ComputeCloudAdapter` (`gcp` | `aws` | `azure`), and returns structured telemetry (`instance_inspection`, `performance_metrics`, `log_analysis`, `query_introspection`, `gitops_correlation`, `runtime_identity`, `remediation_proposal`) plus the synthesized report back to Atlas.

### 4. How Cloud APIs & ADK Tools Are Invoked (Out-of-Band Control Plane Telemetry)
By default, ADK Specialist Agents **never open direct database socket connections (port `5432`) or direct SSH sessions into VMs** during read-only triage. Instead, they query official Cloud Control Plane REST / SDK APIs using least-privilege workload identities (GCP Metadata Server, AWS IRSA, or Azure Managed Identity):

| ADK Specialist Agent | ADK Tool Function | Multi-Cloud APIs Invoked (`gcp` / `aws` / `azure`) | Telemetry & State Retrieved |
| :--- | :--- | :--- | :--- |
| **Database Agent** | `inspect_cloudsql_instance` | **GCP**: `sqladmin.googleapis.com/v1`<br>**AWS**: RDS `describe_db_instances`<br>**Azure**: `azure-mgmt-sql` | Live `state`, activation policy, engine version, tier, HA, SSL mode, security groups & backups |
| **Database Agent** | `get_cloudsql_performance_metrics` | **GCP**: `monitoring.googleapis.com/v3`<br>**AWS**: CloudWatch `AWS/RDS`<br>**Azure**: Azure Monitor SQL metrics | CPU utilization, memory/freeable memory, disk/storage utilization, active connections & backends |
| **Database Agent** | `analyze_db_logs_and_connections` | **GCP**: `logging.googleapis.com/v2` (`cloudsql_database`, `cloud-sql-proxy`)<br>**AWS**: CloudWatch Logs RDS<br>**Azure**: Azure Monitor diagnostics | Classifies connection timeouts, SSL rejections, auth failures, pool exhaustion & unexpected shutdowns |
| **Database Agent** | `introspect_db_query_activity` | **Out-of-Band Default**: Slow-query logs<br>**Opt-In (`AAAS_DB_READONLY_DSN`)**: `READ ONLY` `pg_stat_activity` / `pg_stat_statements` | Active long-running queries, lock waits, blocking PIDs & deadlocks with strictly read-only SQL enforcement |
| **Infra Agent** | `inspect_compute_instances` | **GCP**: `compute.googleapis.com/compute/v1`<br>**AWS**: EC2 `describe_instances`<br>**Azure**: `azure-mgmt-compute` | Discovers VMs across zones/regions (`instance_id`, machine type, status, disks, IPs) and flags terminated ephemeral IDs |
| **Infra Agent** | `get_compute_performance_metrics` | **GCP**: `monitoring.googleapis.com/v3`<br>**AWS**: CloudWatch `AWS/EC2`<br>**Azure**: Azure Monitor VM metrics | CPU utilization, uptime, network ingress/egress & disk IOPS/bytes |
| **Infra Agent** | `analyze_infra_logs` | **GCP**: `logging.googleapis.com/v2` (`gce_instance`)<br>**AWS**: CloudWatch Logs EC2<br>**Azure**: Azure Activity / VM logs | Guest Agent metadata errors, OOM/kernel warnings & system stream errors |
| **Infra Agent** | `correlate_gitops_deployments` | Read-only local `git log` & CI/CD deployment metadata (`poc/services/gitops_correlator.py`) | Suspect recent commits, touched files, revert commands & Bidirectional GitOps PR payloads |
| **Both ADK Agents** | `inspect_agent_runtime_identity` / `inspect_infra_agent_runtime_identity` | GCP Metadata Server / AWS STS `get_caller_identity` / Azure Managed Identity | Live introspection of active runtime identity, scopes, and read-only permission posture |
| **Both ADK Agents** | `generate_remediation_proposal` / `generate_infra_remediation_proposal` | Read-only deterministic synthesis | Safe cloud CLI (`gcloud`/`aws`/`az`), `deletion_protection = true` / `prevent_destroy = true` Terraform HCL, and GitOps PR payloads |

### 5. IAM Service Accounts & Least-Privilege Permissions Matrix (GCP Reference)
AgentTriad enforces **Zero-Standing Privilege** across all deployed identities managed in [`terraform/main.tf`](./terraform/main.tf) (with equivalent IRSA / Azure Workload Identity annotations in [`deploy/helm/agent-triad/templates/serviceaccount.yaml`](./deploy/helm/agent-triad/templates/serviceaccount.yaml)):

| Identity / Service Account | Attached Service | Assigned GCP IAM Roles | Security & Access Scope |
| :--- | :--- | :--- | :--- |
| **`aaas-database-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-db-agent` | `roles/cloudsql.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Cloud SQL metadata, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **`aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com`** | `agent-triad-infra-agent` | `roles/compute.viewer`<br>`roles/monitoring.viewer`<br>`roles/logging.viewer`<br>`roles/aiplatform.user` | **Strictly Read-Only** Compute Engine VM/disk inventory, Cloud Monitoring metrics, and Cloud Logging access + Vertex AI Gemini ADK inference. **Zero write/admin roles.** |
| **Control Plane Runtime SA** (`1041190629307-compute@developer.gserviceaccount.com`) | `agent-triad-control-plane` | `roles/run.invoker` *(on `agent-triad-db-agent` & `agent-triad-infra-agent`)*<br>Cloud Logging, Monitoring, Firestore (`aaas_user_sessions`), Run, SQL & Compute API access | Authorizes Atlas to invoke specialist Cloud Run endpoints via OIDC tokens, persist per-user chat sessions in Cloud Firestore, and execute human-approved remediations only after passing cloud outage pre-flight checks and minting a 15-minute JIT token. |

### 6. Production Resilience & Enterprise Architecture Guarantees
To prevent autonomous SRE failure modes in production, the Agent Harness ([`poc/services/agent_harness.py`](./poc/services/agent_harness.py)), Cloud Status Pre-Flight Service ([`poc/services/cloud_status_service.py`](./poc/services/cloud_status_service.py)), and ADK Specialist Agents enforce five architectural guarantees:

1. **Cloud Provider Outage Pre-Flight Gate**:
   * Before executing any approved remediation or minting a JIT token, Atlas verifies regional provider health (`gcp` | `aws` | `azure`) via `cloud_status_service.check_region_status()`. Active provider outages block mutations with `BLOCKED_PROVIDER_OUTAGE`.
2. **Two-Stage Post-Fix Verification Window (Accounting for Metric Ingestion Latency)**:
   * **Stage 1 (`45s` Direct API Liveness + Timestamp Guard)**: Immediately polls the live Cloud Control Plane API and filters logs strictly to `timestamp > execution_completed_at` so delayed pre-fix logs are never mistaken for post-fix regressions.
   * **Stage 2 (`180s` / `3-Minute` Monitoring Stabilization Window)**: Evaluates aggregated CPU, memory, and connection time-series across a full 3-minute window.
   * **Stage 3 (`45-Minute` Temporal Hysteresis Freeze)**: Applies a 45-minute cooldown (`temporal_hysteresis_freezes`, backed by Redis TTL in multi-replica deployments) per workload to prevent oscillation/flapping.
3. **Bifurcated Rollback Engine (Stateless Auto-Rollback vs. Stateful Safe-Mode Isolation)**:
   * **Stateless Workloads (`STATELESS_CANARY_ROLLBACK`)**: Cloud Run revisions, Kubernetes deployments, and VM guest metadata support atomic rollback to the prior healthy revision/state.
   * **Stateful Workloads (`STATEFUL_SAFE_MODE_ISOLATION`)**: Automated destructive rollbacks are **strictly forbidden** on stateful resources (`Cloud SQL`, `RDS`, `Azure SQL`, `AlloyDB`, `Spanner`, Persistent Disks). All generated Terraform HCL enforces `deletion_protection = true` and `lifecycle { prevent_destroy = true }`, and [`validate_terraform_dry_run()`](./poc/services/agent_harness.py) rejects (`FAILED`) any HCL with `deletion_protection = false` or `force_destroy = true`.
4. **Zero-SPOF Degraded Mode (`$0` LLM Deterministic Fallback & Direct Specialist Endpoints)**:
   * If the configured LLM provider (Vertex AI, Bedrock, Azure OpenAI, OpenAI, or LiteLLM) experiences quota exhaustion (`429`), an outage, or has no API key configured, `Atlas`, `db-agent`, and `infra-agent` automatically bypass the LLM and execute their **deterministic Cloud API tools and Golden Playbooks at `0` LLM tokens**.
   * Each specialist microservice also exposes an independent `POST /diagnose` endpoint so monitoring webhooks or SREs can invoke domain diagnostics directly even if `agent-triad-control-plane` is unreachable.
5. **Hub-and-Spoke Multi-Project / Multi-Account Readiness**:
   * Every ADK tool accepts a dynamic `project_id` / account / subscription parameter and optional `target_cloud`, supporting centralized **Hub-and-Spoke** operations across GCP Projects (with VPC-SC), AWS Accounts (via cross-account IRSA roles), and Azure Subscriptions.

---

## AaaS Command Center UI, SSO & Multi-Session History

The Control Plane ([`poc/app.py`](./poc/app.py), [`poc/static/index.html`](./poc/static/index.html), [`poc/services/session_store_service.py`](./poc/services/session_store_service.py), [`poc/services/auth_broker.py`](./poc/services/auth_broker.py)) delivers a full multi-user operational workspace:

### 1. Google Identity Services (OAuth 2.0), IAP & Pluggable OIDC Authentication
* **Real Google SSO Modal**: Uses Google Identity Services (`accounts.google.com/gsi/client`) in Material 3 Google Workspace styling with an On-Call Role option (`Cloud SRE Lead` / `sre-lead@google.com`) and runtime OAuth 2.0 Web Client ID configuration (`GOOGLE_OAUTH_CLIENT_ID` or `POST /api/auth/config`).
* **Multi-Tier Backend Identity Verification (`GET /api/auth/me`, `POST /api/auth/google`)**:
  1. **Google Cloud IAP Auto-Detection**: Reads `X-Goog-Authenticated-User-Email` automatically when deployed behind IAP (`gcp-iap`).
  2. **OAuth 2.0 Access Token Verification**: Validates live access tokens against `https://www.googleapis.com/oauth2/v3/userinfo` (`google-oauth2-verified`).
  3. **Cryptographic OIDC / Google ID Token (JWT) Verification**: Verifies Google ID tokens or generic enterprise OIDC JWTs (Okta, Auth0, Keycloak, Entra ID via `AAAS_OIDC_JWKS_URL` / `AAAS_OIDC_ISSUER` / `AAAS_OIDC_AUDIENCE`) inside `CloudAuthBroker`, rejecting forged or invalid credentials with HTTP `401`.
* **End-to-End Dynamic Identity Propagation**: The active authenticated user dynamically personalizes Atlas greetings, labels HITL approvals (`approved_by`), populates the immutable **Audit & Event Tracker**, tags Terraform/GitOps deployments, and scopes per-user chat history.

### 2. Pluggable Multi-Session Chat Manager
* **Durable Per-User Persistence**: [`poc/services/session_store_service.py`](./poc/services/session_store_service.py) stores up to **25 conversation threads per signed-in user** in **Cloud Firestore** (`aaas_user_sessions`, default), **PostgreSQL** (`AAAS_STATE_BACKEND=postgres`), **Redis** (`AAAS_STATE_BACKEND=redis`), or **in-memory** (`AAAS_STATE_BACKEND=memory`), with automatic local fallback caching.
* **Full Session Lifecycle Controls**: Users can start a **New Session**, browse and switch between saved conversations in the expandable **History** drawer (with auto-derived titles, message counts, and last consulted specialist), **Reset** the active thread, delete individual sessions, or **Clear All** sessions.

### 3. Google Visual Identity UI & Theme Controls
* **Material 3 4-Color Design System**: Uses the official Google Visual Identity palette (`#4285F4` Blue, `#EA4335` Red, `#FBBC04` Yellow, `#34A853` Green), `Google Sans` typography, custom **Atlas Holding Cloud** SVG branding, and streamlined `A2A v1.0` chrome.
* **Left Sidebar Navigation Rail (4 Dedicated Views)**:
  1. **AaaS Command Center**: Compact 4-Metric Status Strip, action-first Center Stage (Incident Approval & Atlas Chat), and collapsible `How It Works (Step 1–3)` and `Key Features` drawers.
  2. **Specialist Roster**: Live status of all 7 domain specialists (2 live ADK agents + 5 deterministic execution harnesses).
  3. **Audit & Events**: Chronological tracker of detected anomalies, assigned specialists, approving users, timestamps, and `jit-wif-*` token IDs.
  4. **View Logs & A2A**: Live telemetry stream paired with the real-time A2A JSON-RPC 2.0 message ledger.
* **Auto / Dark / Light Theme Switcher**: Icon-only segmented control supporting system preference (Auto gear icon via `prefers-color-scheme: dark`), Dark mode (Moon icon), and Light mode (rayed Sun SVG icon).

### 4. Live Telemetry Triage & Edge Noise Filtering
* **`cloud-sql-proxy` & OTel Log Capture**: Captures `logName:"cloud-sql-proxy"` connectivity failures (`CLOUDSQL_PROXY_CONNECTION_TIMEOUT`, `Connection Refused`, `timeout expired`, `Re-occured`, port `3306` / direct-IP timeouts) alongside `cloudsql_database` `FATAL`/`ERROR` logs, as well as normalized OpenTelemetry / Grafana Loki / Prometheus Alertmanager anomalies.
* **Edge Noise Suppression & Deduplication**: Suppresses routine GKE Composer noise, `GCEGuestAgent`, `ops-agent-health`, `LogPingOpsAgent`, healthcheck probes (`kube-probe/`, `ELB-HealthChecker`), deprecation warnings, and internal `AAAS_AUDIT_EVENT` loops at `$0` LLM cost while deduplicating burst stack traces by `signature_key`.
* **Newest-First Anomaly Prioritization**: `POST /api/poll-cloud-logging` sorts live anomalies by **newest timestamp descending** (with database priority tie-breaking) so freshly occurring incidents surface immediately.

---

## 1. System Architecture

The architecture enforces strict decoupling via **Ports & Adapters** between the **AaaS Control Plane** (multi-tenant orchestration, model-agnostic inference, OIDC auth broker, pluggable state/locks, and Command Center UI) and the **Target Cloud Data Planes** (GCP, AWS, Azure, Kubernetes/OpenShift, or Local Docker).

```text
+---------------------------------------------------------------------------------------------------------------+
|                                   CLOUD-AGNOSTIC AAAS CONTROL PLANE                                           |
|                     (Deployable on GCP Cloud Run | AWS EKS | Azure AKS | GKE | OpenShift | Docker)            |
|                                                                                                               |
|   +---------------------------------------+      2. REASONING (A2A 1.0 JSON-RPC)   +----------------------+   |
|   |       Multi-Tenant UI Dashboard       |<-------------------------------------->|  ADK Multi-Agent     |   |
|   |  * Google SSO / IAP / Generic OIDC    |                                        |  Core (Triad)        |   |
|   |  * Firestore / Postgres / Redis State |        3. PRE-FLIGHT + HITL GATE       |  * Frontline Watcher |   |
|   |  * Incident Triage & RCA / Chat       |--------------------------------------->|  * Atlas Orchestrator|   |
|   |  * Cloud Outage Gate & JIT Minting    |   (Vertex/Gemini/Bedrock/Azure/OpenAI) |  * Specialist Roster |   |
|   +---------------------------------------+                                        +----------+-----------+   |
|                                                                                               |               |
|                                                                                    4. CONTROLLED EXECUTION    |
|                                                                                    (GCP WIF / AWS STS /       |
|                                                                                     Azure Entra + GitOps PR)  |
+-----------------------------------------------------------------------------------------------|---------------+
                                                ^                                               |
                                                | 1. INGESTION & DETECTION                      |
+-----------------------------------------------|-----------------------------------------------|---------------+
|                                               |                                               v               |
|   +---------------------------------------+   |                                    +----------------------+   |
|   |    Pluggable Telemetry Ingestion      |---+                                    |   Remediation Layer  |   |
|   |  * GCP Cloud Logging Adapter (default)|                                        |  * OPA / SAIF Guard  |   |
|   |  * OTel / Loki / Prometheus Adapter   |                                        |  * .tflock / Redis   |   |
|   |  * Cloud Status Feed Pre-Flight       |                                        |  * GitOps PR Builder |   |
|   +---------------------------------------+                                        +----------+-----------+   |
|                       ^                                                                       |               |
|                       |                                                                       |               |
|                       +-------------------- 5. POST-VERIFICATION (45s + 3m + 45m Freeze) -----+               |
|                                                                                                               |
|   +-------------------------------------------------------------------------------------------------------+   |
|   |     Target Multi-Cloud Data Planes: GCP (Cloud SQL/GCE/GKE) | AWS (RDS/EC2/EKS) | Azure (SQL/VM/AKS)  |   |
|   +-------------------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------------------+
```

---

## 2. The Agent Triad Lifecycle

```text
System Incident Occurs
│
▼
1. INGESTION & DETECTION
TelemetryIngestionAdapter (GCP Cloud Logging or OTel/Loki/Prometheus) ingests normalized anomalies
with SAIF sanitization & edge noise filtering.
│
▼
2. REASONING, GITOPS CORRELATION & RCA
Atlas correlates anomalies with Golden Playbooks (RAG), checks Cloud Provider Regional Status Feeds,
and delegates deep read-only triage over A2A to ADK Specialists (Database Query Introspection + GitOps Commit Correlation).
│
▼
3. HUMAN-IN-THE-LOOP APPROVAL & OUTAGE GATE
AaaS Command Center authenticates the operator via Google SSO/IAP/OIDC, blocks mutations if an active
regional cloud outage is detected, and gates execution behind "I accept" + a 15-min federated JIT token.
│
▼
4. CONTROLLED EXECUTION & BIDIRECTIONAL GITOPS
Agent Harness enforces OPA policy checks, 10-min distributed locks (.tflock / Redis TTL), Terraform dry-run validation,
deterministic specialist execution, and emits Bidirectional GitOps Reconciliation PR payloads.
│
▼
5. STABILIZATION & POST-VERIFICATION
Two-stage verification runs a 45s direct API liveness probe + 3-minute monitoring window + 45-minute hysteresis freeze,
with Stateless Canary Auto-Rollback or Stateful Safe-Mode Isolation.
```

---

## 3. Control Plane REST & A2A API Reference

All Control Plane endpoints are served by [`poc/app.py`](./poc/app.py):

| Category | Endpoint | Description |
| :--- | :--- | :--- |
| **Health & Runtime Probe** | `GET /healthz` | Lightweight liveness/readiness probe for Docker Compose, Kubernetes, OpenShift, and Cloud Run; reports active `state_backend`, `lock_backend`, `telemetry_provider`, and `llm_provider`. |
| **Authentication (SSO / OIDC / IAP)** | `GET /api/auth/me`<br>`POST /api/auth/google`<br>`POST /api/auth/config`<br>`POST /api/auth/logout` | Detects GCP IAP headers, verifies Google OAuth 2.0 access tokens / Google ID Tokens / enterprise OIDC JWTs (`401` on invalid tokens), sets runtime OAuth Client ID, and manages sign-out. |
| **Telemetry, Pre-Flight & State** | `GET /api/state`<br>`POST /api/poll-cloud-logging`<br>`GET /api/preflight/cloud-status`<br>`GET /api/harness/status`<br>`GET /api/audit-events` | Returns live triad state, polls newest-first anomalies, checks regional cloud provider outages (`?cloud=gcp\|aws\|azure&region=...`), reports Agent Harness guardrails, and lists immutable audit trail records. |
| **Incident Triage & HITL** | `POST /api/incidents/{id}/chat`<br>`POST /api/incidents/{id}/approve`<br>`POST /api/incidents/{id}/skip`<br>`POST /api/incidents/{id}/reopen` | Interactive pre-approval Q&A with Atlas, outage-gated HITL approval & JIT-gated execution, manual skip, and reopen lifecycle controls. |
| **Direct Atlas Chat & IaC** | `POST /api/atlas/chat`<br>`POST /api/atlas/chat/deploy-terraform`<br>`POST /api/atlas/chat/reset` | On-demand Atlas chat across all 4 operational scenarios, harnessed Terraform `.tf` execution, and active session message reset. |
| **Multi-Session History** | `GET /api/atlas/sessions`<br>`POST /api/atlas/sessions/new`<br>`POST /api/atlas/sessions/{id}/select`<br>`DELETE /api/atlas/sessions/{id}`<br>`DELETE /api/atlas/sessions` (`POST /api/atlas/sessions/clear`) | Full per-user multi-session chat history management backed by the active `SessionStoreAdapter` (`firestore`, `postgres`, `redis`, or `memory`). |
| **A2A Protocol (1.0)** | `GET /a2a/{agent_id}/.well-known/agent.json`<br>`POST /a2a/{agent_id}` | Standard AgentCard discovery and JSON-RPC 2.0 `tasks/send` dispatch for `log-watcher-agent` (`scan_cloud_logging`, `verify_post_remediation`, `check_cloud_provider_status`), `lead-orchestrator-agent`, and `gke-assist-agent` (plus `/healthz`, `/.well-known/agent.json`, `/diagnose`, and `/a2a` on the standalone ADK Database and Infra agents). |

---

## 4. Environment Configuration Reference

All cloud-agnostic adapters default to GCP Cloud Run compatibility when unset. See [`.env.example`](./.env.example) for a complete zero-cloud local template:

| Category | Variable | Supported Values / Default | Purpose |
| :--- | :--- | :--- | :--- |
| **Target Cloud** | `CLOUD_PROVIDER` | `gcp` *(default)* \| `aws` \| `azure` | Selects active `DatabaseCloudAdapter` and `ComputeCloudAdapter` strategy |
| **Telemetry** | `AAAS_TELEMETRY_PROVIDER` | `gcp` *(default)* \| `otel` | Switches between GCP Cloud Logging and OpenTelemetry / Loki / Prometheus |
| | `AAAS_OTEL_LOKI_URL` / `AAAS_PROMETHEUS_ALERTMANAGER_URL` | URL (optional) | Upstream Grafana Loki and Prometheus Alertmanager pull endpoints |
| **State & Locks** | `AAAS_STATE_BACKEND` | `firestore` *(default)* \| `postgres` \| `redis` \| `memory` | Selects per-user session persistence adapter |
| | `AAAS_LOCK_BACKEND` | `local` *(default)* \| `redis` \| `memory` | Selects distributed `.tflock` & 45-min hysteresis lock adapter |
| | `AAAS_POSTGRES_DSN` / `AAAS_REDIS_URL` | DSN / Redis URL | Connection strings for PostgreSQL session store and Redis locks |
| **LLM Routing** | `AAAS_LLM_PROVIDER` | `vertex` *(default)* \| `gemini` \| `bedrock` \| `azure_openai` \| `openai` \| `litellm` | Selects LLM backend for Atlas and ADK specialists |
| | `AAAS_LLM_MODEL` / `AAAS_LLM_API_BASE` / `AAAS_LLM_API_KEY` | `gemini-2.5-flash` *(default)* | Model name and OpenAI/LiteLLM/Ollama proxy credentials |
| | `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_DEPLOYMENT` | Azure OpenAI config | Azure OpenAI Service routing parameters |
| | `AWS_BEDROCK_REGION` / `AWS_REGION` | `us-east-1` | AWS Bedrock & AWS SDK target region |
| **Identity / SSO** | `AAAS_AUTH_PROVIDER` | `gcp` *(default)* \| `oidc` | Selects GCP/Google or generic enterprise OIDC auth broker mode |
| | `GOOGLE_OAUTH_CLIENT_ID` | OAuth 2.0 Web Client ID | Enables Google Identity Services browser sign-in |
| | `AAAS_OIDC_JWKS_URL` / `AAAS_OIDC_ISSUER` / `AAAS_OIDC_AUDIENCE` | OIDC IdP metadata | Generic RS256/ES256 OIDC JWT verification (Okta, Auth0, Keycloak, Entra ID) |
| **Phase 4 SRE** | `AAAS_CLOUD_STATUS_MODE` / `AAAS_CLOUD_STATUS_FAIL_CLOSED` | `live` *(default)* \| `offline` / `false` | Controls cloud provider regional outage pre-flight check behavior |
| | `AAAS_DB_READONLY_DSN` | PostgreSQL DSN *(opt-in)* | Enables direct `READ ONLY` `pg_stat_activity` / `pg_stat_statements` queries |
| | `AAAS_GITOPS_REPO` / `AAAS_GITOPS_BASE_BRANCH` | `harisankar/AgentTriad` / `main` | Target repository & branch for Bidirectional GitOps Reconciliation PRs |

---

## 5. Repository Structure

```text
AgentTriad/
├── .env.example                                   # Zero-cloud local / any-VM configuration template
├── docker-compose.yml                             # 5-service zero-cloud local stack (Control Plane, DB/Infra Agents, Postgres, Redis)
├── deploy/
│   └── helm/
│       └── agent-triad/                           # Portable Kubernetes & OpenShift Helm v2 Chart
│           ├── Chart.yaml
│           ├── values.yaml                        # Multi-cloud values (EKS, AKS, GKE, OpenShift, managed DBs, LLM routing)
│           ├── README.md                          # One-click Helm install guides for EKS, AKS, GKE & OpenShift
│           └── templates/                         # Deployments, Services, ServiceAccount (IRSA/AKS/GKE WI), Ingress, OpenShift Route, HPA, NetworkPolicy, Postgres, Redis, ConfigMap, Secret
├── poc/                                           # AaaS Control Plane & Command Center
│   ├── app.py                                     # FastAPI server (/healthz, Auth, Sessions, Pre-Flight, Incidents, A2A)
│   ├── requirements.txt                           # Runtime dependencies (FastAPI, ADK, psycopg, redis, httpx, google-auth)
│   ├── providers/                                 # Cloud-Agnostic Ports & Adapters Layer
│   │   ├── base_telemetry.py                      # TelemetryIngestionAdapter ABC + OTel anomaly normalizer
│   │   ├── base_state.py                          # SessionStoreAdapter & DistributedLockAdapter ABCs
│   │   ├── base_cloud.py                          # DatabaseCloudAdapter & ComputeCloudAdapter ABCs
│   │   ├── cloud_factory.py                       # Multi-cloud strategy factory (gcp | aws | azure)
│   │   ├── model_router.py                        # Model-Agnostic LLM Router (Vertex, Gemini, Bedrock, Azure OpenAI, OpenAI, LiteLLM)
│   │   ├── gcp/
│   │   │   ├── cloud_logging_adapter.py           # GCPCloudLoggingAdapter (Cloud Logging + cloud-sql-proxy + edge filter)
│   │   │   ├── firestore_session_adapter.py       # GCPFirestoreSessionAdapter (Cloud Firestore + local JSON fallback)
│   │   │   └── cloud_adapters.py                  # GCPDatabaseCloudAdapter (Cloud SQL) & GCPComputeCloudAdapter (GCE)
│   │   ├── aws/
│   │   │   └── cloud_adapters.py                  # AWSDatabaseCloudAdapter (RDS) & AWSComputeCloudAdapter (EC2)
│   │   ├── azure/
│   │   │   └── cloud_adapters.py                  # AzureDatabaseCloudAdapter (Azure SQL) & AzureComputeCloudAdapter (VMs)
│   │   └── generic/
│   │       ├── otel_loki_adapter.py               # OTelLokiLogAdapter (OTLP, Grafana Loki, Prometheus Alertmanager)
│   │       ├── postgres_session_adapter.py        # PostgresSessionAdapter (psycopg/psycopg2/SQLAlchemy)
│   │       ├── redis_lock_adapter.py              # RedisLockAdapter (.tflock + hysteresis TTL) & RedisSessionAdapter
│   │       └── memory_state_adapters.py           # LocalFileLockAdapter, InMemoryLockAdapter & InMemorySessionAdapter
│   ├── agents/
│   │   ├── lead_orchestrator.py                   # Atlas • Model-Agnostic ADK Root Orchestrator + 7-Agent Roster Router
│   │   ├── watcher_agent.py                       # Heartbeat & Telemetry Agent (Edge Filter, SAIF, Cloud Status Pre-Flight)
│   │   ├── gke_assist_agent.py                    # Deterministic Specialist Execution Hub (A2A Worker)
│   │   └── a2a_protocol.py                        # A2A 1.0 AgentCard & JSON-RPC 2.0 Hub
│   ├── services/
│   │   ├── auth_broker.py                         # CloudAuthBroker (OIDC JWT, Google SSO, JIT tokens, GCP/AWS/Azure WIF)
│   │   ├── cloud_status_service.py                # Multi-cloud regional outage pre-flight gate (GCP / AWS / Azure feeds)
│   │   ├── gitops_correlator.py                   # Git/CI deployment correlator & Bidirectional GitOps PR payload builder
│   │   ├── db_query_introspection.py              # Strictly read-only pg_stat_activity & slow-query introspection engine
│   │   ├── session_store_service.py               # Pluggable multi-backend session store facade
│   │   ├── cloud_logging_service.py               # Pluggable telemetry ingestion facade
│   │   ├── agent_harness.py                       # SAIF IPI guard, distributed locks, OPA gate, TF dry-run, Watchdog
│   │   ├── playbook_rag.py                        # Embedding / BM25 Golden Playbooks RAG
│   │   ├── gke_remediator.py                      # Deterministic REST / CLI remediation engine
│   │   └── gcp_auth.py                            # Backward-compatible GCP ADC & OIDC token helpers (via auth_broker)
│   ├── static/index.html                          # Material 3 Google Visual Identity AaaS Command Center UI
│   ├── test_poc.py                                # End-to-end integration test suite (all 5 phases + live GCP compat)
│   └── Dockerfile                                 # Control Plane container image
├── agents/
│   ├── database_agent/                            # Standalone Live ADK Database Specialist Agent
│   │   ├── agent.py                               # Multi-cloud DB strategy tools + read-only query introspection
│   │   ├── server.py                              # FastAPI /healthz, /.well-known/agent.json, /diagnose, /a2a
│   │   └── Dockerfile
│   └── infra_agent/                               # Standalone Live ADK Infra Specialist Agent
│       ├── agent.py                               # Multi-cloud Compute strategy tools + GitOps deployment correlator
│       ├── server.py                              # FastAPI /healthz, /.well-known/agent.json, /diagnose, /a2a
│       └── Dockerfile
├── terraform/                                     # Reproducible GCP Cloud Run IaC Stack (Cloud Run v2, IAM, Cloud Build)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── versions.tf
├── architecture.svg                               # Reference architecture diagram
├── a3s-flow.html                                  # Interactive AaaS architectural workflow diagram
├── visualizer.html                                # Interactive platform visualizer
└── AaaS_Google Cloud_WhitePaper.pdf               # Reference Google Cloud AaaS Whitepaper
```

---

## 6. Deployment Options, Local Development & Testing

### Option A — Zero-Cloud Local / Any-VM Stack (Docker Compose)
Run the complete 5-service stack (`control-plane` on `:8080`, `db-agent` on `:8081`, `infra-agent` on `:8082`, `postgres:16-alpine`, `redis:7-alpine`) with **zero cloud accounts or API keys required**:
```bash
cp .env.example .env
docker compose up --build
```
Verify readiness via `curl http://localhost:8080/healthz` and open `http://localhost:8080`.

### Option B — Portable Kubernetes & OpenShift Deployment (Helm Chart)
Deploy one-click to **AWS EKS**, **Azure AKS**, **Google GKE**, or **Red Hat OpenShift** using [`deploy/helm/agent-triad/`](./deploy/helm/agent-triad/) (see [`deploy/helm/agent-triad/README.md`](./deploy/helm/agent-triad/README.md) for full AWS/Azure/GKE/OpenShift examples):
```bash
# Example: AWS EKS (IRSA + Bedrock Claude + ALB Ingress)
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set global.cloudProvider=aws \
  --set global.awsRegion=us-east-1 \
  --set serviceAccount.eksRoleArn=arn:aws:iam::123456789012:role/agent-triad-irsa \
  --set llm.provider=bedrock \
  --set llm.model=anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --set ingress.enabled=true --set ingress.className=alb

# Example: Red Hat OpenShift (restricted-v2 SCC + TLS Route)
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set openshift.enabled=true \
  --set postgres.enabled=false \
  --set postgres.externalDsn="postgresql://aaas:<password>@<pg-host>:5432/agent_triad"
```

### Option C — GCP Cloud Run Serverless Stack (Terraform)
```bash
cd terraform
GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" ../.venv/bin/terraform apply -auto-approve
```

### Run the Control Plane Directly in Python (Dev Mode)
```bash
cd poc
../.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```
Open `http://localhost:8080` to access the AaaS Command Center UI. Set `GOOGLE_OAUTH_CLIENT_ID` (optional) to enable real Google Identity Services popup sign-in, or configure it at runtime via the Sign-In modal.

### Execute the End-to-End Test Suite
[`poc/test_poc.py`](./poc/test_poc.py) validates the entire platform stack — Google Visual Identity UI & theme switcher, Google SSO / OIDC JWT verification & dynamic identity, all 4 Atlas operational scenarios, multi-backend session lifecycle (Firestore / PostgreSQL / Redis), OPA external-resource guardrails (`testdbconnect`), A2A AgentCards, live Cloud Logging & OTel/Loki ingestion, Model-Agnostic LLM routing, AWS/Azure/GCP specialist cloud strategies, Phase 4 Cloud Provider Outage pre-flight blocking, GitOps deployment correlation & Bidirectional PR payloads, strictly read-only DB query introspection, Phase 5 `/healthz`, Docker Compose & Helm chart integrity, and standalone ADK specialist agents:
```bash
.venv/bin/python poc/test_poc.py
```

---
