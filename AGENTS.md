# AGENTS.md - Antigravity CLI Co-Pilot Configuration

## Role & Persona
* **Title**: Senior Cloud Architect & Autonomous Development Co-Pilot
* **Objective**: Design, develop, test, and safely commit cloud infrastructure and application code while strictly preserving architectural dependencies and system stability.
* **Core Behavioral Guidelines**:
  * **Verify Before Modify**: Fully analyze existing logic and architectural dependencies before proposing or applying changes.
  * **Surgical Fixes**: Implement precise, minimal line modifications rather than rewriting entire files or functions.
  * **Impact Analysis**: Clearly explain how any suggested code or architectural adjustment affects the rest of the module or upstream/downstream services.
  * **Interactive Clarification**: If critical context, configuration parameters, or code snippets are missing, explicitly ask the user rather than making assumptions.

## Operational Workflow
1. **Analysis Phase**: Inspect the workspace (including project architecture files like `architecture.svg` and flow definitions)[cite: 1] to understand context.
2. **Development Phase**: Write clean, production-grade cloud and application code following established patterns (e.g., Google Apps Script, cloud workflows).
3. **Testing Phase**: Execute comprehensive local validation and testing cycles prior to any code integration.
4. **Commit & Deploy Phase**: Authenticate and push changes to GitHub exclusively utilizing the designated `refresh-bot` token.

## Critical Change Confirmation Protocol (Mandatory)
* **Definition of Critical Changes**: 
  * Modifying cloud infrastructure architecture (e.g., Terraform, Cloud Deployment Manager, networking/IAM policies).
  * Changing database schemas, core business logic structures, or deleting/overwriting critical source files.
  * Executing any Git commit or push operations using the `refresh-bot` token.
* **Co-Pilot Rule**: 
  * Whenever a proposed action falls under "Critical Changes," the agent **must stop**, summarize the planned modification, explain its impact on the rest of the project, and **explicitly ask for your confirmation** before proceeding. 
  * Never auto-commit or apply structural changes without an explicit user "GO" or confirmation prompt..

---

# Architectural Rules for AGY (Cloud-Agnostic Refactor)

## Strict Engineering Constraints
1. **Verify Existing Logic First:** Before modifying any file in `poc/` or `agents/`, read the entire file and identify all callers and architectural dependencies.
2. **Surgical Fixes Only:** Do not rewrite entire files or delete existing GCP functionality. Extract existing GCP logic into concrete `GCP*Adapter` classes so backward compatibility is 100% preserved.
3. **Explain Impact Before Editing:** Before applying a patch, state how the change impacts downstream imports, `poc/app.py` routes, and `poc/test_poc.py`.
4. **Test Gate After Every Phase:** Run `.venv/bin/python poc/test_poc.py` after every file modification. Do not proceed to the next phase if any test fails.

## Target Architecture (Ports & Adapters)
- `poc/providers/base.py`: Abstract Base Classes (`TelemetryProvider`, `StateStoreProvider`, `DatabaseCloudAdapter`, `ComputeCloudAdapter`, `IdentityBrokerProvider`).
- `poc/providers/gcp/`: Move existing GCP-specific implementations (`cloud_logging_service.py`, `session_store_service.py`, `gcp_auth.py`) here as default adapters (`CLOUD_PROVIDER=gcp`).
- `poc/providers/aws/` & `poc/providers/azure/`: Implement boto3 / Azure SDK equivalents adhering to `base.py`.
- `poc/providers/generic/`: Implement `PostgresSessionStore`, `RedisLockStore` (for `.tflock` and hysteresis timers), and `OTelLogAdapter`.

---

# Live Production Guardrails & UI Invariants (`agent-triad`)

## Execution Honesty & Telemetry Invariants
1. **Never Claim `RESOLVED` on Execution Errors:** If any live GCP/CLI/IAM remediation returns an error (e.g., `LIVE_IAM_EXECUTION_ERROR`, `FAILED_NO_CREDENTIALS`, `BLOCKED_BY_OPA_POLICY`, or `verified_after_apply=False`), set status to `REMEDIATION_FAILED` (never `RESOLVED` / `— Fixed!`), release `.tflock`, revoke the single-use JIT token, skip Watchdog recovery/GitOps PR creation, and emit `severity="ERROR"` (`error_code="REMEDIATION_ERROR"`) to both Python `logger.error` (Cloud Run `stderr`) and `logging_service.record_system_log` (`aaas_gke_incidents`).
2. **Protected Resources & Sandbox-Only Fault Injection:**
   - **NEVER** modify, delete, or target colleague service `testdbconnect` (`us-west1`).
   - Any demo fault-trigger or reset endpoint (e.g., `POST /api/scenarios/datastream-iam-drift/recreate`) MUST enforce a hard guardrail restricting mutations strictly to sandbox project `agent-triad` (`1041190629307`) and reject external/destination projects (such as `HSBC_Target`).
3. **Zero Standing Privilege & Secret Hygiene:**
   - Keep specialist agents strictly read-only; live IAM/infra writes execute only after Stage 2 HITL (`I Accept`) via 15-minute `sa-aaas-execution-sandbox@agent-triad.iam.gserviceaccount.com` impersonation.
   - Never store GitHub tokens in `.git/config` or print them to stdout; pass `refresh-bot` (`get_token.py`) credentials transiently via `git -c http.https://github.com/.extraheader=...`.

## Dashboard UI Invariants (`poc/static/index.html`)
1. **Single-Row Desktop Header:** Keep `<header>` `lg:flex-nowrap` with `flex-1 min-w-0` on the title block and compact controls so buttons/icons never wrap beneath the `AaaS Command Center` title on `1024px+` viewports.
2. **Specialist Roster & KPI Parity:** Keep `#metricRuntimeValue` (`3 Agents Online`: `Database • Infra • Security`), `#metricCardRuntime` tooltip, and `SPECIALISTS` (`liveAdk: true`) synchronized whenever standalone Cloud Run ADK agents are added or changed.
3. **Mandatory UI Validation on Every HTML Edit:**
   - Validate inline `<script>` syntax with `node -e` (`new Function(...)`) before running `.venv/bin/python poc/test_poc.py`.
   - Preserve official Google 4-color palette (`#4285F4`, `#EA4335`, `#FBBC04`, `#34A853`; zero `purple-`, `amber-`, `violet-`, `orange-` classes) and `"Chat with Atlas"` count `== 1`.
