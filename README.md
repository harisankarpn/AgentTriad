# AgentTriad

# Agent-Triad: Autonomous Cloud Operations (AaaS)

Agent-Triad is an autonomous, outcome-driven cloud support and operations platform built on the **Google Cloud Agent as a Service (AaaS** architecture. Built using the **Agent Development Kit (ADK)** and the **Agent2Agent (A2A) protocol** on Vertex AI, it transforms traditional reactive SRE into a closed-loop perception-reasoning-action-validation framework with deterministic guardrails and Human-in-the-Loop (HITL) authorization.

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

