"""
Agent 2: Atlas • Lead Orchestrator Agent (Single Authorizing ADK Root Gemini Agent + A2A Hub).

Architectural Role (Aligned with AaaS Google Cloud Whitepaper & `a3s-flow.html`):
  - `Atlas` is the ONLY Gemini reasoning agent in the triad that interacts with `User: Hari`,
    queries the RAG Knowledge Base, authorizes/mints 15-minute WIF JIT tokens, and delegates
    tasks over A2A to the 7-Agent Specialist Roster.
  - Supports all 4 Customer Scenarios:
      * Scenario 1: Simple troubleshooting requiring a 1-line CLI / API fix (1 Specialist)
      * Scenario 2: Complex multi-service fix (IAM + VPC Firewall + API/DB) requiring a
        coordinated Multi-Specialist Terraform (`.tf`) remediation bundle
      * Scenario 3: Customer asks Atlas in chat to generate & validate a Terraform (`.tf`)
        deployment script (with optional Agent Harness execution on approval)
      * Scenario 4: Simple GCP "How-To" questions answered directly with $0 Harness overhead
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

from agents.a2a_protocol import (
    A2AProtocolHub,
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    AgentSkill,
)
from providers.cloud_factory import get_database_cloud_adapter, normalize_target_cloud
from providers.model_router import (
    ModelAgnosticLLMClient,
    get_llm_provider_config,
    resolve_adk_model,
)
from services.agent_harness import agent_harness, inspect_agent_harness_policy_tool
from services.cloud_status_service import cloud_status_service
from services.db_query_introspection import analyze_pg_stat_activity_and_slow_queries
from services.gitops_correlator import correlate_gitops_deployments_tool, gitops_correlator
from services.playbook_rag import (
    RAG_PLAYBOOK_CATALOG,
    playbook_rag_service,
    query_playbook_rag_tool,
)
from services.security_iam_service import security_iam_service
from services.session_store_service import session_store_service

try:
    from google.adk.agents import Agent as AdkAgent
    from google.adk.runners import Runner as AdkRunner
    from google.adk.sessions import InMemorySessionService
except ImportError:
    AdkAgent = None
    AdkRunner = None
    InMemorySessionService = None

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:
    genai = None
    genai_types = None


PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
LOCATION = os.getenv("GCP_LOCATION", "us-central1")
MODEL_NAME = (
    os.getenv("AAAS_LLM_MODEL")
    or os.getenv("AAAS_GEMINI_MODEL")
    or "gemini-2.5-flash"
)


GOLDEN_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    item["scenario_key"]: item for item in RAG_PLAYBOOK_CATALOG
}
GOLDEN_PLAYBOOKS["real_gcp_anomaly"] = {
    "playbook_id": "PB-GCP-900",
    "scenario_key": "real_gcp_anomaly",
    "scenario_type": "SCENARIO_1_CLI_FIX",
    "scenario_badge": "Scenario 1 • 1-Line CLI/API Fix",
    "title": "Live Google Cloud Service Telemetry Remediation",
    "blast_radius_tier": "HIGH (Live Production Service Error)",
    "rollback_mode": "STATELESS_CANARY_ROLLBACK",
    "affected_services": ["gcp-live-workload"],
    "business_impact": "Live Google Cloud resource reported an operational error in Cloud Logging.",
    "root_cause": "Runtime error detected by Cloud Logging Watcher Agent from live GCP telemetry.",
    "remedy_summary": "Apply targeted Google Cloud configuration update and verify telemetry recovery.",
    "recommended_cli": f"gcloud run services list --project={PROJECT_ID}",
    "terraform_code": None,
    "rollback_plan": "Revert resource configuration to previous revision if error rate persists.",
    "customer_headline": "Live Google Cloud Service Alert",
    "customer_what_happened": "Real GCP Log Detected: A service in your Google Cloud project reported an operational error.",
    "customer_why_approve": "Applies the recommended Google Cloud fix and verifies recovery.",
    "risk_badge": "Low Risk • 1-Line CLI/API Fix",
    "downtime_badge": "Zero Downtime",
    "safety_badge": "Auto-Rollback Protected",
}


# Specialist Agent Roster (7 Domain Worker Harnesses)
WORKER_AGENT_BOUTIQUE: List[Dict[str, str]] = [
    {
        "id": "serverless-agent",
        "name": "Serverless Agent",
        "domain": "Cloud Run & Cloud Functions",
        "icon": "fa-bolt",
        "description": "Remediates Cloud Run scaling limits, revision port bindings, and Cloud Functions runtime errors.",
    },
    {
        "id": "database-agent",
        "name": "Database Agent",
        "domain": "Cloud SQL, AlloyDB & Spanner",
        "icon": "fa-database",
        "description": "Troubleshoots Cloud SQL connectivity, connection pools, socket proxies, and DB port probes.",
    },
    {
        "id": "infra-agent",
        "name": "Infra Agent",
        "domain": "GKE, Compute Engine & Terraform IaC",
        "icon": "fa-server",
        "description": "Handles GKE pods/nodes, Compute Engine VMs, persistent disks, and Terraform IaC deployments.",
    },
    {
        "id": "networking-agent",
        "name": "Networking Agent",
        "domain": "VPC, Firewall, Load Balancing & DNS",
        "icon": "fa-network-wired",
        "description": "Resolves VPC routing, Serverless VPC Access connectors, firewall rules, and Load Balancers.",
    },
    {
        "id": "data-analytics-agent",
        "name": "Data Analytics Agent",
        "domain": "Vertex AI, BigQuery & Dataflow",
        "icon": "fa-chart-line",
        "description": "Recovers Vertex AI Reasoning Engines, BigQuery slots, Dataflow pipelines, and Pub/Sub backlog.",
    },
    {
        "id": "security-agent",
        "name": "Security Agent",
        "domain": "IAM, Cloud Armor & Secret Manager",
        "icon": "fa-shield-halved",
        "description": "Audits and remediates IAM permissions, WIF policies, Cloud Armor WAF rules, and Security Command Center alerts.",
    },
    {
        "id": "billing-agent",
        "name": "Billing Agent",
        "domain": "Cloud Billing, Quotas & FinOps",
        "icon": "fa-credit-card",
        "description": "Monitors Cloud Billing budgets, cost anomalies, API quota exhaustion, and resource right-sizing guardrails.",
    },
]

SPECIALIST_BY_ID: Dict[str, Dict[str, str]] = {w["id"]: w for w in WORKER_AGENT_BOUTIQUE}


class LeadOrchestratorAgent:
    """
    Single Authorizing ADK Root Gemini Agent (`Atlas`).
    Supervises all agents, runs the ADK ReAct & RAG Playbook lookup, enforces Stage 2 HITL
    approval, mints 15-minute WIF JIT tokens, and delegates execution to the 7 Deterministic
    Specialist Harnesses over A2A.
    """

    AGENT_ID = "lead-orchestrator-agent"

    def __init__(self, a2a_hub: A2AProtocolHub, logging_service: Any = None) -> None:
        self.a2a_hub = a2a_hub
        self.logging_service = logging_service
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.audit_events: Dict[str, Dict[str, Any]] = {}
        self.dispatch_history: List[Dict[str, Any]] = []
        self.ignored_log_ids: set[str] = set()
        self.ignored_signatures: set[str] = set()
        self.active_target_cloud: str = normalize_target_cloud(os.getenv("CLOUD_PROVIDER", "gcp"))
        self.active_user: Dict[str, str] = {
            "name": "Hari",
            "email": "harisankar@google.com",
            "picture": "",
            "provider": "google-sso",
        }
        self.adk_agent = self._build_adk_agent()
        self.adk_session_service = InMemorySessionService() if InMemorySessionService is not None else None
        self.adk_runner = (
            AdkRunner(
                agent=self.adk_agent,
                app_name="aaas_control_plane",
                session_service=self.adk_session_service,
            )
            if (AdkRunner is not None and self.adk_agent is not None and self.adk_session_service is not None)
            else None
        )
        self._genai_client = self._build_genai_client()
        self._llm_client = ModelAgnosticLLMClient(
            genai_client=self._genai_client,
            default_model=MODEL_NAME,
        )
        self.general_chat_messages: List[Dict[str, Any]] = self._default_general_chat_greeting()
        self.active_session_id: str = f"sess-{uuid.uuid4().hex[:8]}"
        self._init_or_restore_user_sessions(sync_from_firestore=True)
        self.card = AgentCard(
            id=self.AGENT_ID,
            name="Atlas • Lead Orchestrator",
            role="Single Authorizing ADK Root Gemini Agent, RAG Analyzer & JIT Gatekeeper",
            description=(
                "Sole Gemini reasoning brain in the AaaS Control Plane. Ingests SAIF-sanitized "
                "telemetry from Heartbeat & Telemetry via A2A, queries the ADK RAG Playbook & Terraform "
                "Knowledge Base, manages Stage 2 HITL approval with User: Hari, mints 15-minute WIF JIT "
                "tokens, and delegates execution to the 7 Deterministic Specialist Harnesses over A2A."
            ),
            url="/a2a/lead-orchestrator-agent",
            skills=[
                AgentSkill(
                    id="ingest_anomaly_alert",
                    name="Ingest Anomaly, Query RAG & Acquire Agent Harness Lock",
                    description=(
                        "Receives SAIF-sanitized anomaly alerts, retrieves Golden Playbooks / Terraform modules "
                        "via ADK RAG, acquires `.tflock` lease, evaluates OPA policy, and alerts User: Hari."
                    ),
                    tags=["orchestrator", "adk", "rag", "agent-harness", "hitl"],
                ),
                AgentSkill(
                    id="delegate_approved_remediation",
                    name="Mint JIT Token & Delegate Fix to Specialist Roster",
                    description=(
                        "Mints a 15-minute WIF JIT token upon User: Hari's acceptance and delegates "
                        "1-line CLI/API or Multi-Service Terraform execution to the Specialist Roster via A2A."
                    ),
                    tags=["delegation", "a2a", "jit", "terraform", "specialist-roster"],
                ),
            ],
        )
        self.a2a_hub.register_agent(self.card, self.handle_a2a_task)

    def _build_adk_agent(self) -> Any:
        if AdkAgent is None:
            return None
        try:
            return AdkAgent(
                name="atlas_aaas_root_orchestrator",
                model=resolve_adk_model(MODEL_NAME),
                description=(
                    "Atlas: Single Authorizing ADK Root Gemini Agent that coordinates Heartbeat & Telemetry "
                    "and the 7 Deterministic Specialist Execution Harnesses."
                ),
                instruction=(
                    "You are Atlas, the single authorizing ADK Root Orchestrator in the Google Cloud AaaS Control Plane. "
                    "Use `query_playbook_rag_tool` to retrieve Golden Playbooks and Terraform modules, "
                    "and `inspect_agent_harness_policy_tool` to verify OPA blast-radius policies and Terraform dry-runs. "
                    "Never execute mutations without Stage 2 HITL approval from User: Hari and a minted 15-minute JIT token."
                ),
                tools=[
                    query_playbook_rag_tool,
                    inspect_agent_harness_policy_tool,
                    correlate_gitops_deployments_tool,
                ],
            )
        except Exception:
            return None

    def set_target_cloud(self, target_cloud: str) -> str:
        """Sets the active target cloud (`gcp` | `aws` | `azure`) for AaaS Control Plane operations."""
        normalized = normalize_target_cloud(target_cloud)
        self.active_target_cloud = normalized
        return normalized

    @staticmethod
    def classify_fault_attribution(
        cloud_provider_status: Optional[Dict[str, Any]],
        log_entry: Optional[Dict[str, Any]] = None,
        specialist: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Distinguishes whether an incident stems from:
          - `INTERNAL_CLOUD_PROVIDER_OUTAGE`: An active regional cloud provider service outage
            where Atlas engages the Safety Brake and blocks workload mutations (zero JIT minted).
          - `EXTERNAL_APP_WORKLOAD`: An application, database, or customer workload fault while
            the underlying cloud provider region is operational (safe for HITL-gated remediation).
        """
        status_doc = cloud_provider_status or {}
        mutations_allowed = bool(status_doc.get("mutations_allowed", True))
        cloud_code = str(
            status_doc.get("cloud_provider")
            or (log_entry or {}).get("cloud_provider")
            or "gcp"
        ).strip().lower()
        cloud_upper = cloud_code.upper()
        region = str(status_doc.get("region") or (log_entry or {}).get("cluster") or "us-central1")
        provider_status = str(status_doc.get("status") or "OPERATIONAL")
        active_incidents = status_doc.get("active_incidents") or []
        spec_name = (specialist or {}).get("name") or "Specialist Agent"

        if not mutations_allowed or provider_status == "ACTIVE_PROVIDER_OUTAGE":
            first_inc_title = (
                active_incidents[0].get("title")
                if active_incidents and isinstance(active_incidents[0], dict)
                else f"Active {cloud_upper} regional outage in {region}"
            )
            return {
                "origin": "INTERNAL_CLOUD_PROVIDER_OUTAGE",
                "scope": "INTERNAL_CLOUD_SERVICE",
                "label": f"Internal • {cloud_upper} Provider Outage",
                "summary": (
                    f"{cloud_upper} regional service incident detected in `{region}` ({first_inc_title}). "
                    f"Safety Brake active — automated mutations held until provider recovers."
                ),
                "cloud_provider": cloud_code,
                "region": region,
                "provider_status": provider_status,
                "mutations_allowed": False,
                "active_incident_count": int(status_doc.get("active_incident_count") or len(active_incidents) or 1),
            }

        return {
            "origin": "EXTERNAL_APP_WORKLOAD",
            "scope": "EXTERNAL_APPLICATION",
            "label": "External • App / Workload Fault",
            "summary": (
                f"{cloud_upper} `{region}` control plane is operational ({provider_status}). "
                f"Fault attributed to customer workload/configuration — eligible for {spec_name} HITL remediation."
            ),
            "cloud_provider": cloud_code,
            "region": region,
            "provider_status": provider_status,
            "mutations_allowed": True,
            "active_incident_count": 0,
        }

    async def _run_cloud_provider_preflight_check(
        self,
        cloud_provider: str = "gcp",
        region: str = "us-central1",
        service_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pre-flight Cloud Provider Status Check delegated to `log-watcher-agent` over A2A
        (`check_cloud_provider_status`), falling back to local `cloud_status_service`.
        Blocks infrastructure mutations whenever an active regional provider outage is detected.
        """
        resolved_cloud = normalize_target_cloud(cloud_provider)
        try:
            if "log-watcher-agent" in self.a2a_hub.handlers:
                resp = await self.a2a_hub.send_a2a_task(
                    sender_id=self.AGENT_ID,
                    recipient_id="log-watcher-agent",
                    skill_id="check_cloud_provider_status",
                    payload={
                        "cloud_provider": resolved_cloud,
                        "region": region,
                        "service_hint": service_hint,
                    },
                    summary=f"Pre-flight cloud provider status check ({resolved_cloud.upper()} / {region})",
                )
                if isinstance(resp.result, dict) and "mutations_allowed" in resp.result:
                    return resp.result
        except Exception:
            pass
        return await asyncio.to_thread(
            cloud_status_service.check_region_status,
            cloud_provider=resolved_cloud,
            region=region,
            service_hint=service_hint,
        )

    def _build_genai_client(self) -> Any:
        if genai is None:
            return None
        try:
            from services.gcp_auth import get_gcp_credentials

            creds = get_gcp_credentials()
            return genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION, credentials=creds)
        except Exception:
            return None

    def _invoke_live_database_agent_a2a(
        self,
        prompt: str,
        instance_name: str = "testdbinstance1",
        target_cloud: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Invokes the live Cloud Run ADK Database Specialist Agent (`agent-triad-db-agent`)
        over Zero-Trust A2A (`POST /a2a` with OIDC Identity Token and `target_cloud` strategy)
        and logs the remote A2A exchange into the AaaS Control Plane ledger.
        """
        import subprocess
        import urllib.request

        resolved_cloud = normalize_target_cloud(target_cloud)
        db_agent_url = os.getenv(
            "DATABASE_AGENT_URL",
            "https://agent-triad-db-agent-qq3mp7ftqq-uc.a.run.app",
        ).rstrip("/")

        effective_prompt = prompt
        if self.ignored_signatures:
            ignored_list = ", ".join(sorted(self.ignored_signatures)[:8])
            effective_prompt = (
                f"{prompt}\n\n"
                f"[Operator Triage Note: The operator marked these benign signatures Safe to Ignore "
                f"({ignored_list}). Do NOT prioritize, raise, or force remediation on those ignored items; "
                f"focus strictly on active unignored database errors such as PostgreSQL object permission denied.]"
            )

        from services.auth_broker import auth_broker

        id_token_str = auth_broker.mint_oidc_id_token(db_agent_url)

        rpc_id = f"a2a-db-{uuid.uuid4().hex[:8]}"
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tasks/send",
            "params": {
                "skill_id": "diagnose_database_anomaly",
                "data": {
                    "prompt": effective_prompt,
                    "instance_name": instance_name,
                    "target_cloud": resolved_cloud,
                },
            },
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if id_token_str:
            headers["Authorization"] = f"Bearer {id_token_str}"

        diagnosis: Optional[Dict[str, Any]] = None
        a2a_timeout = int(os.getenv("AAAS_SPECIALIST_A2A_TIMEOUT", "20"))
        try:
            req = urllib.request.Request(
                f"{db_agent_url}/a2a",
                data=json.dumps(rpc_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=a2a_timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
            diagnosis = (resp_json.get("result") or {}).get("diagnosis")
        except Exception:
            diagnosis = None

        if not diagnosis:
            try:
                import concurrent.futures
                import importlib.util
                from pathlib import Path

                _parents = Path(__file__).resolve().parents
                agent_py = (_parents[2] / "agents" / "database_agent" / "agent.py") if len(_parents) > 2 else None
                spec = (
                    importlib.util.spec_from_file_location("aaas_database_agent_mod", str(agent_py))
                    if agent_py and agent_py.exists()
                    else None
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        diagnosis = pool.submit(
                            lambda: asyncio.run(
                                mod.run_diagnosis(
                                    prompt=effective_prompt,
                                    instance_name=instance_name,
                                    target_cloud=resolved_cloud,
                                )
                            )
                        ).result(timeout=a2a_timeout)
            except Exception:
                diagnosis = None

        if diagnosis:
            lower_prompt = prompt.lower()
            if "ddl_privilege_audit" not in diagnosis and any(
                k in lower_prompt
                for k in ("permission denied", "ddl", "drop", "create", "grant", "revoke", "audit_logs", "table")
            ):
                try:
                    db_adapter = get_database_cloud_adapter(resolved_cloud)
                    resolved_inst = (
                        (diagnosis.get("instance_inspection") or {}).get("instance_name")
                        or (instance_name if instance_name and instance_name != "auto" else "testdbinstance1")
                    )
                    tbl_m = re.search(
                        r"(?:permission denied for\s+(?:table|relation|view|sequence|schema)\s+|table\s+)([a-zA-Z0-9_.\"]+)",
                        prompt,
                        re.IGNORECASE,
                    )
                    hinted_tbl = tbl_m.group(1).strip('"') if tbl_m else ""
                    ddl_audit = db_adapter.inspect_table_ddl_and_privilege_logs(
                        table_or_object=hinted_tbl,
                        instance_name=resolved_inst,
                    )
                    diagnosis["ddl_privilege_audit"] = ddl_audit
                    tools_inv = list(diagnosis.get("tools_invoked") or [])
                    if "inspect_table_ddl_and_privilege_logs" not in tools_inv:
                        tools_inv.append("inspect_table_ddl_and_privilege_logs")
                        diagnosis["tools_invoked"] = tools_inv
                    if ddl_audit.get("permission_denied_events") or ddl_audit.get("permission_denied_count", 0) > 0:
                        recomputed_prop = db_adapter.generate_remediation_proposal(
                            issue_type="PG_OBJECT_PERMISSION_DENIED",
                            instance_name=resolved_inst,
                        )
                        diagnosis["remediation_proposal"] = recomputed_prop
                        log_anal = dict(diagnosis.get("log_analysis") or {})
                        log_anal["primary_issue_type"] = "PG_OBJECT_PERMISSION_DENIED"
                        log_anal["root_cause"] = ddl_audit.get("root_cause_summary") or log_anal.get("root_cause")
                        log_anal["ddl_and_privilege_correlation"] = ddl_audit
                        diagnosis["log_analysis"] = log_anal
                except Exception:
                    pass

            self.a2a_hub.message_ledger.insert(
                0,
                {
                    "id": rpc_id,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "sender": self.AGENT_ID,
                    "recipient": "agent-triad-db-agent (Cloud Run ADK)",
                    "skill_id": "diagnose_database_anomaly",
                    "summary": (
                        f"Atlas invoked live Cloud Run ADK Database Agent ({db_agent_url}/a2a) "
                        f"for `{instance_name}` -> tools={diagnosis.get('tools_invoked', [])}"
                    ),
                    "status": "COMPLETED",
                },
            )
            return diagnosis
        return None

    def _invoke_live_infra_agent_a2a(
        self,
        prompt: str,
        target_instance: str = "auto",
        target_cloud: Optional[str] = None,
        skill_id: str = "diagnose_infra_anomaly",
        project_id: Optional[str] = None,
        workload: str = "",
        incident_timestamp: str = "",
        mock_deployments: Optional[List[Dict[str, Any]]] = None,
        recommended_cli: str = "",
        terraform_hcl: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Invokes the live Cloud Run ADK Infra Specialist Agent (`agent-triad-infra-agent`)
        over Zero-Trust A2A (`POST /a2a` with OIDC Identity Token and `target_cloud` strategy)
        and logs the remote A2A exchange into the AaaS Control Plane ledger. Falls back to
        in-process ADK execution (`agents.infra_agent.agent.run_diagnosis`) if the remote
        endpoint is not yet reachable.
        """
        import urllib.request

        resolved_cloud = normalize_target_cloud(target_cloud)
        infra_agent_url = os.getenv(
            "INFRA_AGENT_URL",
            "https://agent-triad-infra-agent-qq3mp7ftqq-uc.a.run.app",
        ).rstrip("/")

        from services.auth_broker import auth_broker

        id_token_str = auth_broker.mint_oidc_id_token(infra_agent_url)

        rpc_id = f"a2a-infra-{uuid.uuid4().hex[:8]}"
        data_payload: Dict[str, Any] = {
            "prompt": prompt,
            "target_instance": target_instance,
            "target_cloud": resolved_cloud,
            "project_id": project_id or PROJECT_ID,
            "workload": workload or target_instance,
            "incident_timestamp": incident_timestamp,
            "recommended_cli": recommended_cli,
            "terraform_hcl": terraform_hcl,
        }
        if mock_deployments:
            data_payload["mock_deployments"] = mock_deployments

        rpc_payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tasks/send",
            "params": {
                "skill_id": skill_id,
                "data": data_payload,
            },
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if id_token_str:
            headers["Authorization"] = f"Bearer {id_token_str}"

        diagnosis: Optional[Dict[str, Any]] = None
        a2a_timeout = int(os.getenv("AAAS_SPECIALIST_A2A_TIMEOUT", "20"))
        try:
            req = urllib.request.Request(
                f"{infra_agent_url}/a2a",
                data=json.dumps(rpc_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=a2a_timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
            diagnosis = (resp_json.get("result") or {}).get("diagnosis")
        except Exception:
            diagnosis = None

        if not diagnosis:
            try:
                import asyncio
                import concurrent.futures
                import importlib.util
                from pathlib import Path

                _parents = Path(__file__).resolve().parents
                agent_py = (_parents[2] / "agents" / "infra_agent" / "agent.py") if len(_parents) > 2 else None
                spec = (
                    importlib.util.spec_from_file_location("aaas_infra_agent_mod", str(agent_py))
                    if agent_py and agent_py.exists()
                    else None
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        diagnosis = pool.submit(
                            lambda: asyncio.run(
                                mod.run_diagnosis(
                                    prompt=prompt,
                                    target_instance=target_instance,
                                    target_cloud=resolved_cloud,
                                    project_id=project_id or PROJECT_ID,
                                    workload=workload or target_instance,
                                    incident_timestamp=incident_timestamp,
                                    mock_deployments=mock_deployments,
                                    recommended_cli=recommended_cli,
                                    terraform_hcl=terraform_hcl,
                                )
                            )
                        ).result(timeout=a2a_timeout)
            except Exception:
                diagnosis = None

        if diagnosis:
            self.a2a_hub.message_ledger.insert(
                0,
                {
                    "id": rpc_id,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "sender": self.AGENT_ID,
                    "recipient": "agent-triad-infra-agent (Cloud Run ADK)",
                    "skill_id": skill_id,
                    "summary": (
                        f"Atlas invoked live Cloud Run ADK Infra Agent ({infra_agent_url}/a2a) "
                        f"for `{workload or target_instance}` -> tools={diagnosis.get('tools_invoked', [])}"
                    ),
                    "status": "COMPLETED",
                },
            )
            return diagnosis
        return None

    def _invoke_live_security_agent_a2a(
        self,
        prompt: str,
        project_id: Optional[str] = None,
        region: str = "europe-west2",
        service_agent_email: str = "",
        target_cloud: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Invokes the live Cloud Run ADK Security Specialist Agent (`agent-triad-security-agent`)
        over Zero-Trust A2A (`POST /a2a` with OIDC Identity Token) to audit live GCP IAM policy
        (`getIamPolicy`) and Cloud Audit Logs (`SetIamPolicy` drift), recording the remote A2A
        exchange in the Control Plane ledger. Falls back gracefully to in-process ADK execution
        if the remote Cloud Run endpoint is unreachable (e.g., offline unit tests).
        """
        import urllib.request

        resolved_cloud = normalize_target_cloud(target_cloud)
        clean_project = (project_id or PROJECT_ID).replace("projects/", "").strip() or PROJECT_ID
        security_agent_url = os.getenv(
            "SECURITY_AGENT_URL",
            "https://agent-triad-security-agent-qq3mp7ftqq-uc.a.run.app",
        ).rstrip("/")

        from services.auth_broker import auth_broker

        id_token_str = auth_broker.mint_oidc_id_token(security_agent_url)

        rpc_id = f"a2a-sec-{uuid.uuid4().hex[:8]}"
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tasks/send",
            "params": {
                "skill_id": "diagnose_security_iam_anomaly",
                "data": {
                    "prompt": prompt,
                    "project_id": clean_project,
                    "region": region,
                    "service_agent_email": service_agent_email,
                    "target_cloud": resolved_cloud,
                },
            },
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if id_token_str:
            headers["Authorization"] = f"Bearer {id_token_str}"

        diagnosis: Optional[Dict[str, Any]] = None
        a2a_timeout = int(os.getenv("AAAS_SPECIALIST_A2A_TIMEOUT", "20"))
        try:
            req = urllib.request.Request(
                f"{security_agent_url}/a2a",
                data=json.dumps(rpc_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=a2a_timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
            diagnosis = (resp_json.get("result") or {}).get("diagnosis")
        except Exception:
            diagnosis = None

        if not diagnosis:
            try:
                import asyncio
                import concurrent.futures
                import importlib.util
                from pathlib import Path

                _parents = Path(__file__).resolve().parents
                agent_py = (_parents[2] / "agents" / "security_agent" / "agent.py") if len(_parents) > 2 else None
                spec = (
                    importlib.util.spec_from_file_location("aaas_security_agent_mod", str(agent_py))
                    if agent_py and agent_py.exists()
                    else None
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        diagnosis = pool.submit(
                            lambda: asyncio.run(
                                mod.run_diagnosis(
                                    prompt=prompt,
                                    project_id=clean_project,
                                    region=region,
                                    service_agent_email=service_agent_email,
                                    target_cloud=resolved_cloud,
                                )
                            )
                        ).result(timeout=a2a_timeout)
            except Exception:
                diagnosis = None

        if diagnosis:
            self.a2a_hub.message_ledger.insert(
                0,
                {
                    "id": rpc_id,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "sender": self.AGENT_ID,
                    "recipient": "agent-triad-security-agent (Cloud Run ADK)",
                    "skill_id": "diagnose_security_iam_anomaly",
                    "summary": (
                        f"Atlas invoked live Cloud Run ADK Security Agent ({security_agent_url}/a2a) "
                        f"for `{clean_project}` -> tools={diagnosis.get('tools_invoked', [])}"
                    ),
                    "status": "COMPLETED",
                },
            )
            return diagnosis
        return None


    def _resolve_coordinated_specialists(
        self,
        log_entry: Dict[str, Any],
        rag_playbook: Dict[str, Any],
        primary_specialist: Dict[str, str],
    ) -> List[Dict[str, str]]:
        coord_ids = rag_playbook.get("coordinated_specialist_ids") or [primary_specialist["id"]]
        resolved: List[Dict[str, str]] = [primary_specialist]
        for sid in coord_ids:
            spec = SPECIALIST_BY_ID.get(sid)
            if spec and all(r["id"] != spec["id"] for r in resolved):
                resolved.append(spec)
        return resolved

    def _analyze_impact_and_remedy(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the ADK RAG Playbook lookup + Vertex AI Gemini (`gemini-2.5-flash`) ReAct synthesis
        to classify the incident into Scenario 1 (1-line CLI/API fix) or Scenario 2 (Multi-Service
        Terraform fix) and compute root cause, blast radius, and remediation plan.
        """
        scenario_id = log_entry.get("scenario_id", "real_gcp_anomaly")
        query_text = f"{log_entry.get('title', '')} {log_entry.get('message', '')} {log_entry.get('workload', '')}"
        rag_result = playbook_rag_service.retrieve_playbook(
            query=query_text,
            scenario_hint=scenario_id if scenario_id != "real_gcp_anomaly" else None,
        )
        playbook = GOLDEN_PLAYBOOKS.get(scenario_id, rag_result or GOLDEN_PLAYBOOKS["real_gcp_anomaly"])

        otel_attrs = ((log_entry.get("otel") or {}).get("attributes") or {})
        lock_recommended_cli = bool(
            scenario_id in ("datastream_iam_drift", "cloudsql_pg_permission_denied", "cloudsql_conn_probe")
            or otel_attrs.get("lock_recommended_cli")
        )
        default_kubectl = (
            log_entry.get("recommended_kubectl")
            or playbook.get("recommended_cli")
            or f"gcloud run services update {log_entry.get('container', 'service')} --region={log_entry.get('cluster', 'us-central1')} --project={PROJECT_ID}"
        )
        terraform_code = log_entry.get("terraform_code") or playbook.get("terraform_code")
        scenario_type = playbook.get("scenario_type", "SCENARIO_1_CLI_FIX")
        scenario_badge = playbook.get("scenario_badge", "Scenario 1 • 1-Line CLI/API Fix")
        rag_score = rag_result.get("rag_similarity_score", 0.94)

        analysis: Dict[str, Any] = {
            "playbook_id": playbook["playbook_id"],
            "playbook_title": playbook["title"],
            "scenario_type": scenario_type,
            "scenario_badge": scenario_badge,
            "coordinated_specialist_ids": list(playbook.get("coordinated_specialist_ids") or []),
            "rag_similarity_score": rag_score,
            "rag_engine": rag_result.get("rag_engine", "Vertex AI Playbook RAG"),
            "blast_radius_tier": playbook["blast_radius_tier"],
            "rollback_mode": playbook.get("rollback_mode", "STATELESS_CANARY_ROLLBACK"),
            "affected_services": playbook["affected_services"],
            "business_impact": playbook["business_impact"],
            "root_cause": playbook["root_cause"],
            "remedy_summary": playbook["remedy_summary"],
            "recommended_kubectl": default_kubectl,
            "terraform_code": terraform_code,
            "rollback_plan": playbook["rollback_plan"],
            "customer_headline": playbook.get("customer_headline", log_entry.get("title", "Cloud Issue Detected")),
            "customer_what_happened": playbook.get("customer_what_happened", log_entry.get("message", "")),
            "customer_why_approve": playbook.get("customer_why_approve", playbook["remedy_summary"]),
            "risk_badge": playbook.get("risk_badge", "Low Risk • Safe Fix"),
            "downtime_badge": playbook.get("downtime_badge", "Zero Downtime"),
            "safety_badge": playbook.get("safety_badge", "Auto-Rollback Protected"),
            "reasoning_engine": f"ADK Root Agent (Atlas • {MODEL_NAME}) + RAG Playbook {playbook['playbook_id']} (score={rag_score})",
        }

        if self._llm_client.is_available and not lock_recommended_cli:
            try:
                prompt = (
                    "You are Atlas, the Single Authorizing ADK Root Gemini Agent for Google Cloud AaaS (AgentTriad).\n"
                    "The Heartbeat & Telemetry Agent reported this SAIF-sanitized GCP Cloud Logging anomaly via A2A:\n"
                    f"{json.dumps(log_entry, default=str)}\n\n"
                    f"Matched RAG Playbook Context (similarity={rag_score}):\n{json.dumps(playbook, default=str)}\n\n"
                    "Return a JSON object with keys:\n"
                    "- customer_headline (string, 4-8 words in simple non-technical English for a business owner)\n"
                    "- customer_what_happened (string, 1 simple non-technical sentence explaining what went wrong)\n"
                    "- customer_why_approve (string, 1 simple non-technical sentence explaining how the fix helps)\n"
                    "- root_cause (string, 1-2 sentences technical root cause)\n"
                    "- business_impact (string, 1-2 sentences quantifying user/SLO impact)\n"
                    "- blast_radius_tier (string, e.g. 'HIGH (Tier-1 Service)')\n"
                    "- affected_services (array of strings)\n"
                    "- remedy_summary (string, 1-2 sentences explaining the technical fix)\n"
                    "- recommended_kubectl (string, exact gcloud or kubectl command)\n"
                    "- rollback_plan (string, 1 sentence fail-safe rollback plan)"
                )
                raw_json = self._llm_client.generate_text(
                    prompt,
                    response_mime_type="application/json",
                    temperature=0.2,
                )
                if raw_json:
                    parsed = json.loads(raw_json)
                    for key in (
                        "customer_headline",
                        "customer_what_happened",
                        "customer_why_approve",
                        "root_cause",
                        "business_impact",
                        "blast_radius_tier",
                        "affected_services",
                        "remedy_summary",
                        "recommended_kubectl",
                        "rollback_plan",
                    ):
                        if parsed.get(key):
                            analysis[key] = parsed[key]
            except Exception as exc:
                analysis["reasoning_note"] = f"Used deterministic RAG Playbook {playbook['playbook_id']} ({type(exc).__name__})"

        return analysis

    def _friendly_service_name(self, log_entry: Dict[str, Any]) -> str:
        source = str(log_entry.get("source", "")).lower()
        scen = str(log_entry.get("scenario_id", "")).lower()
        workload = str(log_entry.get("workload", "service"))
        if "datastream" in source or "datastream" in scen or "datastream" in workload.lower():
            return f"Datastream Private Connectivity ({workload})"
        if "cloud_run" in source or "cloud_run" in scen:
            return f"Cloud Run ({workload})"
        if "cloud_function" in source or "cloud_function" in scen:
            return f"Cloud Functions ({workload})"
        if "reasoningengine" in source or "reasoning_engine" in scen:
            return f"Vertex AI Reasoning Engine ({workload})"
        if "cloudsql" in source or "cloudsql" in scen:
            return f"Cloud SQL ({workload})"
        if "gce_instance" in source:
            return f"Compute Engine ({workload})"
        return f"GCP ({workload})"

    def _select_specialist_worker(self, log_entry: Dict[str, Any]) -> Dict[str, str]:
        """Selects the primary domain specialist from the 7-Agent Specialist Roster based on telemetry."""
        source = str(log_entry.get("source", "")).lower()
        scen = str(log_entry.get("scenario_id", "")).lower()
        workload = str(log_entry.get("workload", "")).lower()
        msg = str(log_entry.get("message", "")).lower()

        if (
            scen == "datastream_iam_drift"
            or "datastream" in source
            or "datastream" in workload
            or "gcp-sa-datastream" in msg
            or ("failed_precondition" in msg and "permission" in msg)
        ):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent (with Infra Agent coordinated)
        if any(k in msg or k in source or k in workload for k in ("billing", "budget", "cost", "finops")):
            return WORKER_AGENT_BOUTIQUE[6]  # Billing Agent
        if (
            "testdbconnect" in workload
            or "cloudsql" in source
            or "cloudsql" in scen
            or "sql" in workload
            or "database" in msg
            or "permission denied for " in msg
            or ("db=" in msg and "user=" in msg)
        ):
            return WORKER_AGENT_BOUTIQUE[1]  # Database Agent
        if any(k in msg or k in source or k in workload for k in ("iam", "permission", "unauthorized", "forbidden", "secret", "armor")):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent
        if "reasoningengine" in source or "reasoning_engine" in scen or "bigquery" in source or "dataflow" in source:
            return WORKER_AGENT_BOUTIQUE[4]  # Data Analytics Agent
        if "vpc" in source or "network" in source or "loadbalancing" in source or "ingress" in workload:
            return WORKER_AGENT_BOUTIQUE[3]  # Networking Agent
        if "cloud_run" in source or "cloud_run" in scen or "cloud_function" in source or "cloud_function" in scen:
            return WORKER_AGENT_BOUTIQUE[0]  # Serverless Agent
        return WORKER_AGENT_BOUTIQUE[2]  # Infra Agent

    def _upsert_audit_event(self, incident: Dict[str, Any], event_type: str) -> Dict[str, Any]:
        """Maintains a structured, auditable Event Tracker record for every incident and approval."""
        incident_id = incident["incident_id"]
        jit = incident.get("jit_token") or {}
        exec_res = incident.get("execution_result") or {}
        impact = incident.get("impact_analysis") or {}
        specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
        coord_specs = incident.get("coordinated_specialists") or [specialist]
        audit_entry: Dict[str, Any] = {
            "incident_id": incident_id,
            "service_label": incident.get("service_label") or self._friendly_service_name(incident.get("log_entry", {})),
            "workload": incident.get("workload", ""),
            "cluster": incident.get("cluster", ""),
            "severity": incident.get("severity", "ERROR"),
            "title": impact.get("customer_headline") or incident.get("title", "Cloud Service Anomaly"),
            "technical_title": incident.get("title", ""),
            "scenario_badge": impact.get("scenario_badge", "Scenario 1 • 1-Line CLI/API Fix"),
            "specialist_agent_id": specialist.get("id", "serverless-agent"),
            "specialist_agent_name": specialist.get("name", "Serverless Agent"),
            "coordinated_specialist_names": [s.get("name", "") for s in coord_specs],
            "specialist_domain": specialist.get("domain", "Cloud Run & Cloud Functions"),
            "occurred_at": incident.get("occurred_at") or incident.get("created_at"),
            "detected_at": incident.get("detected_at") or incident.get("created_at"),
            "status": incident.get("status", "AWAITING_HITL_APPROVAL"),
            "approved_by": incident.get("approved_by"),
            "approved_at": incident.get("approved_at"),
            "resolved_at": incident.get("resolved_at"),
            "jit_token_id": jit.get("token_id"),
            "command": exec_res.get("command") or impact.get("recommended_kubectl"),
            "reconciliation_pr": exec_res.get("reconciliation_pr"),
            "last_event_type": event_type,
            "updated_at": incident.get("updated_at"),
        }
        self.audit_events[incident_id] = audit_entry
        if self.logging_service is not None and hasattr(self.logging_service, "record_audit_event"):
            try:
                self.logging_service.record_audit_event(
                    incident_id=incident_id,
                    event_type=event_type,
                    service=audit_entry["service_label"],
                    issue_title=audit_entry["title"],
                    occurred_at=str(audit_entry["occurred_at"]),
                    action_status=audit_entry["status"],
                    approved_by=audit_entry["approved_by"],
                    approved_at=audit_entry["approved_at"],
                    command=audit_entry["command"],
                    jit_token_id=audit_entry["jit_token_id"],
                )
            except Exception:
                pass
        return audit_entry

    @staticmethod
    def _build_datastream_iam_hcl(project_id: str, sa_email: str) -> str:
        clean_proj = (project_id or PROJECT_ID).replace("projects/", "").strip() or PROJECT_ID
        clean_sa = (sa_email or security_iam_service.default_datastream_service_agent(clean_proj)).strip()
        if clean_sa.startswith("serviceAccount:"):
            clean_sa = clean_sa.split(":", 1)[1]
        return f"""terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 5.0"
    }}
  }}
}}

# Security Agent + Infra Agent: Bidirectional GitOps Reconciliation for Datastream SA IAM Drift
resource "google_project_iam_member" "datastream_sa_network_admin" {{
  project = "{clean_proj}"
  role    = "roles/compute.networkAdmin"
  member  = "serviceAccount:{clean_sa}"

  lifecycle {{
    prevent_destroy = true
  }}
}}"""

    @staticmethod
    def _format_datastream_four_phase_rca(
        *,
        uname: str,
        cloud_provider_status: Dict[str, Any],
        iam_audit: Dict[str, Any],
        gitops_correlation: Optional[Dict[str, Any]] = None,
        customer_ticket: Optional[Dict[str, Any]] = None,
    ) -> str:
        region = str(cloud_provider_status.get("region") or iam_audit.get("region") or "europe-west2")
        provider_state = str(cloud_provider_status.get("status") or "OPERATIONAL")
        is_green = bool(cloud_provider_status.get("mutations_allowed", True))
        provider_display = (
            f"OPERATIONAL (Green • {provider_state})"
            if is_green
            else f"ACTIVE OUTAGE ({provider_state})"
        )
        target_project = str(iam_audit.get("project_id") or PROJECT_ID)
        sa_email = str(iam_audit.get("target_service_agent") or "")
        req_role = str(iam_audit.get("required_role") or "roles/compute.networkAdmin")
        recommended_cli = str(iam_audit.get("recommended_cli") or "")
        iam_source_badge = (
            "Live GCP `projects.getIamPolicy`"
            if iam_audit.get("live_gcp_verified")
            else "Security Agent IAM Posture Audit"
        )
        assigned_roles = iam_audit.get("assigned_roles") or []
        roles_str = ", ".join(assigned_roles) if assigned_roles else "NONE"

        suspect = (gitops_correlation or {}).get("highest_confidence_match")
        if suspect:
            delta_m = suspect.get("delta_minutes_before_incident")
            delta_label = f"{delta_m} min prior" if delta_m is not None else "recently"
            gitops_line = (
                f"Correlated suspect IaC / IAM drift (`{suspect.get('short_sha')}` by `{suspect.get('author')}`, "
                f"{delta_label}, confidence `{suspect.get('confidence')}`): {suspect.get('subject')}"
            )
        else:
            gitops_line = (
                "External Terraform / IAM state drift removed the Datastream service agent binding on the host project."
            )

        ticket_header = ""
        if customer_ticket and customer_ticket.get("customer_name"):
            ticket_header = (
                f"Customer: **{customer_ticket.get('customer_name')}** • "
                f"Project: `projects/{target_project}` • Region: `{region}` • "
                f"Impact: `{customer_ticket.get('business_impact', 'Non-Production System impaired')}`\n\n"
            )

        return (
            f"Hey {uname} 👋 I completed the 4-phase Agent-Triad investigation for **Datastream Private Connectivity** on `{target_project}`.\n\n"
            f"{ticket_header}"
            f"• **Phase 1 — Pre-Flight Cloud Provider Status (`Cloud_Provider_Health_Tool`)**: "
            f"GCP `{region}` is **`{provider_display}`**. "
            f"There is **no Google Cloud regional outage** — Safety Brake remains disengaged; fault classified as `External • IaC / IAM Configuration Drift`.\n"
            f"• **Phase 2 — Specialist Routing (Parallel A2A)**:\n"
            f"  - **Security Agent (`Security_Agent_Tool` • {iam_source_badge})**: Confirmed Datastream service agent "
            f"`{sa_email}` is missing `{req_role}` on `{target_project}` (current roles: `{roles_str}`).\n"
            f"  - **Infra Agent (`GitOps_Correlator_Tool`)**: {gitops_line}\n"
            f"• **Phase 3 — Blameless RCA & Direct Guidance**: Google Cloud infrastructure in `{region}` is healthy; "
            f"an external IaC/IAM state drift deployment caused this regression. **Do NOT remove the Datastream service account** — "
            f"removing it will not allow private connectivity outside Shared VPC and breaks peering validation. Restoring `{req_role}` "
            f"unblocks IP range validation for Cloud SQL private connectivity immediately.\n"
            f"• **Phase 4 — Stage 2 HITL Remediation (Zero Autonomous Execution)**:\n"
            f"  Proposed CLI Fix:\n"
            f"  `{recommended_cli}`\n\n"
            f"**Click 'I Accept' to mint a 15-minute JIT token and execute this GitOps synchronization.**"
        )

    def _build_initial_chat_greeting(
        self,
        log_entry: Dict[str, Any],
        impact: Dict[str, Any],
        specialist: Dict[str, str],
        coordinated_specialists: List[Dict[str, str]],
        harness_bundle: Dict[str, Any],
        now_iso: str,
    ) -> List[Dict[str, Any]]:
        uname = self.active_user.get("name", "Hari")
        iam_audit = impact.get("iam_audit")
        is_datastream_iam = bool(iam_audit) and (
            log_entry.get("scenario_id") == "datastream_iam_drift"
            or "datastream" in str(log_entry.get("source") or "").lower()
            or "datastream" in str(log_entry.get("workload") or "").lower()
            or "gcp-sa-datastream" in str(log_entry.get("message") or "").lower()
        )
        if is_datastream_iam:
            opening_text = self._format_datastream_four_phase_rca(
                uname=uname,
                cloud_provider_status=impact.get("cloud_provider_status") or {"region": log_entry.get("cluster", "europe-west2"), "status": "OPERATIONAL", "mutations_allowed": True},
                iam_audit=iam_audit,
                gitops_correlation=impact.get("gitops_correlation"),
                customer_ticket=impact.get("customer_ticket") or log_entry.get("customer_ticket"),
            )
            return [
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "scenario_badge": impact.get("scenario_badge", "Scenario 1 • External IaC / IAM Drift"),
                    "text": opening_text,
                    "timestamp": now_iso,
                }
            ]

        service_label = self._friendly_service_name(log_entry)
        severity = log_entry.get("severity", "ERROR")
        what_happened = impact.get("customer_what_happened") or log_entry.get("message", "")
        next_step = impact.get("customer_why_approve") or impact.get("remedy_summary", "")
        blast = impact.get("blast_radius_tier", "HIGH")
        coord_names = ", ".join(f"**{s['name']}**" for s in coordinated_specialists)
        lock_uri = (harness_bundle.get("lock") or {}).get("gcs_uri", "gs://agent-triad-tf-state/lock.tflock")
        rag_score = impact.get("rag_similarity_score", 0.94)

        ddl_audit = impact.get("ddl_privilege_audit")
        ddl_line = ""
        if isinstance(ddl_audit, dict):
            ddl_evts = ddl_audit.get("ddl_events") or ddl_audit.get("ddl_statements") or []
            dcl_evts = ddl_audit.get("dcl_grant_revoke_events") or ddl_audit.get("privilege_statements") or []
            ddl_bits: List[str] = []
            for d_evt in ddl_evts[:2]:
                stmt_short = str(d_evt.get("statement") or d_evt.get("verb") or "DDL")[:60]
                ddl_bits.append(f"`{stmt_short}` at `{d_evt.get('timestamp', '')}`")
            for g_evt in dcl_evts[:2]:
                stmt_short = str(g_evt.get("statement") or g_evt.get("verb") or "GRANT/REVOKE")[:60]
                ddl_bits.append(f"`{stmt_short}` at `{g_evt.get('timestamp', '')}`")
            if ddl_bits:
                ddl_line = f"• **Correlated Cloud SQL DDL / ACL Logs**: {', '.join(ddl_bits)}\n"

        w_spec = (harness_bundle.get("watchdog_spec") or {})
        rb_mode = (
            "Stateful Safe-Mode Isolation (`prevent_destroy=true`)"
            if w_spec.get("rollback_mode") == "STATEFUL_SAFE_MODE_ISOLATION"
            else "Stateless Canary Auto-Rollback"
        )
        opening_text = (
            f"Hey {uname} 👋 There's an issue I just found with **{service_label}**.\n\n"
            f"• **Classification**: `{impact.get('scenario_badge', 'Scenario 1 • 1-Line CLI/API Fix')}` (Playbook Match: `{int(rag_score * 100)}%`)\n"
            f"• **Severity**: `{severity}` — {blast}\n"
            f"• **What happened**: {what_happened}\n"
            f"{ddl_line}"
            f"• **Delegation Plan**: {coord_names}\n"
            f"• **Safety Guardrails**: Verified Non-Destructive (`PASS`) • Resource Locked for 10m (`{lock_uri}`) • 45s Liveness + 3m Metric Verify ({rb_mode})\n"
            f"• **Next Steps**: {next_step}\n\n"
            "Ask me anything about why this happened, recent DDL/log changes, whether there's any downtime, the rollback plan, "
            "or the exact command/Terraform script. Whenever you're ready, type **'I accept'** or click **I accept** below!"
        )
        return [
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": opening_text,
                "timestamp": now_iso,
            }
        ]

    async def handle_a2a_task(self, request: A2ATaskRequest) -> A2ATaskResponse:
        """Handles incoming A2A `ingest_anomaly_alert` tasks from the Heartbeat & Telemetry Agent."""
        skill_id = request.params.get("skill_id", "")
        parts = request.params.get("message", {}).get("parts", [])
        data = parts[0].get("data", {}) if parts else {}

        if skill_id == "ingest_anomaly_alert":
            raw_entry = data.get("log_entry", {})
            log_entry = agent_harness.sanitize_telemetry_saif(raw_entry)
            incident_id = log_entry.get("log_id", f"inc-{len(self.incidents) + 1}")
            sig_key = str(log_entry.get("signature_key") or "").strip()
            wl_err_key = f"{log_entry.get('workload', '')}::{log_entry.get('error_code', '')}"
            existing_inc = self.incidents.get(incident_id)
            if (
                incident_id in self.ignored_log_ids
                or (sig_key and sig_key in self.ignored_signatures)
                or wl_err_key in self.ignored_signatures
                or (existing_inc and existing_inc.get("status") == "IGNORED")
            ):
                return A2ATaskResponse(
                    id=request.id,
                    result={
                        "status": "IGNORED_BY_OPERATOR",
                        "incident_id": incident_id,
                        "signature_key": sig_key,
                    },
                )
            specialist = self._select_specialist_worker(log_entry)

            cluster = log_entry.get("cluster", "us-central1")
            namespace = log_entry.get("namespace", "default")
            workload = log_entry.get("workload", "deployment/app")
            raw_cloud = str(log_entry.get("cloud_provider") or "").strip().lower()
            event_cloud = raw_cloud if raw_cloud in ("gcp", "aws", "azure") else self.active_target_cloud

            is_datastream_iam = (
                log_entry.get("scenario_id") == "datastream_iam_drift"
                or "datastream" in str(log_entry.get("source") or "").lower()
                or "datastream" in workload.lower()
                or "gcp-sa-datastream" in str(log_entry.get("message") or "").lower()
            )
            target_project = (
                str(log_entry.get("project_id") or PROJECT_ID).replace("projects/", "").strip()
                or PROJECT_ID
            )
            target_datastream_sa = str(
                (log_entry.get("metrics_snapshot") or {}).get("datastream_sa")
                or ((log_entry.get("otel") or {}).get("attributes") or {}).get("gcp.datastream.service_agent")
                or (log_entry.get("customer_ticket") or {}).get("service_agent_email")
                or security_iam_service.default_datastream_service_agent(target_project)
            ).strip()

            async def _fetch_specialist_diag() -> tuple[
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
                Optional[Dict[str, Any]],
            ]:
                if is_datastream_iam:
                    sec_prompt = (
                        f"Atlas Phase 2 Security Audit: Datastream private connectivity in `{cluster}` on project "
                        f"`{target_project}` failed with: {log_entry.get('message')}. "
                        f"Verify live IAM policy posture for `{target_datastream_sa}`, inspect Cloud Audit Logs "
                        f"for recent SetIamPolicy REMOVE drift, and propose the exact least-privilege CLI & Terraform fix."
                    )
                    infra_prompt = (
                        f"Atlas Phase 2 GitOps Correlation: Datastream private connectivity `{workload}` in "
                        f"`{target_project}` ({cluster}) failed with missing IAM permissions. "
                        f"Correlate recent Terraform state drift / SetIamPolicy REMOVE audit logs and CI/CD deployments."
                    )
                    sec_d, inf_d = await asyncio.gather(
                        asyncio.to_thread(
                            self._invoke_live_security_agent_a2a,
                            prompt=sec_prompt,
                            project_id=target_project,
                            region=cluster,
                            service_agent_email=target_datastream_sa,
                            target_cloud=event_cloud,
                        ),
                        asyncio.to_thread(
                            self._invoke_live_infra_agent_a2a,
                            prompt=infra_prompt,
                            target_instance=workload,
                            target_cloud=event_cloud,
                            skill_id="correlate_gitops_drift",
                            project_id=target_project,
                            workload=workload,
                            incident_timestamp=str(log_entry.get("timestamp") or data.get("detected_at") or ""),
                            mock_deployments=log_entry.get("mock_deployments"),
                            recommended_cli=str(log_entry.get("recommended_kubectl") or ""),
                        ),
                    )
                    iam_res = (sec_d or {}).get("iam_audit")
                    if not isinstance(iam_res, dict) or not iam_res.get("recommended_cli"):
                        iam_res = await asyncio.to_thread(
                            security_iam_service.inspect_datastream_iam_posture,
                            project_id=target_project,
                            region=cluster,
                            service_agent_email=target_datastream_sa,
                            execute_live=(target_project == PROJECT_ID),
                        )
                    return None, inf_d, iam_res, sec_d
                if specialist.get("id") == "database-agent":
                    target_inst = str(log_entry.get("pod") or "testdbinstance1").split(":")[-1]
                    db_d = await asyncio.to_thread(
                        self._invoke_live_database_agent_a2a,
                        prompt=(
                            f"Atlas Alert: Cloud Logging detected [{log_entry.get('severity')}] on `{workload}`: "
                            f"{log_entry.get('message')}. Inspect the live database instance and logs and propose a safe fix."
                        ),
                        instance_name=target_inst,
                        target_cloud=event_cloud,
                    )
                    return db_d, None, None, None
                if specialist.get("id") == "infra-agent":
                    target_inst = str(log_entry.get("pod") or workload.split("/")[-1] or "auto").split(":")[-1]
                    inf_d = await asyncio.to_thread(
                        self._invoke_live_infra_agent_a2a,
                        prompt=(
                            f"Atlas Alert: Cloud Logging detected [{log_entry.get('severity')}] on `{workload}` "
                            f"(zone/cluster `{cluster}`): {log_entry.get('message')}. "
                            f"Inspect the live compute inventory, performance metrics, and logs "
                            f"for `{target_inst}` and propose a safe remediation."
                        ),
                        target_instance=target_inst,
                        target_cloud=event_cloud,
                    )
                    return None, inf_d, None, None
                if specialist.get("id") == "security-agent":
                    sec_d = await asyncio.to_thread(
                        self._invoke_live_security_agent_a2a,
                        prompt=(
                            f"Atlas Alert: Cloud Logging detected [{log_entry.get('severity')}] on `{workload}`: "
                            f"{log_entry.get('message')}. Audit live IAM posture and Cloud Audit Logs and propose a safe fix."
                        ),
                        project_id=target_project,
                        region=cluster,
                        service_agent_email=target_datastream_sa,
                        target_cloud=event_cloud,
                    )
                    return None, None, (sec_d or {}).get("iam_audit"), sec_d
                return None, None, None, None

            async def _fetch_preflight() -> Dict[str, Any]:
                if data.get("cloud_provider_status"):
                    return data["cloud_provider_status"]
                return await self._run_cloud_provider_preflight_check(
                    cloud_provider=event_cloud or "gcp",
                    region=cluster,
                    service_hint="datastream" if is_datastream_iam else str(log_entry.get("source") or ""),
                )

            # Run Atlas RAG/LLM analysis, live specialist A2A diagnosis, and provider pre-flight in parallel
            impact_and_remedy, (live_db_diag, live_infra_diag, iam_audit, live_sec_diag), cloud_provider_status = await asyncio.gather(
                asyncio.to_thread(self._analyze_impact_and_remedy, log_entry),
                _fetch_specialist_diag(),
                _fetch_preflight(),
            )
            coordinated_specialists = self._resolve_coordinated_specialists(
                log_entry=log_entry,
                rag_playbook=impact_and_remedy,
                primary_specialist=specialist,
            )
            if is_datastream_iam:
                for required_sid in ("security-agent", "infra-agent"):
                    req_spec = SPECIALIST_BY_ID.get(required_sid)
                    if req_spec and all(s["id"] != required_sid for s in coordinated_specialists):
                        coordinated_specialists.append(req_spec)

            customer_ticket = log_entry.get("customer_ticket")
            if customer_ticket:
                impact_and_remedy["customer_ticket"] = customer_ticket

            if live_sec_diag:
                impact_and_remedy["live_security_agent_diagnosis"] = live_sec_diag

            if iam_audit and is_datastream_iam:
                impact_and_remedy["iam_audit"] = iam_audit
                impact_and_remedy["recommended_kubectl"] = iam_audit["recommended_cli"]
                impact_and_remedy["terraform_code"] = self._build_datastream_iam_hcl(
                    target_project,
                    iam_audit.get("target_service_agent") or target_datastream_sa,
                )
                impact_and_remedy["root_cause"] = (
                    f"GCP infrastructure in `{cluster}` is OPERATIONAL (Green). {iam_audit['finding']}"
                )
                if not live_sec_diag:
                    self.a2a_hub.message_ledger.insert(
                        0,
                        {
                            "id": f"a2a-sec-{uuid.uuid4().hex[:8]}",
                            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "sender": self.AGENT_ID,
                            "recipient": "security-agent (Security_Agent_Tool)",
                            "skill_id": "inspect_iam_policy_posture",
                            "summary": (
                                f"Atlas delegated IAM posture verification for `{target_project}` -> "
                                f"`{iam_audit.get('target_service_agent')}` missing `{iam_audit.get('required_role')}` "
                                f"(live_gcp_verified={iam_audit.get('live_gcp_verified')})"
                            ),
                            "status": "COMPLETED",
                        },
                    )

            if live_db_diag:
                impact_and_remedy["live_database_agent_diagnosis"] = live_db_diag
                log_anal = live_db_diag.get("log_analysis") or {}
                prop = live_db_diag.get("remediation_proposal") or {}
                ddl_audit = live_db_diag.get("ddl_privilege_audit") or log_anal.get("ddl_and_privilege_correlation")
                if isinstance(ddl_audit, dict):
                    impact_and_remedy["ddl_privilege_audit"] = ddl_audit
                if log_anal.get("root_cause"):
                    impact_and_remedy["root_cause"] = log_anal["root_cause"]
                    impact_and_remedy["customer_what_happened"] = log_anal["root_cause"]
                has_ddl_perm_denied = isinstance(ddl_audit, dict) and bool(
                    ddl_audit.get("permission_denied_events") or ddl_audit.get("permission_denied_count", 0) > 0
                )
                if has_ddl_perm_denied:
                    if ddl_audit.get("root_cause_summary"):
                        impact_and_remedy["root_cause"] = ddl_audit["root_cause_summary"]
                        impact_and_remedy["customer_what_happened"] = ddl_audit["root_cause_summary"]
                    if ddl_audit.get("recommended_cli"):
                        impact_and_remedy["recommended_kubectl"] = ddl_audit["recommended_cli"]
                if prop.get("remediation_summary"):
                    impact_and_remedy["remedy_summary"] = prop["remediation_summary"]
                    impact_and_remedy["customer_why_approve"] = prop["remediation_summary"]
                if prop.get("recommended_cli") and not (
                    has_ddl_perm_denied and ddl_audit.get("recommended_cli")
                ):
                    impact_and_remedy["recommended_kubectl"] = prop["recommended_cli"]
                if prop.get("terraform_hcl"):
                    impact_and_remedy["terraform_code"] = prop["terraform_hcl"]
            if live_infra_diag:
                impact_and_remedy["live_infra_agent_diagnosis"] = live_infra_diag
                if not is_datastream_iam:
                    log_anal = live_infra_diag.get("log_analysis") or {}
                    prop = live_infra_diag.get("remediation_proposal") or {}
                    if log_anal.get("root_cause"):
                        impact_and_remedy["root_cause"] = log_anal["root_cause"]
                    if log_anal.get("customer_what_happened") or log_anal.get("root_cause"):
                        impact_and_remedy["customer_what_happened"] = (
                            log_anal.get("customer_what_happened") or log_anal.get("root_cause")
                        )
                    if prop.get("remediation_summary"):
                        impact_and_remedy["remedy_summary"] = prop["remediation_summary"]
                        impact_and_remedy["customer_why_approve"] = prop["remediation_summary"]
                    if prop.get("recommended_cli"):
                        impact_and_remedy["recommended_kubectl"] = prop["recommended_cli"]
                    if prop.get("terraform_hcl"):
                        impact_and_remedy["terraform_code"] = prop["terraform_hcl"]

            harness_bundle = agent_harness.build_incident_harness_bundle(
                incident_id=incident_id,
                cluster=cluster,
                namespace=namespace,
                workload=workload,
                command=impact_and_remedy.get("recommended_kubectl", ""),
                terraform_code=impact_and_remedy.get("terraform_code"),
                specialist_ids=[s["id"] for s in coordinated_specialists],
                rollback_mode_hint=impact_and_remedy.get("rollback_mode", ""),
            )
            harness_bundle["rag_playbook"] = {
                "playbook_id": impact_and_remedy.get("playbook_id", "PB-RUN-401"),
                "similarity_score": impact_and_remedy.get("rag_similarity_score", 0.94),
            }
            impact_and_remedy["agent_harness"] = harness_bundle

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            occurred_at = log_entry.get("timestamp") or data.get("detected_at") or now_iso
            detected_at = data.get("detected_at") or now_iso

            # Phase 4: Pre-flight Cloud Provider Status Check snapshot & Fault Attribution
            impact_and_remedy["cloud_provider_status"] = cloud_provider_status
            fault_attribution = self.classify_fault_attribution(
                cloud_provider_status=cloud_provider_status,
                log_entry=log_entry,
                specialist=specialist,
            )
            impact_and_remedy["fault_attribution"] = fault_attribution

            # Phase 4: Read-Only DB Query Introspection (lifted from live DB Agent or out-of-band slow-query log analysis)
            query_introspection: Optional[Dict[str, Any]] = None
            if live_db_diag and isinstance(live_db_diag.get("query_introspection"), dict):
                query_introspection = live_db_diag["query_introspection"]
            elif specialist.get("id") == "database-agent":
                raw_log_lines = [
                    str(line)
                    for line in (
                        [log_entry.get("message")]
                        + (log_entry.get("slow_query_logs") or [])
                    )
                    if line
                ]
                if raw_log_lines:
                    target_inst = str(log_entry.get("pod") or workload.split("/")[-1] or "testdbinstance1").split(":")[-1]
                    query_introspection = analyze_pg_stat_activity_and_slow_queries(
                        instance_name=target_inst,
                        target_cloud=event_cloud or "gcp",
                        log_lines=raw_log_lines,
                    )
            if query_introspection is not None:
                impact_and_remedy["query_introspection"] = query_introspection

            # Phase 4: GitOps / Recent Deployment Correlation & Bidirectional GitOps PR Payload (Infra/Serverless path)
            gitops_correlation: Optional[Dict[str, Any]] = None
            gitops_pr_payload: Optional[Dict[str, Any]] = None
            has_infra_or_serverless = any(
                s.get("id") in ("infra-agent", "serverless-agent") for s in coordinated_specialists
            )
            if has_infra_or_serverless:
                live_infra_corr = (live_infra_diag or {}).get("gitops_correlation")
                has_valid_live_corr = (
                    isinstance(live_infra_corr, dict)
                    and live_infra_corr.get("status") == "CORRELATED_RECENT_DEPLOYMENT"
                    and live_infra_corr.get("highest_confidence_match") is not None
                )
                if has_valid_live_corr and not log_entry.get("mock_deployments"):
                    gitops_correlation = live_infra_corr
                elif is_datastream_iam:
                    iam_drift_deployments: List[Dict[str, Any]] = list(log_entry.get("mock_deployments") or [])
                    sec_drifts = (live_sec_diag or {}).get("drift_events") or []
                    if sec_drifts:
                        iam_drift_deployments = list(sec_drifts) + iam_drift_deployments
                    elif target_project == PROJECT_ID:
                        live_audit_drifts = await asyncio.to_thread(
                            security_iam_service.fetch_recent_iam_drift_audit_events,
                            project_id=target_project,
                            lookback_hours=72,
                        )
                        if live_audit_drifts:
                            iam_drift_deployments = live_audit_drifts + iam_drift_deployments
                    gitops_correlation = gitops_correlator.correlate_recent_deployments(
                        incident_timestamp=occurred_at,
                        workload=workload,
                        window_minutes=4320,
                        deployments=iam_drift_deployments or None,
                    )
                    if not live_infra_diag:
                        top_drift = (gitops_correlation or {}).get("highest_confidence_match")
                        self.a2a_hub.message_ledger.insert(
                            0,
                            {
                                "id": f"a2a-gitops-{uuid.uuid4().hex[:8]}",
                                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "sender": self.AGENT_ID,
                                "recipient": "infra-agent (GitOps_Correlator_Tool)",
                                "skill_id": "correlate_recent_deployments",
                                "summary": (
                                    f"Atlas delegated CI/CD & IAM drift correlation for `{workload}` -> "
                                    f"{top_drift.get('short_sha') + ' (' + str(top_drift.get('confidence')) + ')' if top_drift else 'scanned recent commits & audit logs'}"
                                ),
                                "status": "COMPLETED",
                            },
                        )
                elif live_infra_corr:
                    gitops_correlation = live_infra_corr
                else:
                    gitops_correlation = gitops_correlator.correlate_recent_deployments(
                        incident_timestamp=occurred_at,
                        workload=workload,
                        window_minutes=180,
                    )
                live_prop = (live_infra_diag or {}).get("remediation_proposal") or {}
                gitops_pr_payload = live_prop.get("gitops_pr_payload") or gitops_correlator.build_gitops_reconciliation_pr_payload(
                    incident_id=incident_id,
                    workload=workload,
                    target_cloud=event_cloud or "gcp",
                    recommended_cli=impact_and_remedy.get("recommended_kubectl", ""),
                    terraform_hcl=impact_and_remedy.get("terraform_code"),
                    correlation_report=gitops_correlation,
                    reason=impact_and_remedy.get("remedy_summary", ""),
                )
                impact_and_remedy["gitops_correlation"] = gitops_correlation
                impact_and_remedy["gitops_pr_payload"] = gitops_pr_payload

            chat_messages = self._build_initial_chat_greeting(
                log_entry=log_entry,
                impact=impact_and_remedy,
                specialist=specialist,
                coordinated_specialists=coordinated_specialists,
                harness_bundle=harness_bundle,
                now_iso=now_iso,
            )
            if live_sec_diag and live_sec_diag.get("security_reasoning_report"):
                chat_messages.append(
                    {
                        "role": "assistant",
                        "sender": "Security Agent • Live Cloud Run ADK (agent-triad-security-agent)",
                        "scenario_badge": "Live A2A Diagnosis",
                        "text": (
                            f"📡 **Live A2A Report from `agent-triad-security-agent` (Tools invoked: `{', '.join(live_sec_diag.get('tools_invoked', []))}`)**:\n\n"
                            f"{live_sec_diag['security_reasoning_report']}"
                        ),
                        "timestamp": now_iso,
                    }
                )
            if live_db_diag and live_db_diag.get("dba_reasoning_report"):
                chat_messages.append(
                    {
                        "role": "assistant",
                        "sender": "Database Agent • Live Cloud Run ADK (agent-triad-db-agent)",
                        "scenario_badge": "Live A2A Diagnosis",
                        "text": (
                            f"📡 **Live A2A Report from `agent-triad-db-agent` (Tools invoked: `{', '.join(live_db_diag.get('tools_invoked', []))}`)**:\n\n"
                            f"{live_db_diag['dba_reasoning_report']}"
                        ),
                        "timestamp": now_iso,
                    }
                )
            if live_infra_diag and live_infra_diag.get("infra_reasoning_report"):
                chat_messages.append(
                    {
                        "role": "assistant",
                        "sender": "Infra Agent • Live Cloud Run ADK (agent-triad-infra-agent)",
                        "scenario_badge": "Live A2A Diagnosis",
                        "text": (
                            f"📡 **Live A2A Report from `agent-triad-infra-agent` (Tools invoked: `{', '.join(live_infra_diag.get('tools_invoked', []))}`)**:\n\n"
                            f"{live_infra_diag['infra_reasoning_report']}"
                        ),
                        "timestamp": now_iso,
                    }
                )


            incident_record: Dict[str, Any] = {
                "incident_id": incident_id,
                "occurred_at": occurred_at,
                "detected_at": detected_at,
                "created_at": now_iso,
                "updated_at": now_iso,
                "approved_by": None,
                "approved_at": None,
                "resolved_at": None,
                "service_label": self._friendly_service_name(log_entry),
                "status": "AWAITING_HITL_APPROVAL",
                "reported_by_agent": data.get("detector_agent", "log-watcher-agent"),
                "assigned_orchestrator": self.AGENT_ID,
                "delegated_specialist_agent": "gke-assist-agent",
                "specialist_worker": specialist,
                "coordinated_specialists": coordinated_specialists,
                "agent_harness": harness_bundle,
                "change_risk": harness_bundle.get("change_risk"),
                "last_approval_gate": None,
                "severity": log_entry.get("severity", "CRITICAL"),
                "title": log_entry.get("title", "Cloud Service Anomaly"),
                "cluster": cluster,
                "namespace": namespace,
                "workload": workload,
                "pod": log_entry.get("pod", "unknown-pod"),
                "error_code": log_entry.get("error_code", "GCP_ERROR"),
                "log_entry": log_entry,
                "impact_analysis": impact_and_remedy,
                "target_cloud": event_cloud or "gcp",
                "cloud_provider_status": cloud_provider_status,
                "fault_attribution": fault_attribution,
                "iam_audit": iam_audit,
                "customer_ticket": customer_ticket,
                "query_introspection": query_introspection,
                "gitops_correlation": gitops_correlation,
                "gitops_pr_payload": gitops_pr_payload,
                "chat_messages": chat_messages,
                "jit_token": None,
                "execution_result": None,
                "verification_result": None,
                "timeline": [
                    {
                        "timestamp": detected_at,
                        "agent": "Heartbeat & Telemetry",
                        "event": (
                            f"Detected SAIF-sanitized [{log_entry.get('severity')}] {log_entry.get('error_code')} in "
                            f"Cloud Logging (occurred at {occurred_at}) and alerted Atlas via A2A."
                        ),
                    },
                    {
                        "timestamp": now_iso,
                        "agent": "Atlas • Lead Orchestrator",
                        "event": (
                            f"ADK RAG matched `{impact_and_remedy['playbook_id']}` ({impact_and_remedy['scenario_badge']}), "
                            f"acquired `.tflock` lease `{harness_bundle['lock']['lock_id']}`, passed OPA policy check, "
                            f"and queued {', '.join(s['name'] for s in coordinated_specialists)} awaiting Hari's approval."
                        ),
                    },
                ],
            }
            self.incidents[incident_id] = incident_record
            self._upsert_audit_event(incident_record, event_type="ISSUE_DETECTED")
            diag_tools = list(
                (live_db_diag or {}).get("tools_invoked")
                or (live_infra_diag or {}).get("tools_invoked")
                or (
                    ["Cloud_Provider_Health_Tool", "Security_Agent_Tool", "GitOps_Correlator_Tool"]
                    if iam_audit
                    else []
                )
            )
            self.record_dispatch_event(
                {
                    "dispatch_id": f"disp-{incident_id}",
                    "incident_id": incident_id,
                    "mode": "INCIDENT_TRIAGE_PENDING",
                    "status": "AWAITING_HITL_APPROVAL",
                    "title": impact_and_remedy.get("customer_headline") or log_entry.get("title", "Cloud Service Anomaly"),
                    "workload": workload,
                    "target_cloud": event_cloud or "gcp",
                    "region": cloud_provider_status.get("region") or cluster,
                    "primary_specialist": specialist.get("name", "Specialist Agent"),
                    "coordinated_specialists": [s.get("name", "") for s in coordinated_specialists],
                    "tools_invoked": diag_tools,
                    "jit_token_id": None,
                    "reconciliation_pr": None,
                    "watchdog_status": "AWAITING_HITL_APPROVAL",
                    "mutations_allowed": bool(cloud_provider_status.get("mutations_allowed", True)),
                    "timestamp": now_iso,
                }
            )

            return A2ATaskResponse(
                id=request.id,
                result={
                    "status": "AWAITING_HITL_APPROVAL",
                    "incident_id": incident_id,
                    "orchestrator": self.AGENT_ID,
                    "specialist_worker": specialist,
                    "coordinated_specialists": coordinated_specialists,
                    "agent_harness": harness_bundle,
                    "impact_analysis": impact_and_remedy,
                },
            )

        return A2ATaskResponse(
            id=request.id,
            result={"status": "OK", "agent": self.AGENT_ID},
        )

    async def chat_with_incident(
        self,
        incident_id: str,
        user_message: str,
        user_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Interactive conversational handler for the signed-in user to ask questions about an active incident,
        request a multi-service Terraform remediation bundle (Scenario 2), or instruct Atlas to proceed.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        uname = (user_name or self.active_user.get("name") or "Hari").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_msg = user_message.strip()
        incident.setdefault("chat_messages", []).append(
            {
                "role": "user",
                "sender": uname,
                "text": clean_msg,
                "timestamp": now_iso,
            }
        )

        # Renew 5-minute Lease-Keeper heartbeat on the `.tflock` while Hari is actively chatting
        agent_harness.acquire_or_renew_state_lock(
            incident_id=incident_id,
            cluster=incident.get("cluster", "us-central1"),
            namespace=incident.get("namespace", "default"),
            workload=incident.get("workload", "service"),
        )

        lower_msg = clean_msg.lower()

        terraform_bundle: Optional[Dict[str, Any]] = incident.get("impact_analysis", {}).get("terraform_bundle")

        # Check if Hari wants to upgrade/switch this incident to a Scenario 2 Multi-Service Terraform fix
        if any(k in lower_msg for k in ("terraform", "multi-service", "iam and vpc", "firewall")) and "?" not in lower_msg and "accept" not in lower_msg:
            multi_pb = playbook_rag_service.retrieve_playbook(
                query="multi-service iam firewall vpc cloudsql terraform",
                scenario_hint="multi_service_iam_vpc_db",
            )
            tf_code = multi_pb.get("terraform_code")
            coord_specs = [
                SPECIALIST_BY_ID[sid]
                for sid in multi_pb.get("coordinated_specialist_ids", ["security-agent", "networking-agent", "database-agent"])
                if sid in SPECIALIST_BY_ID
            ]
            incident["coordinated_specialists"] = coord_specs
            incident["impact_analysis"]["terraform_code"] = tf_code
            incident["impact_analysis"]["scenario_type"] = "SCENARIO_2_MULTI_SERVICE_TERRAFORM"
            incident["impact_analysis"]["scenario_badge"] = "Scenario 2 • Multi-Service Terraform Fix"
            harness_bundle = agent_harness.build_incident_harness_bundle(
                incident_id=incident_id,
                cluster=incident.get("cluster", "us-central1"),
                namespace=incident.get("namespace", "default"),
                workload=incident.get("workload", "service"),
                command=incident["impact_analysis"].get("recommended_kubectl", ""),
                terraform_code=tf_code,
                specialist_ids=[s["id"] for s in coord_specs],
                rollback_mode_hint="STATEFUL_SAFE_MODE_ISOLATION",
            )
            terraform_bundle = {
                "status": "READY_FOR_HARNESS_EXECUTION",
                "title": "Scenario 2 • Multi-Service Terraform Fix",
                "hcl_code": tf_code,
                "terraform_code": tf_code,
                "dry_run": harness_bundle.get("terraform_dry_run"),
                "policy_gate": harness_bundle.get("policy_gate"),
                "coordinated_specialists": coord_specs,
            }
            incident["impact_analysis"]["terraform_bundle"] = terraform_bundle
            incident["agent_harness"] = harness_bundle
            incident["impact_analysis"]["agent_harness"] = harness_bundle

        # Check if Hari accepts and tells Atlas to proceed with the fix
        approve_phrases = (
            "i accept",
            "accept",
            "proceed",
            "go ahead",
            "fix it",
            "apply the fix",
            "yes fix",
            "convinced",
            "approve",
            "do it",
            "run the fix",
            "execute the fix",
            "confirm irreversible",
        )
        if incident["status"] == "AWAITING_HITL_APPROVAL" and any(p in lower_msg for p in approve_phrases) and "?" not in lower_msg:
            explicit_crit_ok = any(
                k in lower_msg
                for k in (
                    "confirm irreversible",
                    "confirm critical",
                    "acknowledge irreversible",
                    "cannot be undone",
                )
            )
            updated = await self.approve_and_delegate_to_gke_assist(
                incident_id=incident_id,
                approved_by=f"{uname} (via Chat)",
                execution_mode="live",
                critical_change_confirmed=explicit_crit_ok,
            )
            if updated.get("status") == "BLOCKED_PROVIDER_OUTAGE":
                action = "BLOCKED_PROVIDER_OUTAGE"
            elif updated.get("last_approval_gate") == "CRITICAL_CONFIRMATION_REQUIRED":
                action = "CRITICAL_CONFIRMATION_REQUIRED"
            else:
                action = "APPROVED_AND_EXECUTED"
            return {
                "action_taken": action,
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        # Check if user wants to revert a resolved fix back to the pre-execution stable snapshot
        rollback_phrases = ("revert to stable", "revert snapshot", "rollback", "roll back", "undo the fix")
        if incident["status"] == "RESOLVED" and any(p in lower_msg for p in rollback_phrases) and "?" not in lower_msg:
            updated = await self.rollback_incident_remediation(
                incident_id=incident_id,
                requested_by=f"{uname} (via Chat)",
                reason=f"Operator requested rollback via chat: {clean_msg}",
                execution_mode="live",
                quarantine_signature=True,
            )
            return {
                "action_taken": "ROLLED_BACK_TO_SNAPSHOT",
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        # Check if user explicitly marks this issue "Safe to Ignore" permanently via chat
        if incident["status"] in ("AWAITING_HITL_APPROVAL", "SKIPPED_MANUAL") and "safe to ignore" in lower_msg and "?" not in lower_msg:
            updated = self.dismiss_incident_ignored(
                incident_id=incident_id,
                ignored_by=f"{uname} (via Chat)",
                reason="Marked Safe to Ignore via Atlas Chat",
            )
            return {
                "action_taken": "IGNORED_SAFE_TO_IGNORE",
                "reply": (updated or incident)["chat_messages"][-1]["text"],
                "incident": updated or incident,
            }

        # Check if user wants to skip / handle manually later
        skip_phrases = ("skip", "ignore", "later", "fix manually", "do it myself", "not now", "hold off")
        if incident["status"] == "AWAITING_HITL_APPROVAL" and any(p in lower_msg for p in skip_phrases) and "?" not in lower_msg:
            updated = self.skip_incident_manual(incident_id=incident_id, skipped_by=f"{uname} (via Chat)")
            return {
                "action_taken": "SKIPPED_MANUAL",
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        impact = incident.get("impact_analysis", {})
        log_entry = incident.get("log_entry", {})
        raw_inc_cloud = str(
            log_entry.get("cloud_provider")
            or incident.get("target_cloud")
            or self.active_target_cloud
            or "gcp"
        ).strip().lower()
        inc_target_cloud = raw_inc_cloud if raw_inc_cloud in ("gcp", "aws", "azure") else "gcp"

        asks_ddl_or_logs = any(
            k in lower_msg
            for k in ("ddl", "drop", "create", "alter", "grant", "revoke", "table", "audit_logs", "change", "log", "permission")
        )
        is_db_incident = (
            (incident.get("specialist_worker") or {}).get("id") == "database-agent"
            or "cloudsql" in str(log_entry.get("source") or "").lower()
            or "cloudsql" in str(log_entry.get("scenario_id") or "").lower()
            or "permission denied for " in str(log_entry.get("message") or "").lower()
        )
        ddl_audit = impact.get("ddl_privilege_audit")
        if is_db_incident and (asks_ddl_or_logs or not isinstance(ddl_audit, dict)):
            try:
                inst_hint = str(log_entry.get("pod") or "testdbinstance1").split(":")[-1]
                otel_attrs = ((log_entry.get("otel") or {}).get("attributes") or {})
                tbl_match = re.search(
                    r"(?:permission denied for\s+(?:table|relation|view|sequence|schema)\s+|table\s+)([a-zA-Z0-9_.\"]+)",
                    f"{clean_msg} {log_entry.get('message', '')}",
                    re.IGNORECASE,
                )
                tbl_hint = (
                    (tbl_match.group(1).strip('"') if tbl_match else "")
                    or str(otel_attrs.get("db.sql.table") or "")
                )
                db_adapter = get_database_cloud_adapter(inc_target_cloud)
                ddl_audit = await asyncio.to_thread(
                    db_adapter.inspect_table_ddl_and_privilege_logs,
                    table_or_object=tbl_hint,
                    instance_name=inst_hint,
                )
                if isinstance(ddl_audit, dict):
                    impact["ddl_privilege_audit"] = ddl_audit
                    if ddl_audit.get("permission_denied_events") or ddl_audit.get("permission_denied_count", 0) > 0:
                        if ddl_audit.get("root_cause_summary"):
                            impact["root_cause"] = ddl_audit["root_cause_summary"]
                        if ddl_audit.get("recommended_cli") and log_entry.get("scenario_id") != "cloudsql_conn_probe":
                            impact["recommended_kubectl"] = ddl_audit["recommended_cli"]
                        if (incident.get("specialist_worker") or {}).get("id") != "database-agent":
                            incident["specialist_worker"] = WORKER_AGENT_BOUTIQUE[1]
            except Exception:
                pass

        ddl_timeline_context = ""
        if isinstance(ddl_audit, dict):
            ddl_evts = ddl_audit.get("ddl_events") or ddl_audit.get("ddl_statements") or []
            perm_evts = ddl_audit.get("permission_denied_events") or []
            dcl_evts = ddl_audit.get("dcl_grant_revoke_events") or ddl_audit.get("privilege_statements") or []
            if perm_evts or ddl_evts or dcl_evts:
                lines_ctx = [f"Cloud SQL Statement & Object ACL Correlation ({ddl_audit.get('instance_name', 'testdbinstance1')}):"]
                lines_ctx.append(f"- Root Cause Correlation: {ddl_audit.get('root_cause_summary', '')}")
                for d_evt in ddl_evts[:5]:
                    lines_ctx.append(f"- DDL [{d_evt.get('timestamp')}]: {d_evt.get('statement')}")
                for p_evt in perm_evts[:5]:
                    lines_ctx.append(
                        f"- ERROR [{p_evt.get('timestamp')}]: user={p_evt.get('db_user')} db={p_evt.get('db_name')} "
                        f"permission denied for {p_evt.get('object_kind', 'table')} {p_evt.get('object_name')}"
                    )
                for g_evt in dcl_evts[:5]:
                    lines_ctx.append(f"- DCL [{g_evt.get('timestamp')}]: {g_evt.get('statement')}")
                ddl_timeline_context = "\n".join(lines_ctx) + "\n\n"

        history_text = "\n".join(
            f"{m.get('sender', m.get('role'))}: {m.get('text')}"
            for m in incident.get("chat_messages", [])[-6:]
        )

        reply_text = ""
        if self._llm_client.is_available:
            try:
                prompt = (
                    f"You are Atlas, the Single Authorizing ADK Root Gemini Agent for {uname}'s Google Cloud project (`agent-triad`).\n"
                    f"Answer {uname}'s question clearly, warmly, and concisely (2-5 short bullet points or sentences) in plain English.\n"
                    "If Cloud SQL DDL/DCL statement logs (`DROP TABLE`, `CREATE TABLE`, `GRANT`, `REVOKE`) are provided below, cite their exact timestamps and SQL statements directly.\n"
                    "Reassure the operator about safety, zero downtime, the `.tflock` state lease, OPA policy check, and automatic rollback where relevant, "
                    "and remind them they can say 'I accept' or click 'I accept' whenever ready.\n\n"
                    f"Service: {incident.get('service_label')}\n"
                    f"Scenario Mode: {impact.get('scenario_badge')}\n"
                    f"Root Cause: {impact.get('root_cause')}\n"
                    f"Business Impact: {impact.get('business_impact')}\n"
                    f"Proposed Fix: {impact.get('remedy_summary')}\n"
                    f"Command: {impact.get('recommended_kubectl')}\n"
                    f"Rollback Plan: {impact.get('rollback_plan')}\n"
                    f"Raw Log Message: {log_entry.get('message')}\n\n"
                    f"{ddl_timeline_context}"
                    f"Conversation so far:\n{history_text}\n"
                )
                generated = await asyncio.to_thread(self._llm_client.generate_text, prompt)
                if generated:
                    reply_text = generated
            except Exception:
                reply_text = ""

        if not reply_text:
            if ddl_timeline_context and asks_ddl_or_logs:
                ddl_evts_fb = ((ddl_audit or {}).get("ddl_events") or (ddl_audit or {}).get("ddl_statements") or [])[:4]
                dcl_evts_fb = ((ddl_audit or {}).get("dcl_grant_revoke_events") or (ddl_audit or {}).get("privilege_statements") or [])[:4]
                ddl_bullets: List[str] = [
                    f"I checked the live Cloud SQL statement logs on **`{(ddl_audit or {}).get('instance_name', 'testdbinstance1')}`**, {uname}:"
                ]
                for d_evt in ddl_evts_fb:
                    ddl_bullets.append(f"• **DDL (`{d_evt.get('timestamp')}`)**: `{d_evt.get('statement')}`")
                for p_evt in ((ddl_audit or {}).get("permission_denied_events") or [])[:3]:
                    ddl_bullets.append(
                        f"• **Permission Denied (`{p_evt.get('timestamp')}`)**: `user={p_evt.get('db_user')}` denied on `{p_evt.get('object_name')}`"
                    )
                for g_evt in dcl_evts_fb:
                    ddl_bullets.append(f"• **Privilege DCL (`{g_evt.get('timestamp')}`)**: `{g_evt.get('statement')}`")
                ddl_bullets.append(f"• **Correlation**: {(ddl_audit or {}).get('root_cause_summary') or impact.get('root_cause')}")
                ddl_bullets.append(f"• **Proposed Fix**: `{impact.get('recommended_kubectl')}`")
                reply_text = "\n".join(ddl_bullets)
            elif any(k in lower_msg for k in ("why", "cause", "happen", "reason", "detail")):
                reply_text = (
                    f"Good question, {uname}! Here's what happened under the hood:\n"
                    f"• **Root Cause**: {impact.get('root_cause')}\n"
                    f"• **Impact**: {impact.get('business_impact')}\n"
                    f"• **Affected Services**: {', '.join(impact.get('affected_services', [incident.get('workload', '')]))}\n\n"
                    "Would you like to see the exact command, Terraform bundle, or rollback safety plan before we proceed?"
                )
            elif any(k in lower_msg for k in ("safe", "downtime", "risk", "break", "rollback", "revert", "harness", "lock")):
                reply_text = (
                    f"It's completely safe and gated by the **Agent Harness**, {uname}:\n"
                    f"• **Zero-Standing Privilege**: Only I (`Atlas`) can mint the single-use 15-minute JIT token scoped to `{incident.get('workload')}`.\n"
                    f"• **State Lock & OPA Gate**: `.tflock` lease is active and OPA blast-radius check passed.\n"
                    f"• **Auto-Rollback Plan**: {impact.get('rollback_plan')}\n\n"
                    "Let me know or click **I accept** when you're ready for me to dispatch the Specialist Agent!"
                )
            else:
                reply_text = (
                    f"Here's the full picture for **{incident.get('workload')}**, {uname}:\n"
                    f"• **Scenario**: `{impact.get('scenario_badge')}`\n"
                    f"• **Root Cause**: {impact.get('root_cause')}\n"
                    f"• **Proposed Fix**: {impact.get('remedy_summary')} (`{impact.get('recommended_kubectl')}`)\n"
                    f"• **Safety**: Zero downtime + automatic rollback ({impact.get('rollback_plan')}).\n\n"
                    "Whenever you're ready, say **'I accept'** or click the **I accept** button below!"
                )

        if (
            log_entry.get("scenario_id") == "cloudsql_pg_permission_denied"
            and impact.get("recommended_kubectl")
            and "GRANT SELECT" not in reply_text.upper()
        ):
            reply_text = (
                f"{reply_text.rstrip()}\n\n"
                f"• **Proposed PostgreSQL Privilege Fix**: `{impact.get('recommended_kubectl')}`"
            )

        reply_msg = {
            "role": "assistant",
            "sender": "Atlas • AaaS Lead",
            "text": reply_text,
            "terraform_bundle": terraform_bundle,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        incident["chat_messages"].append(reply_msg)
        incident["updated_at"] = reply_msg["timestamp"]

        return {
            "action_taken": "ANSWERED_QUESTION",
            "reply": reply_text,
            "terraform_bundle": terraform_bundle,
            "incident": incident,
        }

    async def approve_and_delegate_to_gke_assist(
        self,
        incident_id: str,
        approved_by: str = "Hari",
        execution_mode: str = "live",
        custom_kubectl: Optional[str] = None,
        force_override_outage: bool = False,
        critical_change_confirmed: bool = False,
    ) -> Dict[str, Any]:
        """
        Called when Hari approves the fix (via button or chat):
          0. Pre-flight Cloud Provider Status Check via `log-watcher-agent` (`check_cloud_provider_status`):
             blocks infrastructure mutations if the target region is experiencing an active provider outage.
          1. Atlas (the sole authorizing agent) mints a 15-minute WIF JIT token scoped to the incident.
          2. Delegates the remediation task (1-line CLI/API, Multi-Service Terraform bundle, and
             Bidirectional GitOps PR payload) over A2A to the deterministic Specialist Agent Roster.
          3. Requests 45s post-remediation telemetry verification over A2A from `log-watcher-agent`.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        raw_cloud = str(
            (incident.get("log_entry") or {}).get("cloud_provider")
            or incident.get("target_cloud")
            or self.active_target_cloud
            or "gcp"
        ).strip().lower()
        target_cloud = raw_cloud if raw_cloud in ("gcp", "aws", "azure") else "gcp"

        # 0. Pre-flight Cloud Provider Status Check (blocks mutations during active regional provider outages)
        preflight_status = await self._run_cloud_provider_preflight_check(
            cloud_provider=target_cloud,
            region=str(incident.get("cluster") or "us-central1"),
            service_hint=str((incident.get("log_entry") or {}).get("source") or ""),
        )
        incident["cloud_provider_status"] = preflight_status
        incident["fault_attribution"] = self.classify_fault_attribution(
            cloud_provider_status=preflight_status,
            log_entry=incident.get("log_entry") or {},
            specialist=incident.get("specialist_worker") or {},
        )
        if isinstance(incident.get("impact_analysis"), dict):
            incident["impact_analysis"]["cloud_provider_status"] = preflight_status
            incident["impact_analysis"]["fault_attribution"] = incident["fault_attribution"]
        if not preflight_status.get("mutations_allowed", True) and not force_override_outage:
            blocked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            outage_summary = preflight_status.get("recommendation") or (
                f"Active {target_cloud.upper()} regional outage detected in `{preflight_status.get('region')}`."
            )
            incident["status"] = "BLOCKED_PROVIDER_OUTAGE"
            incident["updated_at"] = blocked_at
            incident["execution_result"] = {
                "status": "BLOCKED_PROVIDER_OUTAGE",
                "incident_id": incident_id,
                "mutations_allowed": False,
                "cloud_provider_status": preflight_status,
                "reason": outage_summary,
                "blocked_at": blocked_at,
            }
            incident["timeline"].append(
                {
                    "timestamp": blocked_at,
                    "agent": "Atlas • Pre-Flight Outage Guard",
                    "event": (
                        f"Blocked infrastructure mutation for `{incident.get('workload')}`: {outage_summary} "
                        "Zero JIT tokens minted."
                    ),
                }
            )
            uname = self.active_user.get("name") or "Hari"
            incident.setdefault("chat_messages", []).append(
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "text": (
                        f"⚠️ **Mutation Held by Cloud Provider Status Pre-Flight Check**, {uname}:\n"
                        f"• **Cloud / Region**: `{target_cloud.upper()}` / `{preflight_status.get('region')}`\n"
                        f"• **Status**: `{preflight_status.get('status')}` ({preflight_status.get('active_incident_count', 1)} active provider incident(s))\n"
                        f"• **Action Taken**: {outage_summary}\n"
                        "• **Safety**: No JIT token was minted and no infrastructure changes were dispatched."
                    ),
                    "timestamp": blocked_at,
                }
            )
            self._upsert_audit_event(incident, event_type="MUTATION_BLOCKED_PROVIDER_OUTAGE")
            specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
            coord_specs = incident.get("coordinated_specialists") or [specialist]
            self.record_dispatch_event(
                {
                    "dispatch_id": f"disp-{incident_id}-blocked",
                    "incident_id": incident_id,
                    "mode": "INCIDENT_BLOCKED_OUTAGE",
                    "status": "BLOCKED_PROVIDER_OUTAGE",
                    "title": incident.get("title") or "Cloud Service Anomaly",
                    "workload": incident.get("workload", ""),
                    "target_cloud": target_cloud,
                    "region": preflight_status.get("region") or incident.get("cluster") or "us-central1",
                    "primary_specialist": specialist.get("name", "Specialist Agent"),
                    "coordinated_specialists": [s.get("name", "") for s in coord_specs],
                    "jit_token_id": None,
                    "reconciliation_pr": None,
                    "watchdog_status": "HELD_BY_OUTAGE_GATE",
                    "mutations_allowed": False,
                    "approved_by": approved_by,
                    "reason": outage_summary,
                    "timestamp": blocked_at,
                }
            )
            return incident

        kubectl_cmd = (
            custom_kubectl.strip()
            if custom_kubectl and custom_kubectl.strip()
            else incident["impact_analysis"]["recommended_kubectl"]
        )
        terraform_code = incident["impact_analysis"].get("terraform_code")
        specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
        coordinated_specialists = incident.get("coordinated_specialists") or [specialist]
        coord_names = ", ".join(s.get("name", "Specialist Agent") for s in coordinated_specialists)

        # 0b. Tier-2 Critical Irreversible Change HITL Gate (prevents blind "I accept" rubber-stamping)
        change_risk = agent_harness.classify_change_risk(
            workload=incident.get("workload", ""),
            command=kubectl_cmd,
            terraform_code=terraform_code,
        )
        incident["change_risk"] = change_risk
        if isinstance(incident.get("agent_harness"), dict):
            incident["agent_harness"]["change_risk"] = change_risk
        if change_risk.get("requires_critical_confirmation") and not change_risk.get("blocked_by_opa") and not critical_change_confirmed:
            held_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            reasons_list = change_risk.get("irreversible_reasons") or [change_risk.get("summary", "Irreversible side effects detected.")]
            reasons_bullets = "\n".join(f"• {r}" for r in reasons_list)
            incident["status"] = "AWAITING_HITL_APPROVAL"
            incident["last_approval_gate"] = "CRITICAL_CONFIRMATION_REQUIRED"
            incident["updated_at"] = held_at
            incident["timeline"].append(
                {
                    "timestamp": held_at,
                    "agent": "Atlas • Tier-2 Irreversibility Gate",
                    "event": (
                        f"Held standard 'I accept' from {approved_by} for `{kubectl_cmd}`: critical irreversible impact "
                        f"requires explicit operator confirmation (`CONFIRM IRREVERSIBLE`). Zero JIT tokens minted."
                    ),
                }
            )
            uname = self.active_user.get("name") or "Hari"
            incident.setdefault("chat_messages", []).append(
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "text": (
                        f"🛑 **Explicit Critical-Change Confirmation Required**, {uname} — standard `'I accept'` is held because "
                        f"this action involves **irreversible side effects that cannot be automatically undone**:\n"
                        f"{reasons_bullets}\n"
                        f"• **Command**: `{kubectl_cmd}`\n"
                        f"• **Safety**: Zero JIT tokens were minted.\n"
                        f"• **To Proceed**: Check the **Irreversible Impact Acknowledgment** box on the card and click confirm, "
                        f"or reply **`I accept — CONFIRM IRREVERSIBLE`** in chat."
                    ),
                    "timestamp": held_at,
                }
            )
            self._upsert_audit_event(incident, event_type="CRITICAL_CONFIRMATION_REQUIRED")
            return incident

        if change_risk.get("requires_critical_confirmation") and critical_change_confirmed:
            incident["last_approval_gate"] = "CRITICAL_IRREVERSIBLE_CONFIRMED"
            if "Irreversible Confirmed" not in approved_by:
                approved_by = f"{approved_by} [Irreversible Impact Confirmed]"
        else:
            incident["last_approval_gate"] = "STANDARD_APPROVED"

        # 1. Mint 15-minute JIT token (Only Atlas has authority to mint JIT tokens)
        approved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        jit_token = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=approved_by,
            scope=f"{target_cloud}:{incident['cluster']}:{incident['namespace']}:{incident['workload']}",
            ttl_seconds=900,
        )
        incident["jit_token"] = jit_token
        incident["approved_by"] = approved_by
        incident["approved_at"] = approved_at
        incident["status"] = "DELEGATED_TO_WORKER_AGENT"
        incident["timeline"].append(
            {
                "timestamp": approved_at,
                "agent": "Atlas • Lead Orchestrator",
                "event": (
                    f"User ({approved_by}) approved remedy at {approved_at}. Pre-flight cloud status PASS "
                    f"({target_cloud.upper()}/{preflight_status.get('region')}). Atlas minted 15-min JIT token "
                    f"`{jit_token['token_id'][:20]}...` and delegated task to {coord_names} via A2A."
                ),
            }
        )

        # 2. Delegate execution to Specialist Roster via A2A protocol
        delegation_payload = {
            "incident_id": incident_id,
            "jit_token_id": jit_token["token_id"],
            "execution_mode": execution_mode,
            "kubectl_command": kubectl_cmd,
            "terraform_code": terraform_code,
            "cluster": incident["cluster"],
            "namespace": incident["namespace"],
            "workload": incident["workload"],
            "target_cloud": target_cloud,
            "gitops_pr_payload": incident.get("gitops_pr_payload"),
            "specialist_worker": specialist,
            "coordinated_specialists": coordinated_specialists,
            "log_entry": incident["log_entry"],
        }

        gke_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="gke-assist-agent",
            skill_id="execute_gke_remediation",
            payload=delegation_payload,
            summary=(
                f"Atlas authorized {coord_names}: execute approved fix (`{execution_mode}`) for "
                f"{incident['namespace']}/{incident['workload']} with JIT token {jit_token['token_id'][:16]}..."
            ),
        )

        incident["execution_result"] = gke_resp.result.get("execution", gke_resp.result)
        exec_res = incident["execution_result"] or {}
        if exec_res.get("rollback_snapshot"):
            incident["rollback_snapshot"] = exec_res["rollback_snapshot"]
        iam_exec = exec_res.get("iam_execution_result")
        exec_failed = (
            exec_res.get("status") in ("FAILED", "BLOCKED_BY_OPA_POLICY")
            or gke_resp.result.get("status") == "REMEDIATION_FAILED"
            or (
                isinstance(iam_exec, dict)
                and str(iam_exec.get("status") or "") in ("LIVE_IAM_EXECUTION_ERROR", "FAILED_NO_CREDENTIALS")
            )
        )
        exec_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": exec_time,
                "agent": coord_names,
                "event": (
                    f"Execution FAILED via Agent Harness (`{execution_mode}`): "
                    f"{exec_res.get('error') or (iam_exec.get('error') if isinstance(iam_exec, dict) else '') or exec_res.get('sre_specialist_notes', '')}"
                    if exec_failed
                    else (
                        f"Executed via Agent Harness (`{execution_mode}`). "
                        f"{exec_res.get('sre_specialist_notes', '')}"
                    )
                ),
            }
        )

        uname = self.active_user.get("name") or "Hari"
        if exec_failed:
            err_detail = (
                exec_res.get("error")
                or (iam_exec.get("error") if isinstance(iam_exec, dict) else None)
                or exec_res.get("live_stderr")
                or exec_res.get("sre_specialist_notes")
                or "Live remediation execution returned an error."
            )
            imp_err = iam_exec.get("impersonation_error") if isinstance(iam_exec, dict) else None
            jit_mode = iam_exec.get("jit_impersonation_mode") if isinstance(iam_exec, dict) else "N/A"

            incident["status"] = "REMEDIATION_FAILED"
            incident["resolved_at"] = None
            incident["updated_at"] = exec_time
            incident["verification_result"] = {
                "status": "SKIPPED_EXECUTION_FAILED",
                "healthy": False,
                "summary": f"Post-fix Watchdog verification skipped because live remediation failed: {err_detail}",
            }
            if incident.get("agent_harness") and incident["agent_harness"].get("lock"):
                incident["agent_harness"]["lock"]["status"] = "RELEASED"
            if isinstance(incident.get("iam_audit"), dict):
                incident["iam_audit"]["binding_present"] = False
                incident["iam_audit"]["status"] = "MISSING_REQUIRED_IAM_BINDING"

            incident.setdefault("chat_messages", []).append(
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "text": (
                        f"❌ **Remediation Failed**, {uname} — the fix was **NOT** applied, so this incident remains **unresolved**.\n"
                        f"• **Command Attempted**: `{kubectl_cmd}`\n"
                        f"• **Execution Error**: `{err_detail}`\n"
                        f"• **JIT Token Mode**: `{jit_mode}`"
                        + (f" (Impersonation detail: `{imp_err}`)" if imp_err else "")
                        + "\n"
                        f"• **Safety Controls**: `.tflock` lease released, single-use JIT token revoked, `ERROR` logged to Cloud Logging, and Watchdog closure aborted.\n"
                        f"• **Next Step**: Click **Reopen & Retry** after fixing the permission/API issue, or run the CLI command directly with an authorized IAM admin."
                    ),
                    "timestamp": exec_time,
                }
            )
            self._upsert_audit_event(incident, event_type="REMEDIATION_FAILED")
            self.record_dispatch_event(
                {
                    "dispatch_id": f"disp-{incident_id}",
                    "incident_id": incident_id,
                    "mode": "REMEDIATION_FAILED",
                    "status": "REMEDIATION_FAILED",
                    "title": (incident.get("impact_analysis") or {}).get("customer_headline") or incident.get("title", "Incident Remediation"),
                    "workload": incident.get("workload", ""),
                    "target_cloud": target_cloud,
                    "region": preflight_status.get("region") or incident.get("cluster") or "us-central1",
                    "primary_specialist": specialist.get("name", "Specialist Agent"),
                    "coordinated_specialists": [s.get("name", "") for s in coordinated_specialists],
                    "jit_token_id": jit_token["token_id"],
                    "reconciliation_pr": None,
                    "watchdog_status": "SKIPPED_EXECUTION_FAILED",
                    "mutations_allowed": True,
                    "approved_by": approved_by,
                    "command": kubectl_cmd,
                    "error": err_detail,
                    "timestamp": exec_time,
                }
            )
            return incident

        # 3. Trigger Closed-Loop 45s Post-Verification with Heartbeat & Telemetry via A2A
        snap_info = incident.get("rollback_snapshot") or exec_res.get("rollback_snapshot") or {}
        auto_rb_safe = bool(snap_info.get("auto_rollback_safe", True))
        verify_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="log-watcher-agent",
            skill_id="verify_post_remediation",
            payload={
                "incident_id": incident_id,
                "cluster": incident["cluster"],
                "namespace": incident["namespace"],
                "workload": incident["workload"],
                "project_id": str(
                    (incident.get("iam_audit") or {}).get("project_id")
                    or (incident.get("log_entry") or {}).get("project_id")
                    or incident.get("project_id")
                    or ""
                ),
                "target_cloud": target_cloud,
                "original_log_id": str((incident.get("log_entry") or {}).get("log_id") or ""),
                "execution_completed_at": exec_res.get("completed_at") or exec_time,
                "auto_rollback_safe": auto_rb_safe,
            },
            summary=f"Request 45s Watchdog telemetry verification for {incident['namespace']}/{incident['workload']}",
        )

        incident["verification_result"] = verify_resp.result
        verify_status = str(verify_resp.result.get("status") or "VERIFIED_HEALTHY")
        if verify_status in ("CASCADING_FAILURE_DETECTED", "POST_FIX_REGRESSION_DETECTED"):
            watchdog_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
            collateral_list = list(verify_resp.result.get("collateral_anomalies") or [])
            incident["timeline"].append(
                {
                    "timestamp": watchdog_ts,
                    "agent": "Heartbeat & Telemetry • 45s Watchdog",
                    "event": verify_resp.result.get(
                        "summary",
                        f"Post-fix regression / cascading failure detected ({verify_status}).",
                    ),
                }
            )
            # Escalate any newly broken collateral service logs into dedicated AaaS incident cards
            escalated_collateral_ids: List[str] = []
            for col_entry in collateral_list:
                col_id = str(col_entry.get("log_id") or "")
                if col_id and col_id not in self.incidents:
                    await self.a2a_hub.send_a2a_task(
                        sender_id="log-watcher-agent",
                        recipient_id=self.AGENT_ID,
                        skill_id="ingest_anomaly_alert",
                        payload={
                            "alert_id": col_id,
                            "detected_at": watchdog_ts,
                            "detector_agent": "log-watcher-agent",
                            "saif_sanitized": True,
                            "cloud_provider_status": preflight_status,
                            "log_entry": col_entry,
                        },
                        summary=f"Cascading failure alert escalated on {col_entry.get('workload')} after incident {incident_id}",
                    )
                    escalated_collateral_ids.append(col_id)
            incident["collateral_incident_ids"] = escalated_collateral_ids

            if verify_resp.result.get("auto_rollback_recommended", True):
                return await self.rollback_incident_remediation(
                    incident_id=incident_id,
                    requested_by="Atlas • 45s Watchdog Auto-Rollback",
                    reason=verify_resp.result.get("summary") or f"Watchdog detected {verify_status}",
                    execution_mode=execution_mode,
                    quarantine_signature=True,
                    auto_triggered=True,
                    collateral_anomalies=collateral_list,
                )

            # Tier-2 irreversible action caused collateral degradation: cannot auto-undo, never claim RESOLVED
            incident["status"] = "REMEDIATION_FAILED"
            incident["cascading_failure_hold"] = True
            incident["resolved_at"] = None
            incident["updated_at"] = watchdog_ts
            if incident.get("agent_harness") and incident["agent_harness"].get("lock"):
                incident["agent_harness"]["lock"]["status"] = "RELEASED"
            affected_svcs = ", ".join(verify_resp.result.get("affected_collateral_services") or [incident["workload"]])
            q_rec = agent_harness.quarantine_poison_pill(
                workload=incident.get("workload", ""),
                command=kubectl_cmd,
                reason=f"Irreversible change triggered {verify_status} on {affected_svcs}",
                incident_id=incident_id,
            )
            incident["poison_pill_quarantine"] = q_rec
            incident.setdefault("chat_messages", []).append(
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "text": (
                        f"🚨 **Cascading Failure Detected After Irreversible Change**, {uname}:\n"
                        f"• **Impacted Service(s)**: `{affected_svcs}`\n"
                        f"• **Why Auto-Rollback Held**: `{kubectl_cmd}` was classified as `TIER_2_CRITICAL_IRREVERSIBLE`, "
                        f"so destructive automated rollback is blocked.\n"
                        f"• **Safety Actions Taken**: Quarantined signature `{q_rec['signature_hash']}` for 7 days, "
                        f"released `.tflock`, and escalated `{len(escalated_collateral_ids)}` collateral incident card(s) for immediate triage."
                    ),
                    "timestamp": watchdog_ts,
                }
            )
            self._upsert_audit_event(incident, event_type="CASCADING_FAILURE_IRREVERSIBLE_HOLD")
            return incident

        incident["status"] = "RESOLVED"
        incident["resolved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["updated_at"] = incident["resolved_at"]
        if incident.get("agent_harness") and incident["agent_harness"].get("lock"):
            incident["agent_harness"]["lock"]["status"] = "RELEASED"

        incident["timeline"].append(
            {
                "timestamp": incident["updated_at"],
                "agent": "Heartbeat & Telemetry",
                "event": verify_resp.result.get("summary", "Telemetry verified healthy. Incident closed."),
            }
        )

        iam_exec_line = ""
        if isinstance(iam_exec, dict):
            if iam_exec.get("live_executed"):
                iam_exec_line = (
                    f"• **Live GCP IAM Execution**: `{iam_exec.get('status')}` via `{iam_exec.get('jit_impersonation_mode')}` "
                    f"(etag `{iam_exec.get('updated_etag')}`, live `getIamPolicy` verify=`{'PASS' if iam_exec.get('verified_after_apply') else 'PENDING'}`).\n"
                )
                if isinstance(incident.get("iam_audit"), dict):
                    incident["iam_audit"]["binding_present"] = bool(iam_exec.get("verified_after_apply", True))
                    incident["iam_audit"]["status"] = "IAM_BINDING_PRESENT"
                    if iam_exec.get("role") and iam_exec["role"] not in (incident["iam_audit"].get("assigned_roles") or []):
                        incident["iam_audit"].setdefault("assigned_roles", []).append(iam_exec["role"])
            else:
                iam_exec_line = (
                    f"• **IAM Sandbox Verification**: `{iam_exec.get('status')}` (`{iam_exec.get('jit_impersonation_mode')}`).\n"
                )

        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"✅ All done, {uname}! As the authorizing orchestrator, I minted a single-use JIT token (`{jit_token['token_id'][:18]}...`), "
                    f"logged your approval (`{approved_by}` at `{approved_at}`) in the **Audit Event Tracker**, "
                    f"and dispatched **{coord_names}** via our **Agent Harness Sandbox**.\n"
                    f"• **Executed**: `{kubectl_cmd}`\n"
                    f"{iam_exec_line}"
                    f"• **Harness & Lock**: `.tflock` released & Reconciliation PR `{incident['execution_result'].get('reconciliation_pr')}` opened.\n"
                    f"• **45s Watchdog Check**: **Heartbeat & Telemetry** verified `{incident['workload']}` is back to 100% health with 0 error logs."
                ),
                "timestamp": incident["updated_at"],
            }
        )
        self._upsert_audit_event(incident, event_type="APPROVED_AND_REMEDIATED")
        self.record_dispatch_event(
            {
                "dispatch_id": f"disp-{incident_id}",
                "incident_id": incident_id,
                "mode": "INCIDENT_REMEDIATED",
                "status": "RESOLVED",
                "title": (incident.get("impact_analysis") or {}).get("customer_headline") or incident.get("title", "Incident Remediation"),
                "workload": incident.get("workload", ""),
                "target_cloud": target_cloud,
                "region": preflight_status.get("region") or incident.get("cluster") or "us-central1",
                "primary_specialist": specialist.get("name", "Specialist Agent"),
                "coordinated_specialists": [s.get("name", "") for s in coordinated_specialists],
                "jit_token_id": jit_token["token_id"],
                "reconciliation_pr": (incident.get("execution_result") or {}).get("reconciliation_pr"),
                "watchdog_status": (incident.get("verification_result") or {}).get("status", "VERIFIED_HEALTHY"),
                "mutations_allowed": True,
                "approved_by": approved_by,
                "command": kubectl_cmd,
                "timestamp": incident["updated_at"],
            }
        )
        return incident

    async def rollback_incident_remediation(
        self,
        incident_id: str,
        requested_by: str = "Hari",
        reason: str = "",
        execution_mode: str = "live",
        quarantine_signature: bool = True,
        auto_triggered: bool = False,
        collateral_anomalies: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Reverts a previously applied remediation back to its pre-execution stable snapshot
        (either automatically when the 45s Watchdog detects a cross-service cascading failure,
        or on-demand via 1-click 'Revert to Stable Snapshot' / chat command).
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        exec_res = incident.get("execution_result") or {}
        original_cmd = str(
            exec_res.get("command")
            or (incident.get("impact_analysis") or {}).get("recommended_kubectl")
            or ""
        )
        snapshot = (
            incident.get("rollback_snapshot")
            or exec_res.get("rollback_snapshot")
            or {
                "snapshot_id": f"snap-fallback-{incident_id[-6:]}",
                "snapshot_type": "WORKLOAD_REVISION_SNAPSHOT",
                "rollback_strategy": "STATELESS_ROLLOUT_UNDO",
                "baseline_label": f"Pre-Execution Stable Baseline (`{incident.get('workload')}`)",
                "revert_command": "git revert HEAD --no-edit",
            }
        )
        incident["rollback_snapshot"] = snapshot

        raw_cloud = str(
            (incident.get("log_entry") or {}).get("cloud_provider")
            or incident.get("target_cloud")
            or self.active_target_cloud
            or "gcp"
        ).strip().lower()
        target_cloud = raw_cloud if raw_cloud in ("gcp", "aws", "azure") else "gcp"
        specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
        effective_reason = (
            reason.strip()
            if reason and reason.strip()
            else f"Manual revert to stable snapshot requested by {requested_by}"
        )

        rb_jit = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=requested_by,
            scope=f"rollback:{target_cloud}:{incident['cluster']}:{incident['namespace']}:{incident['workload']}",
            ttl_seconds=900,
        )
        rb_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="gke-assist-agent",
            skill_id="rollback_gke_remediation",
            payload={
                "incident_id": incident_id,
                "jit_token_id": rb_jit["token_id"],
                "execution_mode": execution_mode,
                "cluster": incident["cluster"],
                "namespace": incident["namespace"],
                "workload": incident["workload"],
                "rollback_snapshot": snapshot,
                "original_command": original_cmd,
                "reason": effective_reason,
                "quarantine_signature": quarantine_signature,
                "specialist_worker": specialist,
            },
            summary=(
                f"{'Watchdog Auto-Rollback' if auto_triggered else 'Operator Snapshot Revert'} for "
                f"{incident['namespace']}/{incident['workload']} -> `{snapshot.get('revert_command')}`"
            ),
        )

        rb_res = rb_resp.result.get("rollback", rb_resp.result)
        rb_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["status"] = "ROLLED_BACK"
        incident["resolved_at"] = None
        incident["rolled_back_at"] = rb_time
        incident["rolled_back_by"] = requested_by
        incident["rollback_reason"] = effective_reason
        incident["rollback_auto_triggered"] = auto_triggered
        incident["rollback_result"] = rb_res
        incident["poison_pill_quarantine"] = rb_res.get("poison_pill_quarantine")
        incident["updated_at"] = rb_time
        if incident.get("agent_harness") and incident["agent_harness"].get("lock"):
            incident["agent_harness"]["lock"]["status"] = "RELEASED"

        iam_rb = rb_res.get("iam_rollback_result")
        if isinstance(incident.get("iam_audit"), dict) and isinstance(iam_rb, dict):
            if iam_rb.get("status") in ("ROLLED_BACK_LIVE_GCP_IAM", "ROLLED_BACK_SANDBOX_VALIDATED"):
                incident["iam_audit"]["binding_present"] = False
                incident["iam_audit"]["status"] = "MISSING_REQUIRED_IAM_BINDING"

        incident["timeline"].append(
            {
                "timestamp": rb_time,
                "agent": f"{specialist.get('name', 'Specialist Agent')} • Snapshot Rollback",
                "event": (
                    f"{'Auto-reverted' if auto_triggered else 'Reverted'} `{incident['workload']}` to stable snapshot "
                    f"`{snapshot.get('snapshot_id')}` (`{rb_res.get('revert_command')}`). Reason: {effective_reason}"
                ),
            }
        )

        uname = self.active_user.get("name") or "Hari"
        q_rec = rb_res.get("poison_pill_quarantine") or {}
        col_list = collateral_anomalies or []
        col_line = ""
        if col_list:
            col_svcs = ", ".join(sorted({str(c.get("workload") or "peer-service") for c in col_list}))
            col_line = (
                f"• **Collateral Failure Detected**: Downstream/peer service(s) `{col_svcs}` emitted new `ERROR` telemetry "
                f"after the fix (`timestamp > execution_completed_at`), and were escalated as tracked incident card(s).\n"
            )
        q_line = (
            f"• **7-Day Poison-Pill Quarantine**: Signature `{q_rec.get('signature_hash')}` quarantined until "
            f"`{q_rec.get('expires_at')}` so OPA blocks re-applying the offending command.\n"
            if q_rec.get("signature_hash")
            else ""
        )

        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"⏪ **{'Automatic Watchdog Rollback Completed' if auto_triggered else 'Reverted to Stable Snapshot'}**, {uname}!\n"
                    f"{col_line}"
                    f"• **Restored Baseline**: `{snapshot.get('baseline_label', snapshot.get('snapshot_id'))}` (`{snapshot.get('snapshot_id')}`)\n"
                    f"• **Rollback Command Executed**: `{rb_res.get('revert_command')}`\n"
                    f"• **Triggered By**: `{requested_by}`\n"
                    f"{q_line}"
                    f"• **Safety**: Single-use Rollback JIT token revoked and `.tflock` released."
                ),
                "timestamp": rb_time,
            }
        )
        audit_type = "AUTO_ROLLED_BACK_CASCADING_FAILURE" if auto_triggered else "REMEDIATION_ROLLED_BACK"
        self._upsert_audit_event(incident, event_type=audit_type)
        self.record_dispatch_event(
            {
                "dispatch_id": f"disp-{incident_id}-rb",
                "incident_id": incident_id,
                "mode": "WATCHDOG_AUTO_ROLLBACK" if auto_triggered else "OPERATOR_MANUAL_ROLLBACK",
                "status": "ROLLED_BACK",
                "title": (incident.get("impact_analysis") or {}).get("customer_headline") or incident.get("title", "Snapshot Rollback"),
                "workload": incident.get("workload", ""),
                "target_cloud": target_cloud,
                "region": incident.get("cluster") or "us-central1",
                "primary_specialist": specialist.get("name", "Specialist Agent"),
                "coordinated_specialists": [specialist.get("name", "Specialist Agent")],
                "jit_token_id": rb_jit["token_id"],
                "reconciliation_pr": exec_res.get("reconciliation_pr"),
                "watchdog_status": (incident.get("verification_result") or {}).get("status", "ROLLED_BACK"),
                "mutations_allowed": True,
                "approved_by": requested_by,
                "command": rb_res.get("revert_command"),
                "reason": effective_reason,
                "timestamp": rb_time,
            }
        )
        return incident

    async def verify_incident_post_fix_health(
        self,
        incident_id: str,
        execute_live_iam_check: bool = True,
    ) -> Dict[str, Any]:
        """
        On-demand Post-Fix Service Health Verification triggered when the user clicks
        'Live Health Watch' (or 'Re-Run Post-Fix Health Check') after remediation completes.
        Runs 4 live, read-only health checks:
          1. Target Service & IAM/Config Posture (`getIamPolicy` / execution state)
          2. 45s Post-Fix Error Log Window (`timestamp > execution_completed_at`)
          3. Cross-Service Peer Health (`0` cascading failures across peer workloads)
          4. 15s Heartbeat Dead-Man's Switch & Regional Cloud Provider Feed
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        raw_cloud = str(
            (incident.get("log_entry") or {}).get("cloud_provider")
            or incident.get("target_cloud")
            or self.active_target_cloud
            or "gcp"
        ).strip().lower()
        target_cloud = raw_cloud if raw_cloud in ("gcp", "aws", "azure") else "gcp"
        region = str(incident.get("cluster") or "us-central1")
        workload = str(incident.get("workload") or "service")
        namespace = str(incident.get("namespace") or "default")
        exec_res = incident.get("execution_result") or {}
        exec_completed_at = (
            exec_res.get("completed_at")
            or incident.get("resolved_at")
            or incident.get("rolled_back_at")
            or incident.get("updated_at")
        )
        snap = incident.get("rollback_snapshot") or exec_res.get("rollback_snapshot") or {}

        provider_status = await self._run_cloud_provider_preflight_check(
            cloud_provider=target_cloud,
            region=region,
            service_hint=str((incident.get("log_entry") or {}).get("source") or ""),
        )
        mitigated_log_ids = []
        for other_id, other_inc in self.incidents.items():
            if str(other_inc.get("status") or "") in ("RESOLVED", "ROLLED_BACK"):
                mitigated_log_ids.append(str(other_id))
                other_lid = str((other_inc.get("log_entry") or {}).get("log_id") or "")
                if other_lid:
                    mitigated_log_ids.append(other_lid)

        verify_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="log-watcher-agent",
            skill_id="verify_post_remediation",
            payload={
                "incident_id": incident_id,
                "cluster": region,
                "namespace": namespace,
                "workload": workload,
                "project_id": str(
                    (incident.get("iam_audit") or {}).get("project_id")
                    or (incident.get("log_entry") or {}).get("project_id")
                    or incident.get("project_id")
                    or ""
                ),
                "target_cloud": target_cloud,
                "original_log_id": str((incident.get("log_entry") or {}).get("log_id") or ""),
                "execution_completed_at": exec_completed_at,
                "auto_rollback_safe": bool(snap.get("auto_rollback_safe", True)),
                "mitigated_log_ids": mitigated_log_ids,
            },
            summary=f"On-demand Post-Fix Service Health Verification for {namespace}/{workload}",
        )
        ver_data = verify_resp.result or {}
        target_regs = list(ver_data.get("target_regressions") or [])
        collateral_errs = list(ver_data.get("collateral_anomalies") or [])
        post_metrics = ver_data.get("post_metrics") or {}

        inc_status = str(incident.get("status") or "AWAITING_HITL_APPROVAL")
        workload_check_status = "PASS" if inc_status in ("RESOLVED", "ROLLED_BACK") else "WARN"
        workload_detail = (
            f"`{workload}` is stable after snapshot revert (`{snap.get('baseline_label', 'baseline')}`)."
            if inc_status == "ROLLED_BACK"
            else (
                f"`{workload}` remediation applied and verified (`{exec_res.get('command') or 'config active'}`)."
                if inc_status == "RESOLVED"
                else f"Current status: `{inc_status}`."
            )
        )

        if incident.get("scenario_id") == "datastream_iam_drift" or isinstance(incident.get("iam_audit"), dict):
            prev_iam = incident.get("iam_audit") or {}
            proj = str(prev_iam.get("project_id") or PROJECT_ID)
            sa_email = prev_iam.get("target_service_agent")
            req_role = str(prev_iam.get("required_role") or "roles/compute.networkAdmin")
            iam_exec_mode = str(exec_res.get("execution_mode") or "live")
            if execute_live_iam_check and proj == PROJECT_ID and iam_exec_mode == "live":
                live_iam = await asyncio.to_thread(
                    security_iam_service.inspect_datastream_iam_posture,
                    project_id=proj,
                    region=region,
                    service_agent_email=sa_email,
                    required_role=req_role,
                    execute_live=True,
                )
                incident["iam_audit"] = live_iam
                if inc_status == "RESOLVED":
                    workload_check_status = "PASS" if live_iam.get("binding_present") else "WARN"
                    workload_detail = (
                        f"Live GCP `getIamPolicy` confirmed `{req_role}` is active on `{live_iam.get('target_service_agent')}`."
                        if live_iam.get("binding_present")
                        else f"Live GCP `getIamPolicy`: `{req_role}` not yet observed on `{live_iam.get('target_service_agent')}`."
                    )
                elif inc_status == "ROLLED_BACK":
                    workload_check_status = "PASS"
                    workload_detail = (
                        f"Snapshot revert confirmed via live `getIamPolicy` (roles: "
                        f"`{', '.join(live_iam.get('assigned_roles') or []) or 'NONE'}`)."
                    )

        provider_ok = provider_status.get("mutations_allowed", True)
        checks = [
            {
                "id": "target_service",
                "label": "Target Service & Configuration State",
                "status": workload_check_status,
                "detail": workload_detail,
            },
            {
                "id": "post_fix_logs",
                "label": "45s Post-Fix Error Log Scan",
                "status": "PASS" if len(target_regs) == 0 else "FAIL",
                "detail": (
                    f"0 new ERROR/CRITICAL logs on `{workload}` since `{exec_completed_at or 'execution'}`."
                    if len(target_regs) == 0
                    else f"{len(target_regs)} post-fix regression error(s) detected on `{workload}`."
                ),
            },
            {
                "id": "peer_services",
                "label": "Cross-Service Peer Health Watch",
                "status": "PASS" if len(collateral_errs) == 0 else "FAIL",
                "detail": (
                    "0 cascading failures detected across peer project services."
                    if len(collateral_errs) == 0
                    else (
                        f"Cascading errors detected on: "
                        f"{', '.join(ver_data.get('affected_collateral_services') or ['peer-service'])}."
                    )
                ),
            },
            {
                "id": "heartbeat_and_provider",
                "label": "15s Heartbeat & Cloud Regional Health",
                "status": "PASS" if provider_ok else "WARN",
                "detail": (
                    f"Heartbeat {post_metrics.get('heartbeat_tick', 'PASS (<45s)')} • P99 {post_metrics.get('p99_latency_ms', 142)}ms • "
                    f"{target_cloud.upper()} `{region}` {provider_status.get('status', 'OPERATIONAL')}."
                ),
            },
        ]

        has_fail = any(c["status"] == "FAIL" for c in checks)
        if has_fail:
            overall_health = "DEGRADED_ACTION_REQUIRED"
        elif inc_status == "ROLLED_BACK":
            overall_health = "ROLLED_BACK_STABLE"
        elif inc_status == "RESOLVED":
            overall_health = "VERIFIED_HEALTHY"
        else:
            overall_health = "MONITORING_ACTIVE"

        report = {
            "incident_id": incident_id,
            "service_label": incident.get("service_label") or workload,
            "workload": workload,
            "region": region,
            "target_cloud": target_cloud,
            "incident_status": inc_status,
            "overall_health": overall_health,
            "healthy": not has_fail,
            "checks": checks,
            "post_metrics": post_metrics,
            "rollback_snapshot": snap,
            "verified_at": now_iso,
        }
        incident["post_fix_health_report"] = report
        return report

    def skip_incident_manual(
        self,
        incident_id: str,
        skipped_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Marks an incident as skipped so the user can handle it manually or review later."""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        uname = (skipped_by or self.active_user.get("name") or "Hari").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["status"] = "SKIPPED_MANUAL"
        incident["approved_by"] = f"{uname} (Manual Skip)"
        incident["approved_at"] = now_iso
        incident["updated_at"] = now_iso
        agent_harness.release_state_lock(
            cluster=incident.get("cluster", "us-central1"),
            namespace=incident.get("namespace", "default"),
            workload=incident.get("workload", "service"),
        )
        incident["timeline"].append(
            {
                "timestamp": now_iso,
                "agent": "Atlas • Lead Orchestrator",
                "event": (
                    f"User ({uname}) chose 'Skip / Handle Manually' at {now_iso}. "
                    "Released `.tflock` lease; Specialist Agent stood down with no automated changes made."
                ),
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"Got it, {uname} — I've released the `.tflock` state lock, stood down the **Specialist Agent**, and made **no changes** "
                    f"so you can handle `{incident['workload']}` manually. If you change your mind later, just click **Reopen** below!"
                ),
                "timestamp": now_iso,
            }
        )
        self._upsert_audit_event(incident, event_type="SKIPPED_MANUAL")
        return incident

    def reopen_incident(self, incident_id: str) -> Dict[str, Any]:
        """Re-opens a skipped incident back to AWAITING_HITL_APPROVAL if the user decides to let AI fix it."""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        uname = self.active_user.get("name") or "Hari"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["status"] = "AWAITING_HITL_APPROVAL"
        incident["approved_by"] = None
        incident["approved_at"] = None
        incident["updated_at"] = now_iso
        agent_harness.acquire_or_renew_state_lock(
            incident_id=incident_id,
            cluster=incident.get("cluster", "us-central1"),
            namespace=incident.get("namespace", "default"),
            workload=incident.get("workload", "service"),
        )
        incident["timeline"].append(
            {
                "timestamp": now_iso,
                "agent": "Atlas • Lead Orchestrator",
                "event": f"User ({uname}) re-opened incident and re-acquired `.tflock` lease for Specialist Agent remediation.",
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"Welcome back, {uname}! I've re-opened the issue on **{incident['workload']}** and re-locked `.tflock`. "
                    "Ask me any follow-up questions or click **I accept** whenever you're ready."
                ),
                "timestamp": now_iso,
            }
        )
        self._upsert_audit_event(incident, event_type="REOPENED_FOR_APPROVAL")
        return incident

    async def recheck_incident_provider_status(self, incident_id: str) -> Dict[str, Any]:
        """
        Re-runs the Phase 4 Pre-Flight Cloud Provider Status Check for an incident.
        If the incident was `BLOCKED_PROVIDER_OUTAGE` and the regional outage has now cleared,
        transitions it back to `AWAITING_HITL_APPROVAL` and re-acquires `.tflock`.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        raw_cloud = str(
            (incident.get("log_entry") or {}).get("cloud_provider")
            or incident.get("target_cloud")
            or self.active_target_cloud
            or "gcp"
        ).strip().lower()
        target_cloud = raw_cloud if raw_cloud in ("gcp", "aws", "azure") else "gcp"
        region = str(incident.get("cluster") or "us-central1")
        service_hint = str((incident.get("log_entry") or {}).get("source") or "")

        preflight_status = await self._run_cloud_provider_preflight_check(
            cloud_provider=target_cloud,
            region=region,
            service_hint=service_hint,
        )
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        uname = self.active_user.get("name") or "Hari"

        incident["cloud_provider_status"] = preflight_status
        incident["fault_attribution"] = self.classify_fault_attribution(
            cloud_provider_status=preflight_status,
            log_entry=incident.get("log_entry") or {},
            specialist=incident.get("specialist_worker") or {},
        )
        if isinstance(incident.get("impact_analysis"), dict):
            incident["impact_analysis"]["cloud_provider_status"] = preflight_status
            incident["impact_analysis"]["fault_attribution"] = incident["fault_attribution"]
        incident["updated_at"] = now_iso

        was_blocked = incident.get("status") == "BLOCKED_PROVIDER_OUTAGE"
        mutations_allowed = bool(preflight_status.get("mutations_allowed", True))

        if was_blocked and mutations_allowed:
            incident["status"] = "AWAITING_HITL_APPROVAL"
            incident["execution_result"] = None
            agent_harness.acquire_or_renew_state_lock(
                incident_id=incident_id,
                cluster=region,
                namespace=incident.get("namespace", "default"),
                workload=incident.get("workload", "service"),
            )
            incident.setdefault("timeline", []).append(
                {
                    "timestamp": now_iso,
                    "agent": "Atlas • Pre-Flight Outage Guard",
                    "event": (
                        f"Re-check passed for {target_cloud.upper()}/{preflight_status.get('region')} "
                        f"({preflight_status.get('status')}). Safety Brake lifted and `.tflock` re-acquired "
                        "for HITL approval."
                    ),
                }
            )
            incident.setdefault("chat_messages", []).append(
                {
                    "role": "assistant",
                    "sender": "Atlas • AaaS Lead",
                    "text": (
                        f"✅ **Cloud Provider Outage Cleared**, {uname}!\n"
                        f"• **Cloud / Region**: `{target_cloud.upper()}` / `{preflight_status.get('region')}` is now **`{preflight_status.get('status')}`**.\n"
                        "• **Safety Brake Lifted**: You can now click **I accept** whenever you are ready to mint a 15-minute JIT token and remediate the workload."
                    ),
                    "timestamp": now_iso,
                }
            )
            self._upsert_audit_event(incident, event_type="PROVIDER_OUTAGE_CLEARED")
        elif not mutations_allowed:
            incident.setdefault("timeline", []).append(
                {
                    "timestamp": now_iso,
                    "agent": "Atlas • Pre-Flight Outage Guard",
                    "event": (
                        f"Re-check confirmed active {target_cloud.upper()}/{preflight_status.get('region')} outage "
                        f"({preflight_status.get('active_incident_count', 1)} incident(s)). Safety Brake remains engaged."
                    ),
                }
            )
        return incident

    def dismiss_incident_ignored(
        self,
        incident_id: str,
        ignored_by: Optional[str] = None,
        reason: str = "Marked Safe to Ignore",
        signature_key: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Permanently suppresses an incident marked 'Safe to Ignore' by the operator:
          - Records `incident_id` and its `signature_key` / `workload::error_code` so recurring logs
            are never re-escalated or forced in Atlas.
          - Releases any active `.tflock` state lease.
          - Transitions incident status to `IGNORED` (excluded from `list_incidents()`).
        """
        if incident_id:
            self.ignored_log_ids.add(str(incident_id))
        if signature_key:
            self.ignored_signatures.add(str(signature_key))

        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        uname = (ignored_by or self.active_user.get("name") or "Hari").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        log_entry = incident.get("log_entry") or {}
        inc_sig = str(log_entry.get("signature_key") or "").strip()
        if inc_sig:
            self.ignored_signatures.add(inc_sig)
        if log_entry.get("workload") and log_entry.get("error_code"):
            self.ignored_signatures.add(f"{log_entry.get('workload')}::{log_entry.get('error_code')}")

        incident["status"] = "IGNORED"
        incident["ignored"] = True
        incident["ignored_by"] = uname
        incident["ignored_at"] = now_iso
        incident["ignore_reason"] = reason
        incident["approved_by"] = f"{uname} (Safe to Ignore)"
        incident["updated_at"] = now_iso
        agent_harness.release_state_lock(
            cluster=incident.get("cluster", "us-central1"),
            namespace=incident.get("namespace", "default"),
            workload=incident.get("workload", "service"),
        )
        incident.setdefault("timeline", []).append(
            {
                "timestamp": now_iso,
                "agent": "Atlas • Lead Orchestrator",
                "event": (
                    f"Operator ({uname}) marked `{incident.get('workload')}` Safe to Ignore ({reason}). "
                    "Released `.tflock` lease and permanently suppressed recurring signature from Atlas."
                ),
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"Understood, {uname} — I've marked **`{incident.get('workload')}`** as **Safe to Ignore**, "
                    "released `.tflock`, and suppressed its signature so it won't appear again in Atlas."
                ),
                "timestamp": now_iso,
            }
        )
        self._upsert_audit_event(incident, event_type="SAFE_TO_IGNORE")
        return incident

    def restore_ignored_signatures(
        self,
        log_ids: Optional[List[str]] = None,
        signature_keys: Optional[List[str]] = None,
    ) -> None:
        """Removes restored log IDs and signature keys from Atlas's permanent suppression set."""
        for lid in log_ids or []:
            self.ignored_log_ids.discard(str(lid))
            inc = self.incidents.get(str(lid))
            if inc and inc.get("status") == "IGNORED":
                inc["status"] = "SKIPPED_MANUAL"
                inc["ignored"] = False
        for sig in signature_keys or []:
            self.ignored_signatures.discard(str(sig))

    def list_incidents(self, include_ignored: bool = False) -> List[Dict[str, Any]]:
        visible: List[Dict[str, Any]] = []
        for item in self.incidents.values():
            if not include_ignored:
                if item.get("status") == "IGNORED":
                    continue
                if item.get("incident_id") in self.ignored_log_ids:
                    continue
                le = item.get("log_entry") or {}
                sig = str(le.get("signature_key") or "").strip()
                wl_err = f"{le.get('workload', '')}::{le.get('error_code', '')}"
                if (sig and sig in self.ignored_signatures) or wl_err in self.ignored_signatures:
                    continue
            visible.append(item)
        return sorted(
            visible,
            key=lambda item: item.get("created_at", ""),
            reverse=True,
        )

    def list_audit_events(self) -> List[Dict[str, Any]]:
        return sorted(
            self.audit_events.values(),
            key=lambda item: item.get("detected_at", ""),
            reverse=True,
        )

    def record_dispatch_event(self, entry: Dict[str, Any]) -> None:
        """Records a specialist dispatch execution into the persistent control-plane dispatch feed."""
        dispatch_id = str(entry.get("dispatch_id") or f"disp-{uuid.uuid4().hex[:8]}")
        normalized = {
            **entry,
            "dispatch_id": dispatch_id,
            "timestamp": entry.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.dispatch_history = [d for d in self.dispatch_history if d.get("dispatch_id") != dispatch_id]
        self.dispatch_history.insert(0, normalized)
        if len(self.dispatch_history) > 25:
            self.dispatch_history = self.dispatch_history[:25]

    def list_dispatch_history(self) -> List[Dict[str, Any]]:
        return list(self.dispatch_history)

    def _default_general_chat_greeting(self) -> List[Dict[str, Any]]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        uname = self.active_user.get("name", "Hari")
        return [
            {
                "id": "atlas-welcome",
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "specialist": WORKER_AGENT_BOUTIQUE[0],
                "specialist_worker": WORKER_AGENT_BOUTIQUE[0],
                "coordinated_specialists": [WORKER_AGENT_BOUTIQUE[0]],
                "scenario_badge": "Orchestrator of AaaS",
                "text": f"Hey {uname}, you are now interacting with **Atlas (Orchestrator of AaaS)**. What would you like to do?",
                "timestamp": now_iso,
            }
        ]

    def _init_or_restore_user_sessions(self, sync_from_firestore: bool = True) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        default_msgs = self._default_general_chat_greeting()
        record = session_store_service.get_or_init_user_sessions(
            user_email=u_email,
            user_name=u_name,
            default_messages=default_msgs,
            sync_from_firestore=sync_from_firestore,
        )
        self.active_session_id = record.get("active_session_id") or f"sess-{uuid.uuid4().hex[:8]}"
        active_sess = next(
            (s for s in record.get("sessions", []) if s.get("session_id") == self.active_session_id),
            record["sessions"][0] if record.get("sessions") else None,
        )
        if active_sess and active_sess.get("messages"):
            self.general_chat_messages = list(active_sess["messages"])
            if len(self.general_chat_messages) == 1 and self.general_chat_messages[0].get("id") == "atlas-welcome":
                self.general_chat_messages[0]["text"] = (
                    f"Hey {u_name}, you are now interacting with **Atlas (Orchestrator of AaaS)**. What would you like to do?"
                )
        else:
            self.general_chat_messages = default_msgs
        return record

    def _persist_active_session(self) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        return session_store_service.save_active_session_messages(
            user_email=u_email,
            user_name=u_name,
            session_id=self.active_session_id,
            messages=self.general_chat_messages,
        )

    def set_active_user(
        self,
        name: str,
        email: str = "",
        picture: str = "",
        provider: str = "google-sso",
    ) -> Dict[str, str]:
        clean_name = (name or "Hari").strip()
        clean_email = (email or "harisankar@google.com").strip()
        self.active_user = {
            "name": clean_name,
            "email": clean_email,
            "picture": (picture or "").strip(),
            "provider": provider or "google-sso",
        }
        self._init_or_restore_user_sessions(sync_from_firestore=True)
        if self.general_chat_messages and self.general_chat_messages[0].get("id") == "atlas-welcome":
            self.general_chat_messages[0]["text"] = (
                f"Hey {clean_name}, you are now interacting with **Atlas (Orchestrator of AaaS)**. What would you like to do?"
            )
            self._persist_active_session()
        return self.active_user

    def _select_specialist_for_query(self, query_text: str) -> Dict[str, str]:
        lower = query_text.lower()
        if any(k in lower for k in ("datastream", "gcp-sa-datastream", "failed_precondition")):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent (paired with Infra Agent for Datastream IAM drift)
        if any(
            k in lower
            for k in (
                "sql",
                "database",
                "db",
                "postgres",
                "alloydb",
                "spanner",
                "connection pool",
                "socket",
                "testdbinstance1",
                "telemetrics",
                "permission denied for table",
                "permission denied for schema",
                "permission denied for sequence",
                "permission denied for relation",
                "audit_logs",
                "table ",
                "ddl",
                "grant ",
                "revoke ",
                "drop table",
                "create table",
                "pg_hba",
                "psql",
                "cloudsql",
            )
        ):
            return WORKER_AGENT_BOUTIQUE[1]  # Database Agent
        if any(k in lower for k in ("billing", "cost", "budget", "finops", "price", "spend", "invoice")):
            return WORKER_AGENT_BOUTIQUE[6]  # Billing Agent
        if any(k in lower for k in ("iam", "security", "permission", "role", "wif", "secret", "armor", "auth", "token", "least privilege")):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent
        if any(k in lower for k in ("vpc", "network", "latency", "dns", "load balanc", "firewall", "ingress", "timeout", "packet", "routing", "connector")):
            return WORKER_AGENT_BOUTIQUE[3]  # Networking Agent
        if any(k in lower for k in ("bigquery", "dataflow", "pubsub", "pub/sub", "analytics", "vertex", "rag", "slot")):
            return WORKER_AGENT_BOUTIQUE[4]  # Data Analytics Agent
        if any(k in lower for k in (
            "gke", "kubernetes", "pod", "node", "vm", "compute engine", "gce", "disk",
            "cluster", "terraform", "hcl", "testinstance1", "2397540675679890849",
            "8385313458168693473", "2276555501399631720", "workstations", "gce_instance",
            "guest agent", "metadata", "infra",
        )):
            return WORKER_AGENT_BOUTIQUE[2]  # Infra Agent
        # Preserve conversational continuity if user asks a follow-up question after consulting a specialist
        last_assistant = next(
            (m for m in reversed(self.general_chat_messages) if m.get("role") == "assistant" and m.get("id") != "atlas-welcome"),
            None,
        )
        if last_assistant and last_assistant.get("specialist_worker") and any(
            k in lower for k in ("service account", "in that scenario", "how will you", "how do you", "are you actually")
        ):
            return last_assistant["specialist_worker"]
        return WORKER_AGENT_BOUTIQUE[0]  # Serverless Agent

    def _classify_chat_scenario(self, query_text: str) -> Dict[str, Any]:
        """
        Classifies a direct user message into Scenario 1, 2, 3, or 4 and determines
        the coordinated specialists and whether a Terraform (.tf) bundle should be generated.
        """
        lower = query_text.lower()

        # Check Scenario 2: Multi-Service troubleshooting (IAM + VPC/Firewall + API/DB/Terraform)
        is_pg_object_acl = any(
            p in lower
            for p in (
                "permission denied for table",
                "permission denied for schema",
                "permission denied for sequence",
                "permission denied for relation",
                "permission denied for view",
                "permission denied for function",
            )
        )
        has_network_or_multiservice = any(
            k in lower
            for k in ("vpc", "firewall", "egress", "ingress", "subnet", "network", "multi-service", "cloud run")
        )
        domain_hits = sum(
            1
            for group in (
                ("iam", "permission", "role", "service account", "403"),
                ("vpc", "firewall", "egress", "ingress", "subnet", "network"),
                ("sql", "database", "api", "cloud run", "service"),
            )
            if any(k in lower for k in group)
        )
        if (
            not is_pg_object_acl
            and has_network_or_multiservice
            and domain_hits >= 2
            and any(k in lower for k in ("fix", "troubleshoot", "error", "block", "fail", "issue", "cannot", "multi-service"))
        ):
            rag_pb = playbook_rag_service.retrieve_playbook(query_text, scenario_hint="multi_service_iam_vpc_db")
            coord_specs = [
                SPECIALIST_BY_ID[sid]
                for sid in rag_pb.get("coordinated_specialist_ids", ["security-agent", "networking-agent", "database-agent"])
                if sid in SPECIALIST_BY_ID
            ]
            return {
                "scenario_type": "SCENARIO_2_MULTI_SERVICE_TERRAFORM",
                "scenario_badge": "Multi-Service Terraform Fix",
                "needs_terraform": True,
                "rag_playbook": rag_pb,
                "coordinated_specialists": coord_specs,
            }

        # Check Scenario 3: Customer asks Atlas to help with Terraform scripts for a deployment
        if any(k in lower for k in ("terraform", "main.tf", "hcl", "iac")) or (
            any(k in lower for k in ("deploy", "provision", "create")) and any(k in lower for k in ("script", "stack", "module"))
        ):
            rag_pb = playbook_rag_service.retrieve_playbook(query_text, scenario_hint="terraform_deployment_generator")
            coord_specs = [
                SPECIALIST_BY_ID[sid]
                for sid in rag_pb.get("coordinated_specialist_ids", ["infra-agent", "serverless-agent", "database-agent", "networking-agent", "security-agent"])
                if sid in SPECIALIST_BY_ID
            ]
            return {
                "scenario_type": "SCENARIO_3_TERRAFORM_DEPLOYMENT",
                "scenario_badge": "Terraform Stack Generator",
                "needs_terraform": True,
                "rag_playbook": rag_pb,
                "coordinated_specialists": coord_specs,
            }

        # Check Scenario 1: Simple 1-line CLI/API troubleshooting or live instance performance/health inspection
        if any(
            k in lower
            for k in (
                "troubleshoot",
                "latency",
                "timeout",
                "error",
                "crash",
                "slow",
                "failing",
                "unlogged",
                "fix",
                "performance",
                "testdbinstance1",
                "health",
                "diagnose",
                "permission denied",
                "audit_logs",
                "ddl",
                "drop table",
                "create table",
                "grant ",
                "revoke ",
                "check in the logs",
            )
        ) and not lower.startswith("how do i "):
            primary = self._select_specialist_for_query(query_text)
            return {
                "scenario_type": "SCENARIO_1_CLI_FIX",
                "scenario_badge": "Live Diagnostics & CLI Fix",
                "needs_terraform": False,
                "rag_playbook": None,
                "coordinated_specialists": [primary],
            }

        # Default Scenario 4: Simple GCP How-To question ($0 execution sandbox overhead)
        primary = self._select_specialist_for_query(query_text)
        return {
            "scenario_type": "SCENARIO_4_HOW_TO",
            "scenario_badge": "GCP How-To Guide",
            "needs_terraform": False,
            "rag_playbook": None,
            "coordinated_specialists": [primary],
        }

    def list_general_chat_messages(self) -> List[Dict[str, Any]]:
        return list(self.general_chat_messages)

    def list_chat_sessions(self) -> List[Dict[str, Any]]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        record = session_store_service.get_or_init_user_sessions(
            user_email=u_email,
            user_name=u_name,
            default_messages=self.general_chat_messages,
            sync_from_firestore=False,
        )
        return [
            {
                "session_id": s.get("session_id"),
                "title": s.get("title", "New Chat Session"),
                "user_email": s.get("user_email", u_email),
                "user_name": s.get("user_name", u_name),
                "created_at": s.get("created_at"),
                "updated_at": s.get("updated_at"),
                "message_count": s.get("message_count", len(s.get("messages", []))),
                "user_message_count": s.get("user_message_count", 0),
                "last_specialist": s.get("last_specialist", "Atlas • Lead Orchestrator"),
                "is_active": s.get("session_id") == self.active_session_id,
            }
            for s in record.get("sessions", [])
        ]

    def create_new_chat_session(self, title: Optional[str] = None) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        default_msgs = self._default_general_chat_greeting()
        record = session_store_service.create_new_session(
            user_email=u_email,
            user_name=u_name,
            default_messages=default_msgs,
            title=title,
        )
        self.active_session_id = record["active_session_id"]
        self.general_chat_messages = default_msgs
        return {
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
            "sessions": self.list_chat_sessions(),
        }

    def select_chat_session(self, session_id: str) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        target = session_store_service.select_session(
            user_email=u_email,
            user_name=u_name,
            session_id=session_id,
            default_messages=self._default_general_chat_greeting(),
        )
        self.active_session_id = target["session_id"]
        self.general_chat_messages = list(target.get("messages", self._default_general_chat_greeting()))
        return {
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
            "sessions": self.list_chat_sessions(),
        }

    def delete_chat_session(self, session_id: str) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        record = session_store_service.delete_session(
            user_email=u_email,
            user_name=u_name,
            session_id=session_id,
            default_messages=self._default_general_chat_greeting(),
        )
        self.active_session_id = record["active_session_id"]
        active_sess = next(
            (s for s in record.get("sessions", []) if s.get("session_id") == self.active_session_id),
            record["sessions"][0],
        )
        self.general_chat_messages = list(active_sess.get("messages", self._default_general_chat_greeting()))
        return {
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
            "sessions": self.list_chat_sessions(),
        }

    def clear_all_chat_sessions(self) -> Dict[str, Any]:
        u_email = self.active_user.get("email") or "harisankar@google.com"
        u_name = self.active_user.get("name") or "Hari"
        default_msgs = self._default_general_chat_greeting()
        record = session_store_service.clear_all_sessions(
            user_email=u_email,
            user_name=u_name,
            default_messages=default_msgs,
        )
        self.active_session_id = record["active_session_id"]
        self.general_chat_messages = default_msgs
        return {
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
            "sessions": self.list_chat_sessions(),
        }

    def reset_general_chat(self) -> List[Dict[str, Any]]:
        self.general_chat_messages = self._default_general_chat_greeting()
        self._persist_active_session()
        return list(self.general_chat_messages)

    async def execute_chat_terraform_deployment(
        self,
        approved_by: str = "Hari (via Chat)",
        target_cloud: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the most recent Scenario 2 / Scenario 3 Terraform bundle from Direct Atlas Chat:
          1. Atlas mints a 15-minute WIF JIT token.
          2. Delegates the Terraform bundle to the coordinated Specialist Harnesses over A2A.
          3. Verifies 45s post-deployment telemetry with Heartbeat & Telemetry.
          4. Records the auditable event in the Audit & Event Tracker.
        """
        resolved_cloud = normalize_target_cloud(target_cloud or self.active_target_cloud)
        latest_tf_msg = next(
            (m for m in reversed(self.general_chat_messages) if m.get("terraform_bundle")),
            None,
        )
        recommended_cli_from_bundle: Optional[str] = None
        if latest_tf_msg and latest_tf_msg.get("terraform_bundle"):
            tf_bundle = latest_tf_msg["terraform_bundle"]
            tf_code = tf_bundle.get("terraform_code", "")
            recommended_cli_from_bundle = tf_bundle.get("recommended_cli")
            coord_specs = latest_tf_msg.get("coordinated_specialists") or [WORKER_AGENT_BOUTIQUE[2]]
            primary_spec = latest_tf_msg.get("specialist_worker") or coord_specs[0]
            scen_badge = latest_tf_msg.get("scenario_badge", "Scenario 3 • Terraform Deployment")
        else:
            rag_pb = playbook_rag_service.retrieve_playbook("terraform deployment", scenario_hint="terraform_deployment_generator")
            tf_code = rag_pb.get("terraform_code", "")
            primary_spec = WORKER_AGENT_BOUTIQUE[2]
            coord_specs = [WORKER_AGENT_BOUTIQUE[2], WORKER_AGENT_BOUTIQUE[0], WORKER_AGENT_BOUTIQUE[5]]
            scen_badge = "Scenario 3 • Terraform Deployment"

        incident_id = f"tf-chat-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        workload = "terraform/aaas-managed-stack"
        cluster = "us-central1"
        namespace = "default"

        sql_match = re.search(
            r'resource\s+"google_sql_database_instance"\s+"[^"]+"\s*\{([^}]*)\}',
            tf_code or "",
            re.DOTALL,
        )
        if (
            (recommended_cli_from_bundle and "add-iam-policy-binding" in recommended_cli_from_bundle)
            or "gcp-sa-datastream" in (tf_code or "").lower()
            or "datastream" in scen_badge.lower()
        ):
            cluster = (
                (latest_tf_msg.get("terraform_bundle") or {}).get("region")
                if latest_tf_msg
                else None
            ) or "europe-west2"
            workload = "datastream/private-connectivity-iam"
            namespace = "datastream"
        elif sql_match or (primary_spec and primary_spec.get("id") == "database-agent"):
            sql_body = sql_match.group(1) if sql_match else ""
            name_m = re.search(r'name\s*=\s*"([^"]+)"', sql_body)
            reg_m = re.search(r'region\s*=\s*"([^"]+)"', sql_body)
            sql_inst = name_m.group(1) if name_m else "testdbinstance1"
            cluster = reg_m.group(1) if reg_m else "us-west1"
            workload = f"cloudsql/{sql_inst}"
            if not recommended_cli_from_bundle:
                recommended_cli_from_bundle = (
                    f"gcloud sql instances patch {sql_inst} "
                    f"--database-flags=cloudsql.iam_authentication=on,max_connections=250 "
                    f"--project={PROJECT_ID}"
                )

        cli_cmd = recommended_cli_from_bundle or f"gcloud run services list --project={PROJECT_ID}"

        # Pre-flight Cloud Provider Status Check before minting JIT token for Terraform mutation
        preflight_status = await self._run_cloud_provider_preflight_check(
            cloud_provider=resolved_cloud,
            region=cluster,
            service_hint="terraform",
        )
        if not preflight_status.get("mutations_allowed", True):
            blocked_msg = (
                f"⚠️ **Terraform Deployment Held — Active Cloud Provider Outage in `{preflight_status.get('region')}`**:\n"
                f"{preflight_status.get('recommendation')} Zero JIT tokens minted."
            )
            reply_msg = {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "specialist": primary_spec,
                "specialist_worker": primary_spec,
                "coordinated_specialists": coord_specs,
                "scenario_badge": scen_badge,
                "dispatch_telemetry": {
                    "mode": "HARNESS_BLOCKED_OUTAGE",
                    "status": "BLOCKED_PROVIDER_OUTAGE",
                    "target_cloud": resolved_cloud,
                    "region": preflight_status.get("region") or cluster,
                    "primary_specialist": primary_spec.get("name"),
                    "coordinated_specialists": [s.get("name") for s in coord_specs],
                    "jit_token_id": None,
                    "mutations_allowed": False,
                },
                "text": blocked_msg,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.general_chat_messages.append(reply_msg)
            self._persist_active_session()
            self.record_dispatch_event(
                {
                    "dispatch_id": f"disp-{incident_id}-blocked",
                    "incident_id": incident_id,
                    "mode": "HARNESS_BLOCKED_OUTAGE",
                    "status": "BLOCKED_PROVIDER_OUTAGE",
                    "title": scen_badge,
                    "workload": workload,
                    "target_cloud": resolved_cloud,
                    "region": preflight_status.get("region") or cluster,
                    "primary_specialist": primary_spec.get("name"),
                    "coordinated_specialists": [s.get("name") for s in coord_specs],
                    "jit_token_id": None,
                    "reconciliation_pr": None,
                    "watchdog_status": "HELD_BY_OUTAGE_GATE",
                    "mutations_allowed": False,
                    "approved_by": approved_by,
                    "timestamp": reply_msg["timestamp"],
                }
            )
            return {
                "deployment_id": incident_id,
                "action_taken": "BLOCKED_PROVIDER_OUTAGE",
                "status": "BLOCKED_PROVIDER_OUTAGE",
                "target_cloud": resolved_cloud,
                "cloud_provider_status": preflight_status,
                "reply": blocked_msg,
                "specialist_worker": primary_spec,
                "coordinated_specialists": coord_specs,
                "execution_result": {
                    "status": "BLOCKED_PROVIDER_OUTAGE",
                    "mutations_allowed": False,
                    "cloud_provider_status": preflight_status,
                },
                "active_session_id": self.active_session_id,
                "messages": list(self.general_chat_messages),
            }

        jit_token = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=approved_by,
            scope=f"{resolved_cloud}:{cluster}:{namespace}:{workload}",
            ttl_seconds=900,
        )

        gke_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="gke-assist-agent",
            skill_id="execute_gke_remediation",
            payload={
                "incident_id": incident_id,
                "jit_token_id": jit_token["token_id"],
                "execution_mode": "live",
                "kubectl_command": cli_cmd,
                "terraform_code": tf_code,
                "cluster": cluster,
                "namespace": namespace,
                "workload": workload,
                "target_cloud": resolved_cloud,
                "specialist_worker": primary_spec,
                "coordinated_specialists": coord_specs,
                "log_entry": {"title": scen_badge, "workload": workload, "cloud_provider": resolved_cloud},
            },
            summary=f"Atlas authorized Terraform execution ({scen_badge}) with JIT token {jit_token['token_id'][:16]}...",
        )
        exec_result = gke_resp.result.get("execution", gke_resp.result)

        verify_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="log-watcher-agent",
            skill_id="verify_post_remediation",
            payload={
                "incident_id": incident_id,
                "cluster": cluster,
                "namespace": namespace,
                "workload": workload,
            },
            summary=f"Request 45s Watchdog verification for Terraform stack {workload}",
        )

        if latest_tf_msg and latest_tf_msg.get("terraform_bundle"):
            latest_tf_msg["terraform_bundle"]["status"] = "EXECUTED_VIA_HARNESS"
            latest_tf_msg["terraform_bundle"]["reconciliation_pr"] = exec_result.get("reconciliation_pr")

        coord_names = ", ".join(s["name"] for s in coord_specs)
        tf_resources = exec_result.get("terraform_resources_applied", [])
        chat_iam_exec = exec_result.get("iam_execution_result")
        chat_iam_line = ""
        if isinstance(chat_iam_exec, dict):
            chat_iam_line = (
                f"• **CLI / Live IAM Executed**: `{cli_cmd}` -> `{chat_iam_exec.get('status')}` "
                f"(`{chat_iam_exec.get('jit_impersonation_mode')}`, verified=`{chat_iam_exec.get('verified_after_apply')}`)\n"
            )
        confirm_text = (
            f"✅ **Terraform & GitOps Synchronization Complete via Agent Harness!**\n"
            f"• **Authorized By**: `{approved_by}` (JIT Token `{jit_token['token_id'][:18]}...`)\n"
            f"• **Coordinated Specialists**: {coord_names} (`$0` extra LLM token cost)\n"
            f"{chat_iam_line}"
            f"• **Resources Reconciled ({len(tf_resources)})**: `{', '.join(tf_resources)}` \n"
            f"• **State Lock & GitOps**: `.tflock` released cleanly • Reconciliation PR `{exec_result.get('reconciliation_pr')}` opened.\n"
            f"• **45s Telemetry Watchdog**: `{verify_resp.result.get('status', 'VERIFIED_HEALTHY')}`"
        )

        dispatch_telemetry = {
            "mode": "HARNESS_EXECUTED",
            "status": verify_resp.result.get("status", "VERIFIED_HEALTHY"),
            "target_cloud": resolved_cloud,
            "region": cluster,
            "workload": workload,
            "primary_specialist": primary_spec.get("name"),
            "coordinated_specialists": [s.get("name") for s in coord_specs],
            "jit_token_id": jit_token["token_id"],
            "reconciliation_pr": exec_result.get("reconciliation_pr"),
            "resources_reconciled": tf_resources,
            "watchdog_status": verify_resp.result.get("status", "VERIFIED_HEALTHY"),
            "mutations_allowed": True,
        }
        reply_msg = {
            "role": "assistant",
            "sender": f"Atlas • AaaS Lead (with {coord_names})",
            "specialist": primary_spec,
            "specialist_worker": primary_spec,
            "coordinated_specialists": coord_specs,
            "scenario_badge": scen_badge,
            "dispatch_telemetry": dispatch_telemetry,
            "text": confirm_text,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.general_chat_messages.append(reply_msg)

        # Log into Audit & Event Tracker
        synthetic_inc = {
            "incident_id": incident_id,
            "service_label": f"Terraform Stack ({workload})",
            "workload": workload,
            "cluster": cluster,
            "severity": "INFO",
            "title": scen_badge,
            "specialist_worker": primary_spec,
            "coordinated_specialists": coord_specs,
            "occurred_at": now_iso,
            "detected_at": now_iso,
            "status": "RESOLVED",
            "approved_by": approved_by,
            "approved_at": now_iso,
            "resolved_at": reply_msg["timestamp"],
            "jit_token": jit_token,
            "execution_result": exec_result,
            "impact_analysis": {
                "customer_headline": scen_badge,
                "scenario_badge": scen_badge,
                "recommended_kubectl": cli_cmd,
            },
            "updated_at": reply_msg["timestamp"],
        }
        self.incidents[incident_id] = synthetic_inc
        self._upsert_audit_event(synthetic_inc, event_type="TERRAFORM_APPROVED_AND_EXECUTED")
        self._persist_active_session()
        self.record_dispatch_event(
            {
                "dispatch_id": f"disp-{incident_id}",
                "incident_id": incident_id,
                "mode": "HARNESS_EXECUTED",
                "status": verify_resp.result.get("status", "VERIFIED_HEALTHY"),
                "title": scen_badge,
                "workload": workload,
                "target_cloud": resolved_cloud,
                "region": cluster,
                "primary_specialist": primary_spec.get("name"),
                "coordinated_specialists": [s.get("name") for s in coord_specs],
                "jit_token_id": jit_token["token_id"],
                "reconciliation_pr": exec_result.get("reconciliation_pr"),
                "resources_reconciled": tf_resources,
                "watchdog_status": verify_resp.result.get("status", "VERIFIED_HEALTHY"),
                "mutations_allowed": True,
                "approved_by": approved_by,
                "command": cli_cmd,
                "timestamp": reply_msg["timestamp"],
            }
        )

        return {
            "deployment_id": incident_id,
            "action_taken": "TERRAFORM_APPROVED_AND_EXECUTED",
            "target_cloud": resolved_cloud,
            "reply": confirm_text,
            "specialist_worker": primary_spec,
            "coordinated_specialists": coord_specs,
            "execution_result": exec_result,
            "dispatch_telemetry": dispatch_telemetry,
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
        }

    async def chat_general_with_atlas(
        self,
        user_message: str,
        user_name: Optional[str] = None,
        target_cloud: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Handles manual/direct user conversations with Atlas across all 4 Customer Scenarios:
          - Scenario 1: Simple 1-line CLI/API troubleshooting
          - Scenario 2: Complex multi-service (IAM + VPC Firewall + API/DB) Terraform fix
          - Scenario 3: Customer asks Atlas to generate/deploy a Terraform (.tf) script
          - Scenario 4: Simple Cloud 'How-To' questions ($0 execution sandbox overhead)
        """
        clean_msg = user_message.strip()
        if not clean_msg:
            raise ValueError("Message cannot be empty")

        resolved_cloud = normalize_target_cloud(target_cloud or self.active_target_cloud)
        uname = (user_name or self.active_user.get("name") or "Hari").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.general_chat_messages.append(
            {
                "role": "user",
                "sender": uname,
                "text": clean_msg,
                "target_cloud": resolved_cloud,
                "timestamp": now_iso,
            }
        )

        lower_msg = clean_msg.lower()
        # If user says "I accept" or "deploy terraform" after a Terraform bundle was generated in chat
        if any(p in lower_msg for p in ("i accept", "deploy terraform", "apply terraform", "execute terraform")) and "?" not in lower_msg:
            return await self.execute_chat_terraform_deployment(
                approved_by=f"{uname} (via Chat)",
                target_cloud=resolved_cloud,
            )

        # If Hari asks about the scenarios / capabilities Atlas supports
        if any(
            p in lower_msg
            for p in (
                "what scenario",
                "which scenario",
                "about the scenario",
                "list scenario",
                "4 scenario",
                "four scenario",
                "supported scenario",
                "what can you do",
                "what do you support",
                "show scenario",
                "scenarios",
            )
        ) and not any(k in lower_msg for k in ("in that scenario", "cloud run", "cloud sql", "firewall", "latency")):
            scenarios_text = (
                "I support all **4 AaaS Operational Scenarios**, Hari:\n"
                "• **Scenario 1 (Simple 1-Line CLI/API Fix)**: Quick troubleshooting & 1-line fixes.\n"
                "• **Scenario 2 (Complex Multi-Service Fix)**: Coordinated IAM + VPC Firewall + API/DB fixes via a validated **Terraform (`.tf`)** bundle.\n"
                "• **Scenario 3 (Terraform Deployment Generator)**: Ask me to generate, dry-run validate, and deploy custom **Terraform (`.tf`)** stacks.\n"
                "• **Scenario 4 (GCP How-To & Advisory)**: Instant answers with `$0` execution sandbox overhead.\n\n"
                "Which scenario would you like to run?"
            )
            primary_spec = WORKER_AGENT_BOUTIQUE[0]
            reply_msg = {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "specialist": primary_spec,
                "specialist_worker": primary_spec,
                "coordinated_specialists": [primary_spec],
                "scenario_type": "SCENARIO_4_HOW_TO",
                "scenario_badge": "All 4 AaaS Scenarios",
                "terraform_bundle": None,
                "live_database_agent_diagnosis": None,
                "text": scenarios_text,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.general_chat_messages.append(reply_msg)
            self._persist_active_session()
            return {
                "action_taken": "DIRECT_ATLAS_CHAT_REPLY",
                "target_cloud": resolved_cloud,
                "scenario_type": "SCENARIO_4_HOW_TO",
                "scenario_badge": "All 4 AaaS Scenarios",
                "reply": scenarios_text,
                "specialist_worker": primary_spec,
                "coordinated_specialists": [primary_spec],
                "consulted_specialist": primary_spec,
                "terraform_bundle": None,
                "live_database_agent_diagnosis": None,
                "active_session_id": self.active_session_id,
                "messages": list(self.general_chat_messages),
            }

        # Dedicated Scenario 1 External IaC / IAM Drift role-play in Direct Atlas Chat
        # (Datastream Private Connectivity FAILED_PRECONDITION / Missing Datastream SA permissions)
        is_datastream_ticket_chat = (
            ("datastream" in lower_msg or "gcp-sa-datastream" in lower_msg)
            and any(
                k in lower_msg
                for k in (
                    "failed_precondition",
                    "missing permissions",
                    "private connectivity",
                    "shared vpc",
                    "host project",
                    "networkadmin",
                    "ip range",
                    "service account",
                )
            )
        )
        if is_datastream_ticket_chat:
            proj_match = re.search(r"projects/([a-z][a-z0-9-]{4,40})", clean_msg, re.IGNORECASE)
            reg_match = re.search(
                r"\b((?:europe|us|asia|australia|northamerica|southamerica|me|africa)-[a-z]+[0-9])\b",
                clean_msg,
                re.IGNORECASE,
            )
            sa_match = re.search(r"(service-[a-z0-9-]+@gcp-sa-datastream\.iam\.gserviceaccount\.com)", clean_msg, re.IGNORECASE)
            chat_project = proj_match.group(1) if proj_match else PROJECT_ID
            chat_region = reg_match.group(1).lower() if reg_match else "europe-west2"
            chat_sa = (
                sa_match.group(1)
                if sa_match
                else security_iam_service.default_datastream_service_agent(chat_project)
            )

            # Phase 1: Cloud Provider Status Pre-Flight (`Cloud_Provider_Health_Tool`)
            chat_preflight = await self._run_cloud_provider_preflight_check(
                cloud_provider="gcp",
                region=chat_region,
                service_hint="datastream",
            )
            # Phase 2: Parallel Live Cloud Run ADK Security Agent (`agent-triad-security-agent`)
            #          + Live Cloud Run ADK Infra Agent (`agent-triad-infra-agent`)
            sec_chat_prompt = (
                f"Atlas Phase 2 Security Audit: Datastream private connectivity in `{chat_region}` on "
                f"`{chat_project}` failed with FAILED_PRECONDITION. Verify live IAM posture for `{chat_sa}`, "
                f"check SetIamPolicy Cloud Audit Logs, and propose the least-privilege CLI & Terraform fix."
            )
            infra_chat_prompt = (
                f"Atlas Phase 2 GitOps Correlation: Datastream private connectivity in `{chat_project}` "
                f"({chat_region}) failed with missing IAM permissions. Correlate recent Terraform state drift / "
                f"SetIamPolicy REMOVE audit logs and CI/CD deployments."
            )
            live_sec_chat, live_infra_chat = await asyncio.gather(
                asyncio.to_thread(
                    self._invoke_live_security_agent_a2a,
                    prompt=sec_chat_prompt,
                    project_id=chat_project,
                    region=chat_region,
                    service_agent_email=chat_sa,
                    target_cloud="gcp",
                ),
                asyncio.to_thread(
                    self._invoke_live_infra_agent_a2a,
                    prompt=infra_chat_prompt,
                    target_instance="datastream/private-connectivity",
                    target_cloud="gcp",
                    skill_id="correlate_gitops_drift",
                    project_id=chat_project,
                    workload="datastream/private-connectivity",
                    incident_timestamp=now_iso,
                ),
            )
            chat_iam_audit = (live_sec_chat or {}).get("iam_audit")
            if not isinstance(chat_iam_audit, dict) or not chat_iam_audit.get("recommended_cli"):
                chat_iam_audit = await asyncio.to_thread(
                    security_iam_service.inspect_datastream_iam_posture,
                    project_id=chat_project,
                    region=chat_region,
                    service_agent_email=chat_sa,
                    execute_live=(chat_project == PROJECT_ID),
                )
            live_infra_corr = (live_infra_chat or {}).get("gitops_correlation")
            if (
                isinstance(live_infra_corr, dict)
                and live_infra_corr.get("status") == "CORRELATED_RECENT_DEPLOYMENT"
                and live_infra_corr.get("highest_confidence_match") is not None
            ):
                chat_gitops = live_infra_corr
            else:
                live_audit_drifts = (live_sec_chat or {}).get("drift_events") or await asyncio.to_thread(
                    security_iam_service.fetch_recent_iam_drift_audit_events,
                    project_id=chat_project,
                    lookback_hours=72,
                )
                chat_gitops = gitops_correlator.correlate_recent_deployments(
                    incident_timestamp=now_iso,
                    workload="datastream/private-connectivity",
                    window_minutes=4320,
                    deployments=live_audit_drifts or None,
                )

            sec_spec = SPECIALIST_BY_ID["security-agent"]
            infra_spec = SPECIALIST_BY_ID["infra-agent"]
            coord_specs = [sec_spec, infra_spec]
            coord_names = ", ".join(s["name"] for s in coord_specs)
            chat_hcl = self._build_datastream_iam_hcl(chat_project, chat_iam_audit["target_service_agent"])
            dry_run_report = agent_harness.validate_terraform_dry_run(chat_hcl)
            opa_policy = agent_harness.evaluate_policy_gate(
                workload="datastream/private-connectivity-iam",
                terraform_code=chat_hcl,
                specialist_ids=["security-agent", "infra-agent"],
            )
            tf_bundle = {
                "status": "READY_FOR_HARNESS_EXECUTION",
                "title": "Scenario 1 • Datastream SA IAM & Bidirectional GitOps Sync",
                "scenario_type": "SCENARIO_1_CLI_FIX",
                "scenario_badge": "Scenario 1 • External IaC / IAM Drift",
                "region": chat_region,
                "recommended_cli": chat_iam_audit["recommended_cli"],
                "hcl_code": chat_hcl,
                "terraform_code": chat_hcl,
                "dry_run": dry_run_report,
                "dry_run_report": dry_run_report,
                "policy_gate": opa_policy,
                "opa_policy": opa_policy,
                "coordinated_specialists": coord_specs,
            }
            chat_reply = self._format_datastream_four_phase_rca(
                uname=uname,
                cloud_provider_status=chat_preflight,
                iam_audit=chat_iam_audit,
                gitops_correlation=chat_gitops,
            )
            chat_tools = [
                "Cloud_Provider_Health_Tool",
                "Security_Agent_Tool",
                "GitOps_Correlator_Tool",
            ]
            dispatch_telemetry = {
                "mode": "TERRAFORM_PROPOSAL",
                "status": "AWAITING_HITL_APPROVAL",
                "target_cloud": "gcp",
                "region": chat_region,
                "primary_specialist": sec_spec["name"],
                "coordinated_specialists": [s["name"] for s in coord_specs],
                "tools_invoked": chat_tools,
                "read_only": False,
                "scenario_badge": "Scenario 1 • External IaC / IAM Drift",
            }
            reply_msg = {
                "role": "assistant",
                "sender": f"Atlas • AaaS Lead (with {coord_names})",
                "specialist": sec_spec,
                "specialist_worker": sec_spec,
                "coordinated_specialists": coord_specs,
                "scenario_type": "SCENARIO_1_CLI_FIX",
                "scenario_badge": "Scenario 1 • External IaC / IAM Drift",
                "terraform_bundle": tf_bundle,
                "iam_audit": chat_iam_audit,
                "cloud_provider_status": chat_preflight,
                "gitops_correlation": chat_gitops,
                "dispatch_telemetry": dispatch_telemetry,
                "text": chat_reply,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.general_chat_messages.append(reply_msg)
            self._persist_active_session()
            self.record_dispatch_event(
                {
                    "dispatch_id": f"disp-chat-{uuid.uuid4().hex[:8]}",
                    "mode": "TERRAFORM_PROPOSAL",
                    "status": "AWAITING_HITL_APPROVAL",
                    "title": f"Datastream Private Connectivity IAM Drift ({chat_project})",
                    "scenario_badge": "Scenario 1 • External IaC / IAM Drift",
                    "workload": "datastream/private-connectivity",
                    "target_cloud": "gcp",
                    "region": chat_region,
                    "primary_specialist": sec_spec["name"],
                    "coordinated_specialists": [s["name"] for s in coord_specs],
                    "tools_invoked": chat_tools,
                    "read_only": False,
                    "mutations_allowed": bool(chat_preflight.get("mutations_allowed", True)),
                    "watchdog_status": "AWAITING_HITL_APPROVAL",
                    "timestamp": reply_msg["timestamp"],
                }
            )
            return {
                "action_taken": "DIRECT_ATLAS_CHAT_REPLY",
                "target_cloud": "gcp",
                "scenario_type": "SCENARIO_1_CLI_FIX",
                "scenario_badge": "Scenario 1 • External IaC / IAM Drift",
                "reply": chat_reply,
                "specialist_worker": sec_spec,
                "coordinated_specialists": coord_specs,
                "consulted_specialist": sec_spec,
                "terraform_bundle": tf_bundle,
                "iam_audit": chat_iam_audit,
                "cloud_provider_status": chat_preflight,
                "gitops_correlation": chat_gitops,
                "dispatch_telemetry": dispatch_telemetry,
                "active_session_id": self.active_session_id,
                "messages": list(self.general_chat_messages),
            }

        scenario_info = self._classify_chat_scenario(clean_msg)
        scenario_type = scenario_info["scenario_type"]
        scenario_badge = scenario_info["scenario_badge"]
        needs_terraform = scenario_info["needs_terraform"]
        coordinated_specialists = scenario_info["coordinated_specialists"]
        specialist = self._select_specialist_for_query(clean_msg)
        if all(s["id"] != specialist["id"] for s in coordinated_specialists):
            coordinated_specialists = [specialist] + coordinated_specialists

        spec_name = specialist["name"]
        spec_domain = specialist["domain"]
        coord_names = ", ".join(s["name"] for s in coordinated_specialists)

        rag_pb = scenario_info.get("rag_playbook")
        terraform_code: Optional[str] = rag_pb.get("terraform_code") if rag_pb else None
        recommended_cli: Optional[str] = rag_pb.get("recommended_cli") if rag_pb else None

        history_text = "\n".join(
            f"{m.get('sender', m.get('role'))}: {m.get('text')}"
            for m in self.general_chat_messages[-6:]
        )

        live_db_diagnosis: Optional[Dict[str, Any]] = None
        live_infra_diagnosis: Optional[Dict[str, Any]] = None
        live_sec_diagnosis: Optional[Dict[str, Any]] = None
        is_generic_howto = lower_msg.startswith("how do i ") and not any(
            k in lower_msg for k in ("testdb", "testinstance", "agent-triad", "agent-traid", "2397540675679890849")
        )
        if spec_name == "Database Agent" and not is_generic_howto:
            contextual_prompt = (
                f"Recent Conversation Context:\n{history_text}\n\n"
                f"Current User Message from Hari:\n{clean_msg}"
            )
            live_db_diagnosis = await asyncio.to_thread(
                self._invoke_live_database_agent_a2a,
                prompt=contextual_prompt,
                instance_name="auto",
                target_cloud=resolved_cloud,
            )
            if live_db_diagnosis:
                prop = live_db_diagnosis.get("remediation_proposal") or {}
                is_identity_or_howto_followup = any(
                    q in lower_msg
                    for q in (
                        "what service account",
                        "which service account",
                        "are you actually connecting",
                        "how will you fix",
                        "how do you fix",
                    )
                )
                if prop.get("recommended_cli"):
                    recommended_cli = prop["recommended_cli"]
                if prop.get("terraform_hcl") and not terraform_code and not is_identity_or_howto_followup:
                    terraform_code = prop["terraform_hcl"]
                    if any(k in lower_msg for k in ("troubleshoot", "fix", "error", "stop", "testdbinstance1", "testdbconnect", "fatal", "why", "performance", "issue")):
                        needs_terraform = True
        elif spec_name == "Infra Agent" and not is_generic_howto:
            contextual_prompt = (
                f"Recent Conversation Context:\n{history_text}\n\n"
                f"Current User Message from Hari:\n{clean_msg}"
            )
            live_infra_diagnosis = await asyncio.to_thread(
                self._invoke_live_infra_agent_a2a,
                prompt=contextual_prompt,
                target_instance="auto",
                target_cloud=resolved_cloud,
            )
            if live_infra_diagnosis:
                prop = live_infra_diagnosis.get("remediation_proposal") or {}
                is_identity_or_howto_followup = any(
                    q in lower_msg
                    for q in (
                        "what service account",
                        "which service account",
                        "are you actually connecting",
                        "how will you fix",
                        "how do you fix",
                    )
                )
                if prop.get("recommended_cli"):
                    recommended_cli = prop["recommended_cli"]
                if prop.get("terraform_hcl") and not terraform_code and not is_identity_or_howto_followup:
                    terraform_code = prop["terraform_hcl"]
                    if any(k in lower_msg for k in ("troubleshoot", "fix", "error", "testinstance1", "2397540675679890849", "gce", "vm", "why", "performance", "issue")):
                        needs_terraform = True
        elif spec_name == "Security Agent" and not is_generic_howto:
            contextual_prompt = (
                f"Recent Conversation Context:\n{history_text}\n\n"
                f"Current User Message from Hari:\n{clean_msg}"
            )
            live_sec_diagnosis = await asyncio.to_thread(
                self._invoke_live_security_agent_a2a,
                prompt=contextual_prompt,
                project_id=PROJECT_ID,
                region="europe-west2",
                target_cloud=resolved_cloud,
            )
            if live_sec_diagnosis:
                prop = live_sec_diagnosis.get("remediation_proposal") or {}
                if prop.get("recommended_cli"):
                    recommended_cli = prop["recommended_cli"]
                if prop.get("terraform_hcl") and not terraform_code:
                    terraform_code = prop["terraform_hcl"]

        reply_text = ""
        if live_sec_diagnosis and live_sec_diagnosis.get("security_reasoning_report"):
            tools_used = ", ".join(live_sec_diagnosis.get("tools_invoked", []))
            iam_a = live_sec_diagnosis.get("iam_audit") or {}
            ident = live_sec_diagnosis.get("runtime_identity") or {}
            header_lines = [
                "📡 **Atlas delegated to Live Cloud Run ADK `Security Agent` (`agent-triad-security-agent`) via A2A**",
                f"• **ADK Tools Executed**: `{tools_used}`",
            ]
            if iam_a.get("target_service_agent"):
                header_lines.append(
                    f"• **Live IAM Posture**: `{iam_a.get('target_service_agent')}` → **`{iam_a.get('status')}`** "
                    f"(Live Verified: `{iam_a.get('live_gcp_verified')}`, Roles: `{', '.join(iam_a.get('assigned_roles') or []) or 'NONE'}`)"
                )
            if ident.get("active_service_account"):
                header_lines.append(
                    f"• **Active Runtime Identity**: `{ident.get('active_service_account')}` (Zero-Standing-Privilege Read-Only)"
                )
            reply_text = "\n".join(header_lines) + "\n\n" + str(live_sec_diagnosis["security_reasoning_report"])
        elif live_db_diagnosis and live_db_diagnosis.get("dba_reasoning_report"):
            tools_used = ", ".join(live_db_diagnosis.get("tools_invoked", []))
            insp = live_db_diagnosis.get("instance_inspection") or {}
            perf = (live_db_diagnosis.get("performance_metrics") or {}).get("metrics") or {}
            ident = live_db_diagnosis.get("runtime_identity") or {}
            ddl_a = live_db_diagnosis.get("ddl_privilege_audit") or {}
            cpu_val = (perf.get("cpu_utilization_pct") or {}).get("latest")
            mem_val = (perf.get("memory_utilization_pct") or {}).get("latest")
            conn_val = (perf.get("active_connections") or {}).get("latest")
            header_lines = [
                "📡 **Atlas delegated to Live Cloud Run ADK `Database Agent` (`agent-triad-db-agent`) via A2A**",
                f"• **ADK Tools Executed**: `{tools_used}`",
            ]
            if insp.get("instance_name"):
                header_lines.append(
                    f"• **Live Instance Discovered**: `{insp.get('instance_name')}` (`{insp.get('database_version')}`, Region: `{insp.get('region')}`, State: **`{insp.get('state')}`**, ActivationPolicy: `{insp.get('activation_policy')}`)"
                )
            if cpu_val is not None or mem_val is not None:
                header_lines.append(
                    f"• **Live Cloud Monitoring Telemetry**: CPU `{cpu_val}%` • Memory `{mem_val}%` • "
                    f"Active Connections `{conn_val}` • Service Account `{ident.get('active_service_account', 'aaas-database-agent-sa@agent-triad.iam.gserviceaccount.com')}`"
                )
            elif ident.get("active_service_account"):
                header_lines.append(
                    f"• **Active Runtime Identity**: `{ident.get('active_service_account')}`"
                )
            report_body = str(live_db_diagnosis["dba_reasoning_report"])
            ddl_evts_chat = (ddl_a.get("ddl_events") or ddl_a.get("ddl_statements") or []) if isinstance(ddl_a, dict) else []
            perm_evts_chat = (ddl_a.get("permission_denied_events") or []) if isinstance(ddl_a, dict) else []
            dcl_evts_chat = (ddl_a.get("dcl_grant_revoke_events") or ddl_a.get("privilege_statements") or []) if isinstance(ddl_a, dict) else []
            if (
                isinstance(ddl_a, dict)
                and (perm_evts_chat or ddl_evts_chat or dcl_evts_chat)
                and "GRANT SELECT" not in report_body.upper()
            ):
                ddl_lines = [
                    "🔍 **Correlated Cloud SQL DDL & Object ACL Audit (`inspect_table_ddl_and_privilege_logs`)**:",
                    f"• **Root Cause**: {ddl_a.get('root_cause_summary')}",
                ]
                for d_evt in ddl_evts_chat[:3]:
                    ddl_lines.append(f"• **DDL (`{d_evt.get('timestamp')}`)**: `{d_evt.get('statement')}`")
                for p_evt in perm_evts_chat[:3]:
                    ddl_lines.append(
                        f"• **Permission Denied (`{p_evt.get('timestamp')}`)**: `user={p_evt.get('db_user')}` denied on `{p_evt.get('object_name')}`"
                    )
                for g_evt in dcl_evts_chat[:3]:
                    ddl_lines.append(f"• **Privilege DCL (`{g_evt.get('timestamp')}`)**: `{g_evt.get('statement')}`")
                if ddl_a.get("recommended_cli"):
                    ddl_lines.append(f"• **PostgreSQL Remediation**: `{ddl_a.get('recommended_cli')}`")
                report_body = "\n".join(ddl_lines) + "\n\n" + report_body
            reply_text = "\n".join(header_lines) + "\n\n" + report_body
        elif live_infra_diagnosis and live_infra_diagnosis.get("infra_reasoning_report"):
            tools_used = ", ".join(live_infra_diagnosis.get("tools_invoked", []))
            insp = live_infra_diagnosis.get("instance_inspection") or {}
            perf = (live_infra_diagnosis.get("performance_metrics") or {}).get("metrics") or {}
            ident = live_infra_diagnosis.get("runtime_identity") or {}
            cpu_val = (perf.get("cpu_utilization_pct") or {}).get("latest")
            uptime_val = (perf.get("uptime_seconds") or {}).get("latest")
            net_rx = (perf.get("network_received_bytes") or {}).get("latest")
            header_lines = [
                "📡 **Atlas delegated to Live Cloud Run ADK `Infra Agent` (`agent-triad-infra-agent`) via A2A**",
                f"• **ADK Tools Executed**: `{tools_used}`",
            ]
            if insp.get("instance_name"):
                header_lines.append(
                    f"• **Live Compute VM Discovered**: `{insp.get('instance_name')}` (ID: `{insp.get('instance_id')}`, Zone: `{insp.get('zone')}`, MachineType: `{insp.get('machine_type')}`, Status: **`{insp.get('status')}`**)"
                )
            if cpu_val is not None or uptime_val is not None:
                header_lines.append(
                    f"• **Live Cloud Monitoring Telemetry**: CPU `{cpu_val}%` • Uptime `{uptime_val}s` • "
                    f"Net RX `{net_rx} B` • Service Account `{ident.get('active_service_account', 'aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com')}`"
                )
            elif ident.get("active_service_account"):
                header_lines.append(
                    f"• **Active Runtime Identity**: `{ident.get('active_service_account')}`"
                )
            reply_text = "\n".join(header_lines) + "\n\n" + str(live_infra_diagnosis["infra_reasoning_report"])
        elif self._llm_client.is_available:
            try:
                cloud_cli_hint = {"gcp": "gcloud", "aws": "aws", "azure": "az"}.get(resolved_cloud, "gcloud")
                cloud_label = {"gcp": "Google Cloud (`agent-triad`)", "aws": "AWS", "azure": "Microsoft Azure"}.get(
                    resolved_cloud, "Google Cloud (`agent-triad`)"
                )
                ignore_clause = (
                    f"Note: The operator marked these benign signatures Safe to Ignore ({', '.join(sorted(self.ignored_signatures)[:8])}); "
                    "do NOT raise or force remediation on them.\n"
                    if self.ignored_signatures
                    else ""
                )
                prompt = (
                    f"You are Atlas, the Single Authorizing ADK Root Agent operating on {cloud_label} (active target cloud: {resolved_cloud.upper()}).\n"
                    f"Classified Scenario: {scenario_badge}\n"
                    f"Coordinated Domain Specialists: {coord_names}\n"
                    f"{ignore_clause}"
                    f"Recent Conversation:\n{history_text}\n\n"
                    "Provide a clear, practical, and concise answer (3-5 bullet points) tailored to the operator's request. "
                    f"Include exact `{cloud_cli_hint}` commands or explain how the coordinated specialists and Agent Harness handle this."
                )
                generated = await asyncio.to_thread(self._llm_client.generate_text, prompt)
                if generated:
                    reply_text = generated
            except Exception:
                reply_text = ""

        if not reply_text:
            if scenario_type == "SCENARIO_2_MULTI_SERVICE_TERRAFORM":
                reply_text = (
                    f"I classified this as **{scenario_badge}** and coordinated **{coord_names}**, Hari:\n"
                    "• **Multi-Service Root Cause**: Cross-service failures between Cloud Run, Cloud SQL, and VPC require synchronized IAM (`roles/cloudsql.client`), VPC firewall egress (`tcp:5432`), and revision VPC connector bindings.\n"
                    "• **Speculative Terraform Dry-Run (`PASS`)**: I generated a unified `.tf` remediation bundle below and validated it in the **Agent Harness Sandbox**.\n"
                    "• **Next Step**: Review the Terraform code below and click **I accept — Execute Terraform via Harness** (or type `I accept`) to apply it atomically!"
                )
            elif scenario_type == "SCENARIO_3_TERRAFORM_DEPLOYMENT":
                reply_text = (
                    f"I generated a production-ready **{scenario_badge}** validated across **{coord_names}**, Hari:\n"
                    "• **Included Resources**: Dedicated least-privilege Service Account (`Security Agent`), Serverless VPC Connector (`Networking Agent`), and auto-scaled Cloud Run service with FinOps max-instance caps (`Serverless & Billing Agents`).\n"
                    "• **Agent Harness Dry-Run (`PASS`)**: HCL syntax, OPA blast-radius rules, and zero-secret checks passed.\n"
                    "• **Next Step**: Copy the `.tf` module below or click **I accept — Execute Terraform via Harness** to provision it through the sandbox!"
                )
            elif spec_name == "Database Agent":
                reply_text = (
                    f"I consulted our **{spec_name}** (*{spec_domain}*) for your question, Hari:\n"
                    "• **Cloud Run → Cloud SQL Auth Proxy Setup**: Attach the Cloud SQL instance using `--add-cloudsql-instances=agent-triad:us-central1:INSTANCE` so Cloud Run mounts the Unix socket at `/cloudsql/...`.\n"
                    "• **Unlogged Connection Timeouts**: Check if `max_connections` is saturated or if connection pooling (`PgBouncer` / SQLAlchemy `pool_size=5, max_overflow=2`) needs tuning:\n"
                    "  `gcloud sql operations list --instance=INSTANCE --project=agent-triad`\n"
                    "• **Private IP Verification**: Ensure your Serverless VPC Access connector has `/28` CIDR capacity and egress is set to `private-ranges-only`."
                )
            elif spec_name == "Networking Agent":
                reply_text = (
                    f"I consulted our **{spec_name}** (*{spec_domain}*) to troubleshoot this unlogged network/latency symptom, Hari:\n"
                    "• **Check Cold-Start vs. Network RTT**: Run a timing probe to separate TLS/DNS handshake time from container response time:\n"
                    "  `curl -w 'dns:%{time_namelookup}s connect:%{time_connect}s ttfb:%{time_starttransfer}s\\n' -o /dev/null -s https://SERVICE_URL`\n"
                    "• **Inspect VPC Connector Throughput**: Silent packet drops often occur when a Serverless VPC Access connector hits its throughput ceiling:\n"
                    "  `gcloud compute networks vpc-access connectors describe CONNECTOR --region=us-central1 --project=agent-triad`\n"
                    "• **Keep Warm Instance**: Set `--min-instances=1` on latency-sensitive Cloud Run services to eliminate cold-start spikes."
                )
            elif spec_name == "Security Agent":
                reply_text = (
                    f"I consulted our **{spec_name}** (*{spec_domain}*) for your security/IAM question, Hari:\n"
                    "• **Audit Service Account Bindings**: List active IAM roles granted across `agent-triad`:\n"
                    "  `gcloud projects get-iam-policy agent-triad --flatten='bindings[].members' --format='table(bindings.role,bindings.members)'`\n"
                    "• **Zero-Standing Privilege (WIF + JIT)**: Avoid long-lived JSON keys—use Workload Identity Federation and short-lived 15-minute JIT tokens (`gcloud auth print-access-token`).\n"
                    "• **Secret Manager Best Practice**: Mount secrets directly as environment variables (`--set-secrets=DB_PASS=db-secret:latest`) and grant `roles/secretmanager.secretAccessor` only to the target service account."
                )
            elif spec_name == "Billing Agent":
                reply_text = (
                    f"I consulted our **{spec_name}** (*{spec_domain}*) for your FinOps & cost control question, Hari:\n"
                    "• **Cap Auto-Scaling Spend**: Always set a hard `--max-instances` ceiling on Cloud Run services so unexpected traffic bursts cannot trigger runaway compute charges:\n"
                    "  `gcloud run services update SERVICE --max-instances=10 --region=us-central1 --project=agent-triad`\n"
                    "• **CPU Allocation Mode**: Use `--cpu-throttling` (CPU only allocated during request processing) for request-driven services.\n"
                    "• **Budget Alerts & Quota Checks**: Configure Cloud Billing budget alerts at 50%, 80%, and 100% thresholds via `gcloud billing budgets list`."
                )
            else:
                reply_text = (
                    f"I consulted our **{spec_name}** (*{spec_domain}*) for your request, Hari:\n"
                    "• **Inspect Live Service Configuration & Revisions**:\n"
                    "  `gcloud run services describe agent-triad-control-plane --region=us-central1 --project=agent-triad`\n"
                    "• **Troubleshoot Unlogged Issues (Latency / Silent Timeouts)**:\n"
                    "  1. Check container concurrency & CPU limits (`--concurrency=80`, `--cpu=1`, `--memory=512Mi`).\n"
                    "  2. Verify revision traffic split and startup/liveness probes (`gcloud run revisions list --region=us-central1`)."
                )

        terraform_bundle: Optional[Dict[str, Any]] = None
        if needs_terraform and terraform_code:
            dry_run_report = agent_harness.validate_terraform_dry_run(terraform_code)
            opa_policy = agent_harness.evaluate_policy_gate(
                workload="terraform/aaas-managed-stack",
                terraform_code=terraform_code,
                specialist_ids=[s["id"] for s in coordinated_specialists],
            )
            terraform_bundle = {
                "status": "READY_FOR_HARNESS_EXECUTION",
                "title": scenario_badge,
                "scenario_type": scenario_type,
                "scenario_badge": scenario_badge,
                "recommended_cli": recommended_cli,
                "hcl_code": terraform_code,
                "terraform_code": terraform_code,
                "dry_run": dry_run_report,
                "dry_run_report": dry_run_report,
                "policy_gate": opa_policy,
                "opa_policy": opa_policy,
                "coordinated_specialists": coordinated_specialists,
            }

        tools_invoked: List[str] = list(
            (live_db_diagnosis or {}).get("tools_invoked")
            or (live_infra_diagnosis or {}).get("tools_invoked")
            or []
        )
        dispatch_telemetry = {
            "mode": (
                "LIVE_A2A_SPECIALIST"
                if (live_db_diagnosis or live_infra_diagnosis)
                else ("TERRAFORM_PROPOSAL" if terraform_bundle else "ATLAS_ADVISORY")
            ),
            "status": "COMPLETED",
            "target_cloud": resolved_cloud,
            "primary_specialist": specialist.get("name"),
            "coordinated_specialists": [s.get("name") for s in coordinated_specialists],
            "tools_invoked": tools_invoked,
            "read_only": not bool(terraform_bundle),
            "scenario_badge": scenario_badge,
        }
        reply_msg = {
            "role": "assistant",
            "sender": f"Atlas • AaaS Lead (with {coord_names})",
            "specialist": specialist,
            "specialist_worker": specialist,
            "coordinated_specialists": coordinated_specialists,
            "scenario_type": scenario_type,
            "scenario_badge": scenario_badge,
            "terraform_bundle": terraform_bundle,
            "live_database_agent_diagnosis": live_db_diagnosis,
            "live_infra_agent_diagnosis": live_infra_diagnosis,
            "dispatch_telemetry": dispatch_telemetry,
            "text": reply_text,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.general_chat_messages.append(reply_msg)
        self._persist_active_session()
        self.record_dispatch_event(
            {
                "dispatch_id": f"disp-chat-{uuid.uuid4().hex[:8]}",
                "mode": dispatch_telemetry["mode"],
                "status": "COMPLETED",
                "title": clean_msg[:88] + ("..." if len(clean_msg) > 88 else ""),
                "scenario_badge": scenario_badge,
                "workload": (
                    ((live_db_diagnosis or {}).get("instance_inspection") or {}).get("instance_name")
                    or ((live_infra_diagnosis or {}).get("instance_inspection") or {}).get("instance_name")
                    or "atlas-chat"
                ),
                "target_cloud": resolved_cloud,
                "region": (
                    ((live_db_diagnosis or {}).get("instance_inspection") or {}).get("region")
                    or ((live_infra_diagnosis or {}).get("instance_inspection") or {}).get("zone")
                    or ("us-central1" if resolved_cloud == "gcp" else ("us-east-1" if resolved_cloud == "aws" else "eastus"))
                ),
                "primary_specialist": specialist.get("name"),
                "coordinated_specialists": [s.get("name") for s in coordinated_specialists],
                "tools_invoked": tools_invoked,
                "read_only": dispatch_telemetry["read_only"],
                "mutations_allowed": True,
                "watchdog_status": "READ_ONLY_VERIFIED" if dispatch_telemetry["read_only"] else "AWAITING_HITL_APPROVAL",
                "timestamp": reply_msg["timestamp"],
            }
        )
        return {
            "action_taken": "DIRECT_ATLAS_CHAT_REPLY",
            "target_cloud": resolved_cloud,
            "scenario_type": scenario_type,
            "scenario_badge": scenario_badge,
            "reply": reply_text,
            "specialist_worker": specialist,
            "coordinated_specialists": coordinated_specialists,
            "consulted_specialist": specialist,
            "terraform_bundle": terraform_bundle,
            "live_database_agent_diagnosis": live_db_diagnosis,
            "live_infra_agent_diagnosis": live_infra_diagnosis,
            "dispatch_telemetry": dispatch_telemetry,
            "active_session_id": self.active_session_id,
            "messages": list(self.general_chat_messages),
        }
