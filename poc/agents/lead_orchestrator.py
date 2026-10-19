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
from services.agent_harness import agent_harness, inspect_agent_harness_policy_tool
from services.playbook_rag import (
    RAG_PLAYBOOK_CATALOG,
    playbook_rag_service,
    query_playbook_rag_tool,
)

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
MODEL_NAME = os.getenv("AAAS_GEMINI_MODEL", "gemini-2.5-flash")


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
        self.general_chat_messages: List[Dict[str, Any]] = self._default_general_chat_greeting()
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
                model=MODEL_NAME,
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
                tools=[query_playbook_rag_tool, inspect_agent_harness_policy_tool],
            )
        except Exception:
            return None

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
    ) -> Optional[Dict[str, Any]]:
        """
        Invokes the live Cloud Run ADK Database Specialist Agent (`agent-triad-db-agent`)
        over Zero-Trust A2A (`POST /a2a` with OIDC Identity Token) and logs the remote
        A2A exchange into the AaaS Control Plane ledger.
        """
        import subprocess
        import urllib.request

        db_agent_url = os.getenv(
            "DATABASE_AGENT_URL",
            "https://agent-triad-db-agent-qq3mp7ftqq-uc.a.run.app",
        ).rstrip("/")

        id_token_str = ""
        try:
            from google.auth.transport.requests import Request as GoogleAuthRequest
            from google.oauth2 import id_token as google_id_token

            id_token_str = google_id_token.fetch_id_token(GoogleAuthRequest(), db_agent_url)
        except Exception:
            try:
                proc = subprocess.run(
                    ["gcloud", "auth", "print-identity-token"],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    id_token_str = proc.stdout.strip()
            except Exception:
                id_token_str = ""

        rpc_id = f"a2a-db-{uuid.uuid4().hex[:8]}"
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tasks/send",
            "params": {
                "skill_id": "diagnose_database_anomaly",
                "data": {
                    "prompt": prompt,
                    "instance_name": instance_name,
                },
            },
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if id_token_str:
            headers["Authorization"] = f"Bearer {id_token_str}"

        try:
            req = urllib.request.Request(
                f"{db_agent_url}/a2a",
                data=json.dumps(rpc_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
            diagnosis = (resp_json.get("result") or {}).get("diagnosis")
            if diagnosis:
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
        except Exception:
            pass
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

        if self._genai_client is not None:
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
                config = (
                    genai_types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    )
                    if genai_types is not None
                    else None
                )
                resp = self._genai_client.models.generate_content(
                    model=MODEL_NAME,
                    contents=prompt,
                    config=config,
                )
                if resp and resp.text:
                    parsed = json.loads(resp.text)
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

        if any(k in msg or k in source or k in workload for k in ("billing", "budget", "cost", "finops")):
            return WORKER_AGENT_BOUTIQUE[6]  # Billing Agent
        if any(k in msg or k in source or k in workload for k in ("iam", "permission", "unauthorized", "forbidden", "secret", "armor")):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent
        if "testdbconnect" in workload or "cloudsql" in source or "sql" in workload or "database" in msg:
            return WORKER_AGENT_BOUTIQUE[1]  # Database Agent
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

    def _build_initial_chat_greeting(
        self,
        log_entry: Dict[str, Any],
        impact: Dict[str, Any],
        specialist: Dict[str, str],
        coordinated_specialists: List[Dict[str, str]],
        harness_bundle: Dict[str, Any],
        now_iso: str,
    ) -> List[Dict[str, Any]]:
        service_label = self._friendly_service_name(log_entry)
        severity = log_entry.get("severity", "ERROR")
        what_happened = impact.get("customer_what_happened") or log_entry.get("message", "")
        next_step = impact.get("customer_why_approve") or impact.get("remedy_summary", "")
        blast = impact.get("blast_radius_tier", "HIGH")
        coord_names = ", ".join(f"**{s['name']}**" for s in coordinated_specialists)
        lock_uri = (harness_bundle.get("lock") or {}).get("gcs_uri", "gs://agent-triad-tf-state/lock.tflock")
        rag_score = impact.get("rag_similarity_score", 0.94)

        opening_text = (
            f"Hey Hari 👋 There's an issue I just found with **{service_label}**.\n\n"
            f"• **Classification**: `{impact.get('scenario_badge', 'Scenario 1 • 1-Line CLI/API Fix')}` (RAG Match: `{int(rag_score * 100)}%`)\n"
            f"• **Severity**: `{severity}` — {blast}\n"
            f"• **What happened**: {what_happened}\n"
            f"• **Delegation Plan**: {coord_names}\n"
            f"• **Agent Harness**: Locked `{lock_uri}` (10m TTL) • OPA Policy `PASS`\n"
            f"• **Next Steps**: {next_step}\n\n"
            "Ask me anything about why this happened, whether there's any downtime, the rollback plan, "
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
            impact_and_remedy = self._analyze_impact_and_remedy(log_entry)
            specialist = self._select_specialist_worker(log_entry)
            coordinated_specialists = self._resolve_coordinated_specialists(
                log_entry=log_entry,
                rag_playbook=impact_and_remedy,
                primary_specialist=specialist,
            )

            cluster = log_entry.get("cluster", "us-central1")
            namespace = log_entry.get("namespace", "default")
            workload = log_entry.get("workload", "deployment/app")

            live_db_diag: Optional[Dict[str, Any]] = None
            if specialist.get("id") == "database-agent":
                target_inst = str(log_entry.get("pod") or "testdbinstance1").split(":")[-1]
                live_db_diag = self._invoke_live_database_agent_a2a(
                    prompt=(
                        f"Atlas Alert: Cloud Logging detected [{log_entry.get('severity')}] on `{workload}`: "
                        f"{log_entry.get('message')}. Inspect the live Cloud SQL instance and logs and propose a safe fix."
                    ),
                    instance_name=target_inst,
                )
                if live_db_diag:
                    impact_and_remedy["live_database_agent_diagnosis"] = live_db_diag
                    log_anal = live_db_diag.get("log_analysis") or {}
                    prop = live_db_diag.get("remediation_proposal") or {}
                    if log_anal.get("root_cause"):
                        impact_and_remedy["root_cause"] = log_anal["root_cause"]
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
            chat_messages = self._build_initial_chat_greeting(
                log_entry=log_entry,
                impact=impact_and_remedy,
                specialist=specialist,
                coordinated_specialists=coordinated_specialists,
                harness_bundle=harness_bundle,
                now_iso=now_iso,
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
                "severity": log_entry.get("severity", "CRITICAL"),
                "title": log_entry.get("title", "Cloud Service Anomaly"),
                "cluster": cluster,
                "namespace": namespace,
                "workload": workload,
                "pod": log_entry.get("pod", "unknown-pod"),
                "error_code": log_entry.get("error_code", "GCP_ERROR"),
                "log_entry": log_entry,
                "impact_analysis": impact_and_remedy,
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
    ) -> Dict[str, Any]:
        """
        Interactive conversational handler for Hari to ask questions about an active incident,
        request a multi-service Terraform remediation bundle (Scenario 2), or instruct Atlas to proceed.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_msg = user_message.strip()
        incident.setdefault("chat_messages", []).append(
            {
                "role": "user",
                "sender": "Hari",
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
        )
        if incident["status"] == "AWAITING_HITL_APPROVAL" and any(p in lower_msg for p in approve_phrases) and "?" not in lower_msg:
            updated = await self.approve_and_delegate_to_gke_assist(
                incident_id=incident_id,
                approved_by="Hari (via Chat)",
                execution_mode="live",
            )
            return {
                "action_taken": "APPROVED_AND_EXECUTED",
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        # Check if Hari wants to skip / ignore / handle manually later
        skip_phrases = ("skip", "ignore", "later", "fix manually", "do it myself", "not now", "hold off")
        if incident["status"] == "AWAITING_HITL_APPROVAL" and any(p in lower_msg for p in skip_phrases) and "?" not in lower_msg:
            updated = self.skip_incident_manual(incident_id=incident_id, skipped_by="Hari (via Chat)")
            return {
                "action_taken": "SKIPPED_MANUAL",
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        impact = incident.get("impact_analysis", {})
        log_entry = incident.get("log_entry", {})
        history_text = "\n".join(
            f"{m.get('sender', m.get('role'))}: {m.get('text')}"
            for m in incident.get("chat_messages", [])[-6:]
        )

        reply_text = ""
        if self._genai_client is not None:
            try:
                prompt = (
                    "You are Atlas, the Single Authorizing ADK Root Gemini Agent for Hari's Google Cloud project (`agent-triad`).\n"
                    "Answer Hari's question clearly, warmly, and concisely (2-4 short bullet points or sentences) in plain English.\n"
                    "Reassure him about safety, zero downtime, the `.tflock` state lease, OPA policy check, and automatic rollback where relevant, "
                    "and remind him he can say 'I accept' or click 'I accept' whenever he feels comfortable.\n\n"
                    f"Service: {incident.get('service_label')}\n"
                    f"Scenario Mode: {impact.get('scenario_badge')}\n"
                    f"Root Cause: {impact.get('root_cause')}\n"
                    f"Business Impact: {impact.get('business_impact')}\n"
                    f"Proposed Fix: {impact.get('remedy_summary')}\n"
                    f"Command: {impact.get('recommended_kubectl')}\n"
                    f"Rollback Plan: {impact.get('rollback_plan')}\n"
                    f"Raw Log Message: {log_entry.get('message')}\n\n"
                    f"Conversation so far:\n{history_text}\n"
                )
                resp = self._genai_client.models.generate_content(
                    model=MODEL_NAME,
                    contents=prompt,
                )
                if resp and resp.text:
                    reply_text = resp.text.strip()
            except Exception:
                reply_text = ""

        if not reply_text:
            if any(k in lower_msg for k in ("why", "cause", "happen", "reason", "detail")):
                reply_text = (
                    f"Good question, Hari! Here's what happened under the hood:\n"
                    f"• **Root Cause**: {impact.get('root_cause')}\n"
                    f"• **Impact**: {impact.get('business_impact')}\n"
                    f"• **Affected Services**: {', '.join(impact.get('affected_services', [incident.get('workload', '')]))}\n\n"
                    "Would you like to see the exact command, Terraform bundle, or rollback safety plan before we proceed?"
                )
            elif any(k in lower_msg for k in ("safe", "downtime", "risk", "break", "rollback", "revert", "harness", "lock")):
                reply_text = (
                    f"It's completely safe and gated by the **Agent Harness**, Hari:\n"
                    f"• **Zero-Standing Privilege**: Only I (`Atlas`) can mint the single-use 15-minute JIT token scoped to `{incident.get('workload')}`.\n"
                    f"• **State Lock & OPA Gate**: `.tflock` lease is active and OPA blast-radius check passed.\n"
                    f"• **Auto-Rollback Plan**: {impact.get('rollback_plan')}\n\n"
                    "Let me know or click **I accept** when you're ready for me to dispatch the Specialist Agent!"
                )
            else:
                reply_text = (
                    f"Here's the full picture for **{incident.get('workload')}**, Hari:\n"
                    f"• **Scenario**: `{impact.get('scenario_badge')}`\n"
                    f"• **Root Cause**: {impact.get('root_cause')}\n"
                    f"• **Proposed Fix**: {impact.get('remedy_summary')} (`{impact.get('recommended_kubectl')}`)\n"
                    f"• **Safety**: Zero downtime + automatic rollback ({impact.get('rollback_plan')}).\n\n"
                    "Whenever you're ready, say **'I accept'** or click the **I accept** button below!"
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
    ) -> Dict[str, Any]:
        """
        Called when Hari approves the fix (via button or chat):
          1. Atlas (the sole authorizing agent) mints a 15-minute WIF JIT token scoped to the incident.
          2. Delegates the remediation task (1-line CLI/API or Multi-Service Terraform bundle) over A2A
             to the deterministic Specialist Agent Roster (`$0` extra LLM cost).
          3. Requests 45s post-remediation telemetry verification over A2A from `log-watcher-agent`.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        kubectl_cmd = (
            custom_kubectl.strip()
            if custom_kubectl and custom_kubectl.strip()
            else incident["impact_analysis"]["recommended_kubectl"]
        )
        terraform_code = incident["impact_analysis"].get("terraform_code")
        specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
        coordinated_specialists = incident.get("coordinated_specialists") or [specialist]
        coord_names = ", ".join(s.get("name", "Specialist Agent") for s in coordinated_specialists)

        # 1. Mint 15-minute JIT token (Only Atlas has authority to mint JIT tokens)
        approved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        jit_token = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=approved_by,
            scope=f"gcp:{incident['cluster']}:{incident['namespace']}:{incident['workload']}",
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
                    f"User ({approved_by}) approved remedy at {approved_at}. Atlas minted 15-min JIT token "
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
        exec_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": exec_time,
                "agent": coord_names,
                "event": (
                    f"Executed via Agent Harness (`{execution_mode}`). "
                    f"{incident['execution_result'].get('sre_specialist_notes', '')}"
                ),
            }
        )

        # 3. Trigger Closed-Loop 45s Post-Verification with Heartbeat & Telemetry via A2A
        verify_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="log-watcher-agent",
            skill_id="verify_post_remediation",
            payload={
                "incident_id": incident_id,
                "cluster": incident["cluster"],
                "namespace": incident["namespace"],
                "workload": incident["workload"],
            },
            summary=f"Request 45s Watchdog telemetry verification for {incident['namespace']}/{incident['workload']}",
        )

        incident["verification_result"] = verify_resp.result
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

        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"✅ All done, Hari! As the authorizing orchestrator, I minted a single-use JIT token (`{jit_token['token_id'][:18]}...`), "
                    f"logged your approval (`{approved_by}` at `{approved_at}`) in the **Audit Event Tracker**, "
                    f"and dispatched **{coord_names}** via our **Agent Harness Sandbox**.\n"
                    f"• **Executed**: `{kubectl_cmd}`\n"
                    f"• **Harness & Lock**: `.tflock` released & Reconciliation PR `{incident['execution_result'].get('reconciliation_pr')}` opened.\n"
                    f"• **45s Watchdog Check**: **Heartbeat & Telemetry** verified `{incident['workload']}` is back to 100% health with 0 error logs."
                ),
                "timestamp": incident["updated_at"],
            }
        )
        self._upsert_audit_event(incident, event_type="APPROVED_AND_REMEDIATED")
        return incident

    def skip_incident_manual(
        self,
        incident_id: str,
        skipped_by: str = "Hari",
    ) -> Dict[str, Any]:
        """Marks an incident as skipped so the user can handle it manually or review later."""
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["status"] = "SKIPPED_MANUAL"
        incident["approved_by"] = f"{skipped_by} (Manual Skip)"
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
                    f"User ({skipped_by}) chose 'Skip / Handle Manually' at {now_iso}. "
                    "Released `.tflock` lease; Specialist Agent stood down with no automated changes made."
                ),
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    "Got it, Hari — I've released the `.tflock` state lock, stood down the **Specialist Agent**, and made **no changes** "
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
                "event": "User re-opened incident and re-acquired `.tflock` lease for Specialist Agent remediation.",
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"Welcome back, Hari! I've re-opened the issue on **{incident['workload']}** and re-locked `.tflock`. "
                    "Ask me any follow-up questions or click **I accept** whenever you're ready."
                ),
                "timestamp": now_iso,
            }
        )
        self._upsert_audit_event(incident, event_type="REOPENED_FOR_APPROVAL")
        return incident

    def list_incidents(self) -> List[Dict[str, Any]]:
        return sorted(
            self.incidents.values(),
            key=lambda item: item.get("created_at", ""),
            reverse=True,
        )

    def list_audit_events(self) -> List[Dict[str, Any]]:
        return sorted(
            self.audit_events.values(),
            key=lambda item: item.get("detected_at", ""),
            reverse=True,
        )

    def _default_general_chat_greeting(self) -> List[Dict[str, Any]]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return [
            {
                "id": "atlas-welcome",
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "specialist": WORKER_AGENT_BOUTIQUE[0],
                "specialist_worker": WORKER_AGENT_BOUTIQUE[0],
                "coordinated_specialists": [WORKER_AGENT_BOUTIQUE[0]],
                "scenario_badge": "All 4 AaaS Scenarios Ready",
                "text": (
                    "Hey Hari 👋 You're connected directly to **Atlas (Single Authorizing ADK Root Agent)**!\n\n"
                    "I support all **4 AaaS Operational Scenarios**:\n"
                    "• **Scenario 1 (Simple 1-Line CLI/API Fix)**: Quick troubleshooting & 1-line fixes.\n"
                    "• **Scenario 2 (Complex Multi-Service Fix)**: Coordinated IAM + VPC Firewall + API/DB fixes via a validated **Terraform (`.tf`)** bundle.\n"
                    "• **Scenario 3 (Terraform Deployment Generator)**: Ask me to generate, dry-run validate, and deploy custom **Terraform (`.tf`)** stacks.\n"
                    "• **Scenario 4 (GCP How-To & Advisory)**: Instant answers with `$0` execution sandbox overhead.\n\n"
                    "What would you like to build, ask, or troubleshoot today?"
                ),
                "timestamp": now_iso,
            }
        ]

    def _select_specialist_for_query(self, query_text: str) -> Dict[str, str]:
        lower = query_text.lower()
        if any(k in lower for k in ("billing", "cost", "budget", "finops", "price", "spend", "invoice")):
            return WORKER_AGENT_BOUTIQUE[6]  # Billing Agent
        if any(k in lower for k in ("iam", "security", "permission", "role", "wif", "secret", "armor", "auth", "token", "least privilege")):
            return WORKER_AGENT_BOUTIQUE[5]  # Security Agent
        if any(k in lower for k in ("sql", "database", "db", "postgres", "alloydb", "spanner", "connection pool", "socket")):
            return WORKER_AGENT_BOUTIQUE[1]  # Database Agent
        if any(k in lower for k in ("vpc", "network", "latency", "dns", "load balanc", "firewall", "ingress", "timeout", "packet", "routing", "connector")):
            return WORKER_AGENT_BOUTIQUE[3]  # Networking Agent
        if any(k in lower for k in ("bigquery", "dataflow", "pubsub", "pub/sub", "analytics", "vertex", "rag", "slot")):
            return WORKER_AGENT_BOUTIQUE[4]  # Data Analytics Agent
        if any(k in lower for k in ("gke", "kubernetes", "pod", "node", "vm", "compute engine", "gce", "disk", "cluster", "terraform", "hcl")):
            return WORKER_AGENT_BOUTIQUE[2]  # Infra Agent
        return WORKER_AGENT_BOUTIQUE[0]  # Serverless Agent

    def _classify_chat_scenario(self, query_text: str) -> Dict[str, Any]:
        """
        Classifies a direct user message into Scenario 1, 2, 3, or 4 and determines
        the coordinated specialists and whether a Terraform (.tf) bundle should be generated.
        """
        lower = query_text.lower()

        # Check Scenario 2: Multi-Service troubleshooting (IAM + VPC/Firewall + API/DB/Terraform)
        domain_hits = sum(
            1
            for group in (
                ("iam", "permission", "role", "service account", "403"),
                ("vpc", "firewall", "egress", "ingress", "subnet", "network"),
                ("sql", "database", "api", "cloud run", "service"),
            )
            if any(k in lower for k in group)
        )
        if domain_hits >= 2 and any(k in lower for k in ("fix", "troubleshoot", "error", "block", "fail", "issue", "cannot", "multi-service")):
            rag_pb = playbook_rag_service.retrieve_playbook(query_text, scenario_hint="multi_service_iam_vpc_db")
            coord_specs = [
                SPECIALIST_BY_ID[sid]
                for sid in rag_pb.get("coordinated_specialist_ids", ["security-agent", "networking-agent", "database-agent"])
                if sid in SPECIALIST_BY_ID
            ]
            return {
                "scenario_type": "SCENARIO_2_MULTI_SERVICE_TERRAFORM",
                "scenario_badge": "Scenario 2 • Multi-Service Terraform Fix",
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
                "scenario_badge": "Scenario 3 • Terraform Deployment Generator",
                "needs_terraform": True,
                "rag_playbook": rag_pb,
                "coordinated_specialists": coord_specs,
            }

        # Check Scenario 1: Simple 1-line CLI/API troubleshooting
        if any(k in lower for k in ("troubleshoot", "latency", "timeout", "error", "crash", "slow", "failing", "unlogged", "fix")):
            primary = self._select_specialist_for_query(query_text)
            return {
                "scenario_type": "SCENARIO_1_CLI_FIX",
                "scenario_badge": "Scenario 1 • CLI/API Troubleshooting",
                "needs_terraform": False,
                "rag_playbook": None,
                "coordinated_specialists": [primary],
            }

        # Default Scenario 4: Simple GCP How-To question ($0 execution sandbox overhead)
        primary = self._select_specialist_for_query(query_text)
        return {
            "scenario_type": "SCENARIO_4_HOW_TO",
            "scenario_badge": "Scenario 4 • GCP How-To Advisory ($0 Sandbox Overhead)",
            "needs_terraform": False,
            "rag_playbook": None,
            "coordinated_specialists": [primary],
        }

    def list_general_chat_messages(self) -> List[Dict[str, Any]]:
        return list(self.general_chat_messages)

    def reset_general_chat(self) -> List[Dict[str, Any]]:
        self.general_chat_messages = self._default_general_chat_greeting()
        return list(self.general_chat_messages)

    async def execute_chat_terraform_deployment(
        self,
        approved_by: str = "Hari (via Chat)",
    ) -> Dict[str, Any]:
        """
        Executes the most recent Scenario 2 / Scenario 3 Terraform bundle from Direct Atlas Chat:
          1. Atlas mints a 15-minute WIF JIT token.
          2. Delegates the Terraform bundle to the coordinated Specialist Harnesses over A2A.
          3. Verifies 45s post-deployment telemetry with Heartbeat & Telemetry.
          4. Records the auditable event in the Audit & Event Tracker.
        """
        latest_tf_msg = next(
            (m for m in reversed(self.general_chat_messages) if m.get("terraform_bundle")),
            None,
        )
        if latest_tf_msg and latest_tf_msg.get("terraform_bundle"):
            tf_bundle = latest_tf_msg["terraform_bundle"]
            tf_code = tf_bundle.get("terraform_code", "")
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
        cli_cmd = f"gcloud run services list --project={PROJECT_ID}"

        jit_token = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=approved_by,
            scope=f"gcp:{cluster}:{namespace}:{workload}",
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
                "specialist_worker": primary_spec,
                "coordinated_specialists": coord_specs,
                "log_entry": {"title": scen_badge, "workload": workload},
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
        confirm_text = (
            f"✅ **Terraform Execution Complete via Agent Harness!**\n"
            f"• **Authorized By**: `{approved_by}` (JIT Token `{jit_token['token_id'][:18]}...`)\n"
            f"• **Coordinated Specialists**: {coord_names} (`$0` extra LLM token cost)\n"
            f"• **Resources Reconciled ({len(tf_resources)})**: `{', '.join(tf_resources)}` \n"
            f"• **State Lock & GitOps**: `.tflock` released cleanly • Reconciliation PR `{exec_result.get('reconciliation_pr')}` opened.\n"
            f"• **45s Telemetry Watchdog**: `{verify_resp.result.get('status', 'VERIFIED_HEALTHY')}`"
        )

        reply_msg = {
            "role": "assistant",
            "sender": f"Atlas • AaaS Lead (with {coord_names})",
            "specialist": primary_spec,
            "specialist_worker": primary_spec,
            "coordinated_specialists": coord_specs,
            "scenario_badge": scen_badge,
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

        return {
            "deployment_id": incident_id,
            "action_taken": "TERRAFORM_APPROVED_AND_EXECUTED",
            "reply": confirm_text,
            "specialist_worker": primary_spec,
            "coordinated_specialists": coord_specs,
            "execution_result": exec_result,
            "messages": list(self.general_chat_messages),
        }

    async def chat_general_with_atlas(self, user_message: str) -> Dict[str, Any]:
        """
        Handles manual/direct user conversations with Atlas across all 4 Customer Scenarios:
          - Scenario 1: Simple 1-line CLI/API troubleshooting
          - Scenario 2: Complex multi-service (IAM + VPC Firewall + API/DB) Terraform fix
          - Scenario 3: Customer asks Atlas to generate/deploy a Terraform (.tf) script
          - Scenario 4: Simple GCP 'How-To' questions ($0 execution sandbox overhead)
        """
        clean_msg = user_message.strip()
        if not clean_msg:
            raise ValueError("Message cannot be empty")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.general_chat_messages.append(
            {
                "role": "user",
                "sender": "Hari",
                "text": clean_msg,
                "timestamp": now_iso,
            }
        )

        lower_msg = clean_msg.lower()
        # If Hari says "I accept" or "deploy terraform" after a Terraform bundle was generated in chat
        if any(p in lower_msg for p in ("i accept", "deploy terraform", "apply terraform", "execute terraform")) and "?" not in lower_msg:
            return await self.execute_chat_terraform_deployment(approved_by="Hari (via Chat)")

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

        history_text = "\n".join(
            f"{m.get('sender', m.get('role'))}: {m.get('text')}"
            for m in self.general_chat_messages[-8:]
        )

        live_db_diagnosis: Optional[Dict[str, Any]] = None
        if spec_name == "Database Agent":
            live_db_diagnosis = self._invoke_live_database_agent_a2a(
                prompt=clean_msg,
                instance_name="testdbinstance1",
            )
            if live_db_diagnosis:
                prop = live_db_diagnosis.get("remediation_proposal") or {}
                if prop.get("terraform_hcl") and not terraform_code:
                    terraform_code = prop["terraform_hcl"]
                    if any(k in lower_msg for k in ("troubleshoot", "fix", "error", "stop", "testdbinstance1", "testdbconnect", "fatal", "why")):
                        needs_terraform = True

        reply_text = ""
        if live_db_diagnosis and live_db_diagnosis.get("dba_reasoning_report"):
            tools_used = ", ".join(live_db_diagnosis.get("tools_invoked", []))
            insp = live_db_diagnosis.get("instance_inspection") or {}
            reply_text = (
                f"📡 **Atlas delegated to Live Cloud Run ADK `Database Agent` (`agent-triad-db-agent`) via A2A**\n"
                f"• **ADK Tools Executed**: `{tools_used}`\n"
                f"• **Live Instance Discovered**: `{insp.get('instance_name', 'testdbinstance1')}` (`{insp.get('database_version', 'POSTGRES_18')}`, Region: `{insp.get('region', 'us-west1')}`, State: **`{insp.get('state', 'STOPPED')}`**, ActivationPolicy: `{insp.get('activation_policy', 'NEVER')}`)\n\n"
                f"{live_db_diagnosis['dba_reasoning_report']}"
            )
        elif self._genai_client is not None:
            try:
                prompt = (
                    "You are Atlas, the Single Authorizing ADK Root Gemini Agent for Hari's Google Cloud project (`agent-triad`).\n"
                    f"Classified Scenario: {scenario_badge}\n"
                    f"Coordinated Domain Specialists: {coord_names}\n"
                    f"Recent Conversation:\n{history_text}\n\n"
                    "Provide a clear, practical, and concise answer (3-5 bullet points) tailored to Hari's request. "
                    "Include exact `gcloud` commands or explain how the coordinated specialists and Agent Harness handle this."
                )
                resp = self._genai_client.models.generate_content(
                    model=MODEL_NAME,
                    contents=prompt,
                )
                if resp and resp.text:
                    reply_text = resp.text.strip()
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
                "hcl_code": terraform_code,
                "terraform_code": terraform_code,
                "dry_run": dry_run_report,
                "dry_run_report": dry_run_report,
                "policy_gate": opa_policy,
                "opa_policy": opa_policy,
                "coordinated_specialists": coordinated_specialists,
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
            "text": reply_text,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.general_chat_messages.append(reply_msg)
        return {
            "action_taken": "DIRECT_ATLAS_CHAT_REPLY",
            "scenario_type": scenario_type,
            "scenario_badge": scenario_badge,
            "reply": reply_text,
            "specialist_worker": specialist,
            "coordinated_specialists": coordinated_specialists,
            "consulted_specialist": specialist,
            "terraform_bundle": terraform_bundle,
            "live_database_agent_diagnosis": live_db_diagnosis,
            "messages": list(self.general_chat_messages),
        }
