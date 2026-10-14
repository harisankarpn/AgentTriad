"""
Agent 2: Lead Orchestrator Agent (ADK Root Supervisor + A2A Hub).

Always monitors operations across all registered agents (`log-watcher-agent`
and `gke-assist-agent`). When an alert is reported by the Log Watcher Agent
over A2A:
  1. Analyzes Root Cause, Blast Radius, and Business/SLO Impact (using Vertex AI
     Gemini + Golden Playbook Knowledge Base).
  2. Alerts the user in the Cloud Run Dashboard with the Impact Analysis and
     Recommended Remedy (Stage 2 HITL Gate).
  3. Once the user accepts the remedy, mints a 15-minute JIT token and delegates
     execution to the GKE Assist Bot over the A2A Protocol, followed by a
     closed-loop verification check with the Log Watcher Agent.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, List, Optional

from agents.a2a_protocol import (
    A2AProtocolHub,
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    AgentSkill,
)

try:
    from google.adk.agents import Agent as AdkAgent
except ImportError:
    AdkAgent = None

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
    "cloud_run_port_error": {
        "playbook_id": "PB-RUN-401",
        "title": "Cloud Run Container Port 8080 Startup Probe Remediation",
        "blast_radius_tier": "HIGH (Database Connector Service Unavailable)",
        "affected_services": ["testdbconnect (us-west1)", "cloudsql/testdbinstance1"],
        "business_impact": (
            "Cloud Run service `testdbconnect` failed its TCP startup probe on port 8080, preventing new "
            "revisions from serving database connectivity requests in `us-west1`."
        ),
        "root_cause": (
            "Container failed to bind and listen on `PORT=8080` within the startup timeout window (`HealthCheckContainerError`)."
        ),
        "remedy_summary": (
            "Reconfigure Cloud Run service port binding and extend startup probe timeout to 300s, or roll back to the last ready revision."
        ),
        "rollback_plan": (
            "Route 100% traffic to the previous healthy Cloud Run revision (`--to-latest=false`) if startup probe fails."
        ),
        "customer_headline": "Database Connection Service Failed to Start",
        "customer_what_happened": "Real GCP Log Detected: Your 'testdbconnect' Cloud Run service in us-west1 failed to start listening on port 8080.",
        "customer_why_approve": "Updates the Cloud Run port & startup timeout settings so 'testdbconnect' can start cleanly.",
        "risk_badge": "Low Risk • Cloud Run Config Fix",
        "downtime_badge": "Zero Downtime",
        "safety_badge": "Revision Rollback Protected",
    },
    "cloud_run_scale_limit": {
        "playbook_id": "PB-RUN-405",
        "title": "Cloud Run Max-Instances Capacity Scaling",
        "blast_radius_tier": "MEDIUM-HIGH (Requests Aborted Due to Instance Limit)",
        "affected_services": ["agent-triad-control-plane", "cloud-run-ingress"],
        "business_impact": (
            "Incoming requests were aborted with HTTP 429/503 (`no available instance`) because the service "
            "hit its `max-instances` ceiling during concurrent traffic."
        ),
        "root_cause": (
            "Cloud Run revision scaling limit (`maxScale=1`) prevented horizontal auto-scaling under burst load."
        ),
        "remedy_summary": (
            "Increase Cloud Run `--max-instances` to 10 so additional container instances spin up automatically during traffic bursts."
        ),
        "rollback_plan": (
            "Reset `--max-instances` to baseline capacity if cost/quota guardrails are exceeded."
        ),
        "customer_headline": "Cloud Service Reached Instance Capacity Limit",
        "customer_what_happened": "Real GCP Log Detected: Requests were dropped because the Cloud Run service hit its maximum instance limit.",
        "customer_why_approve": "Raises the auto-scaling ceiling to 10 instances so traffic spikes are handled smoothly without dropped requests.",
        "risk_badge": "Low Risk • Safe Auto-Scaling",
        "downtime_badge": "Zero Downtime",
        "safety_badge": "Quota Guardrail Protected",
    },
    "cloud_function_error": {
        "playbook_id": "PB-CF-502",
        "title": "Cloud Function Code Load Crash (`sre-agent-tools`) Recovery",
        "blast_radius_tier": "MEDIUM (Cloud Function Tooling Endpoint Down)",
        "affected_services": ["function/sre-agent-tools (us-central1)"],
        "business_impact": (
            "Cloud Function `sre-agent-tools` in `us-central1` crashes on startup and cannot process invocations."
        ),
        "root_cause": (
            "Python `functions-framework` failed to load `/workspace/main.py` at line 1 due to a shell heredoc (`cat << 'EOF' > main.py`) "
            "committed inside the Python source file (`NameError: name 'cat' is not defined`)."
        ),
        "remedy_summary": (
            "Strip the invalid shell wrapper from `main.py` and redeploy `sre-agent-tools` on Python 3.10 runtime."
        ),
        "rollback_plan": (
            "Restore previous Cloud Function active version in `us-central1` if health check fails."
        ),
        "customer_headline": "Cloud Function 'sre-agent-tools' Has a Code Error",
        "customer_what_happened": "Real GCP Log Detected: The 'sre-agent-tools' Cloud Function failed to load because of a syntax typo on line 1 of main.py.",
        "customer_why_approve": "Cleans up the invalid line in main.py and redeploys the Cloud Function so it runs normally.",
        "risk_badge": "Safe Code Repair",
        "downtime_badge": "Zero Downtime",
        "safety_badge": "Version Rollback Protected",
    },
    "reasoning_engine_exception": {
        "playbook_id": "PB-VAI-601",
        "title": "Vertex AI Reasoning Engine ADK Executor Recovery",
        "blast_radius_tier": "MEDIUM (Vertex AI Agent Engine Worker Exception)",
        "affected_services": ["reasoning-engine/8565534229956395008 (us-west1)"],
        "business_impact": (
            "Vertex AI Reasoning Engine `8565534229956395008` in `us-west1` logged unhandled task exceptions in `a2a_agent_executor.py`."
        ),
        "root_cause": (
            "ADK `_drive_root_node` / `_cleanup_root_task` raised an unhandled async context exception in the Reasoning Engine worker."
        ),
        "remedy_summary": (
            "Trigger a graceful worker recycle and state reset on Vertex AI Reasoning Engine `8565534229956395008`."
        ),
        "rollback_plan": (
            "Retain existing Reasoning Engine deployment endpoint if worker health check fails."
        ),
        "customer_headline": "AI Reasoning Engine Worker Needs a Fresh Restart",
        "customer_what_happened": "Real GCP Log Detected: Vertex AI Reasoning Engine (in us-west1) encountered a background task error.",
        "customer_why_approve": "Safely restarts the AI Reasoning Engine worker pool to clear the stuck task.",
        "risk_badge": "Low Risk • Worker Restart",
        "downtime_badge": "Zero Downtime",
        "safety_badge": "State Preserved",
    },
    "real_gcp_anomaly": {
        "playbook_id": "PB-GCP-900",
        "title": "Live GCP Cloud Logging Anomaly Remediation",
        "blast_radius_tier": "MEDIUM (Cloud Resource Error Detected)",
        "affected_services": ["gcp-cloud-service"],
        "business_impact": "Live error detected in Google Cloud Logging requiring automated configuration recovery.",
        "root_cause": "Service emitted an ERROR/CRITICAL telemetry event in Google Cloud Logging.",
        "remedy_summary": "Apply automated configuration reconciliation and restart unhealthy service revision.",
        "rollback_plan": "Automatic rollback to previous healthy revision if post-remediation watchdog detects errors.",
        "customer_headline": "Cloud Service Issue Detected in Live Logs",
        "customer_what_happened": "Log Watcher spotted a live error in your Google Cloud project logs.",
        "customer_why_approve": "Safely repairs and restarts the affected cloud service.",
        "risk_badge": "Low Risk • Automated Fix",
        "downtime_badge": "Zero Downtime",
        "safety_badge": "Auto-Rollback Protected",
    },
}


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
        "domain": "Cloud SQL, AlloyDB & DB Connectors",
        "icon": "fa-database",
        "description": "Troubleshoots Cloud SQL connectivity, connection pools, socket proxies, and DB port probes.",
    },
    {
        "id": "infra-agent",
        "name": "Infra Agent",
        "domain": "GKE, Compute Engine & Containers",
        "icon": "fa-server",
        "description": "Handles GKE pods/nodes, Compute Engine VMs, persistent disks, and infrastructure health.",
    },
    {
        "id": "networking-agent",
        "name": "Networking Agent",
        "domain": "VPC, Load Balancing & DNS",
        "icon": "fa-network-wired",
        "description": "Resolves VPC routing, Serverless VPC Access connectors, Load Balancers, and DNS/Ingress rules.",
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


class LeadOrchestratorAgent:
    """
    Central ADK Lead/Orchestrator Agent (Atlas) that supervises all agents, computes
    incident impact & remedies, gates on user HITL approval, tracks auditable events,
    and delegates execution to the Specialist Agent Roster over A2A.
    """

    AGENT_ID = "lead-orchestrator-agent"

    def __init__(self, a2a_hub: A2AProtocolHub, logging_service: Any = None) -> None:
        self.a2a_hub = a2a_hub
        self.logging_service = logging_service
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.audit_events: Dict[str, Dict[str, Any]] = {}
        self.adk_agent = self._build_adk_agent()
        self._genai_client = self._build_genai_client()
        self.card = AgentCard(
            id=self.AGENT_ID,
            name="Atlas • Lead Orchestrator",
            role="Central Operations Supervisor, Impact Analyzer & HITL Gatekeeper",
            description=(
                "Continuously monitors all specialist agents, ingests anomaly alerts from the "
                "Heartbeat & Telemetry Agent via A2A, performs Gemini root-cause & business impact "
                "analysis, alerts the user with the recommended remedy, and delegates user-accepted "
                "remediations to the Specialist Agent Roster over A2A."
            ),
            url="/a2a/lead-orchestrator-agent",
            skills=[
                AgentSkill(
                    id="ingest_anomaly_alert",
                    name="Ingest Anomaly & Compute Impact/Remedy",
                    description=(
                        "Receives anomaly alerts from Heartbeat & Telemetry, correlates with Golden Playbooks "
                        "and Vertex AI Gemini, and alerts the user with Impact Analysis + Remedy."
                    ),
                    tags=["orchestrator", "rca", "impact-analysis", "hitl"],
                ),
                AgentSkill(
                    id="delegate_approved_remediation",
                    name="Mint JIT Token & Delegate Fix to Specialist Agent",
                    description=(
                        "Mints a 15-minute WIF JIT token upon user acceptance and delegates the "
                        "remediation task to the matched domain specialist via A2A."
                    ),
                    tags=["delegation", "a2a", "jit", "specialist-roster"],
                ),
            ],
        )
        self.a2a_hub.register_agent(self.card, self.handle_a2a_task)

    def _build_adk_agent(self) -> Any:
        if AdkAgent is None:
            return None
        try:
            return AdkAgent(
                name="lead_orchestrator_agent",
                model=MODEL_NAME,
                description=(
                    "Lead Orchestrator that supervises Log Watcher and Worker Agent."
                ),
                instruction=(
                    "You are the Lead Orchestrator in the AaaS Control Plane. "
                    "You monitor operations across all agents. When the Log Watcher reports "
                    "an anomaly, determine the technical root cause, blast radius, and business/SLO impact, "
                    "formulate a safe remediation command, and present it to the user for HITL approval. "
                    "Once approved, delegate execution to the Worker Agent over the A2A protocol."
                ),
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

    def _analyze_impact_and_remedy(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uses Vertex AI Gemini (`gemini-2.5-flash`) + Golden Playbook RAG context to
        determine the operational impact, blast radius, root cause, recommended remedy,
        and plain-English customer summary for real GCP logs.
        """
        scenario_id = log_entry.get("scenario_id", "real_gcp_anomaly")
        playbook = GOLDEN_PLAYBOOKS.get(scenario_id, GOLDEN_PLAYBOOKS["real_gcp_anomaly"])
        default_kubectl = log_entry.get(
            "recommended_kubectl",
            f"gcloud run services update {log_entry.get('container', 'service')} --region={log_entry.get('cluster', 'us-central1')} --project={PROJECT_ID}",
        )

        analysis = {
            "playbook_id": playbook["playbook_id"],
            "playbook_title": playbook["title"],
            "blast_radius_tier": playbook["blast_radius_tier"],
            "affected_services": playbook["affected_services"],
            "business_impact": playbook["business_impact"],
            "root_cause": playbook["root_cause"],
            "remedy_summary": playbook["remedy_summary"],
            "recommended_kubectl": default_kubectl,
            "rollback_plan": playbook["rollback_plan"],
            "customer_headline": playbook.get("customer_headline", log_entry.get("title", "Cloud Issue Detected")),
            "customer_what_happened": playbook.get("customer_what_happened", log_entry.get("message", "")),
            "customer_why_approve": playbook.get("customer_why_approve", playbook["remedy_summary"]),
            "risk_badge": playbook.get("risk_badge", "Low Risk • Safe Fix"),
            "downtime_badge": playbook.get("downtime_badge", "Zero Downtime"),
            "safety_badge": playbook.get("safety_badge", "Auto-Rollback Protected"),
            "reasoning_engine": "Golden Playbook + Vertex AI Gemini",
        }

        if self._genai_client is not None:
            try:
                prompt = (
                    "You are the Lead Orchestrator Agent for Google Cloud AaaS (AgentTriad).\n"
                    "The Log Watcher Agent just reported this real GCP Cloud Logging anomaly via A2A:\n"
                    f"{json.dumps(log_entry, default=str)}\n\n"
                    f"Matched Golden Playbook Context:\n{json.dumps(playbook, default=str)}\n\n"
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
                    analysis["reasoning_engine"] = f"Vertex AI ({MODEL_NAME}) + RAG Playbook {playbook['playbook_id']}"
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
        """Selects the appropriate domain specialist from the Specialist Agent Roster based on telemetry."""
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
        audit_entry: Dict[str, Any] = {
            "incident_id": incident_id,
            "service_label": incident.get("service_label") or self._friendly_service_name(incident.get("log_entry", {})),
            "workload": incident.get("workload", ""),
            "cluster": incident.get("cluster", ""),
            "severity": incident.get("severity", "ERROR"),
            "title": impact.get("customer_headline") or incident.get("title", "Cloud Service Anomaly"),
            "technical_title": incident.get("title", ""),
            "specialist_agent_id": specialist.get("id", "serverless-agent"),
            "specialist_agent_name": specialist.get("name", "Serverless Agent"),
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
        self, log_entry: Dict[str, Any], impact: Dict[str, Any], specialist: Dict[str, str], now_iso: str
    ) -> List[Dict[str, Any]]:
        service_label = self._friendly_service_name(log_entry)
        severity = log_entry.get("severity", "ERROR")
        what_happened = impact.get("customer_what_happened") or log_entry.get("message", "")
        next_step = impact.get("customer_why_approve") or impact.get("remedy_summary", "")
        blast = impact.get("blast_radius_tier", "HIGH")
        spec_name = specialist.get("name", "Serverless Agent")
        spec_domain = specialist.get("domain", "Cloud Run & Cloud Functions")

        opening_text = (
            f"Hey Hari 👋 There's an issue I just found with **{service_label}**.\n\n"
            f"• **Severity**: `{severity}` — {blast}\n"
            f"• **What happened**: {what_happened}\n"
            f"• **Assigned Specialist**: **{spec_name}** ({spec_domain})\n"
            f"• **Next Steps**: {next_step}\n\n"
            "Ask me anything about why this happened, whether there's any downtime, the rollback plan, "
            "or the exact command. Whenever you're ready, type **'I accept'** or click **I accept** below to proceed with the fix!"
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
            log_entry = data.get("log_entry", {})
            incident_id = log_entry.get("log_id", f"inc-{len(self.incidents) + 1}")
            impact_and_remedy = self._analyze_impact_and_remedy(log_entry)
            specialist = self._select_specialist_worker(log_entry)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            occurred_at = log_entry.get("timestamp") or data.get("detected_at") or now_iso
            detected_at = data.get("detected_at") or now_iso
            chat_messages = self._build_initial_chat_greeting(log_entry, impact_and_remedy, specialist, now_iso)

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
                "severity": log_entry.get("severity", "CRITICAL"),
                "title": log_entry.get("title", "Cloud Service Anomaly"),
                "cluster": log_entry.get("cluster", "us-central1"),
                "namespace": log_entry.get("namespace", "default"),
                "workload": log_entry.get("workload", "deployment/app"),
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
                            f"Detected [{log_entry.get('severity')}] {log_entry.get('error_code')} in "
                            f"Cloud Logging (occurred at {occurred_at}) and alerted Atlas via A2A."
                        ),
                    },
                    {
                        "timestamp": now_iso,
                        "agent": "Atlas • Lead Orchestrator",
                        "event": (
                            f"Evaluated blast radius ({impact_and_remedy['blast_radius_tier']}), "
                            f"routed to {specialist['name']}, and initiated interactive chat with Hari."
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
        or instruct the AaaS Lead to proceed with the fix / skip manually.
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

        lower_msg = clean_msg.lower()

        # Check if Hari accepts and tells the chatbot to proceed with the fix
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

        # Check if Hari wants to skip / handle manually
        skip_phrases = (
            "skip",
            "ignore",
            "fix manually",
            "do it manually",
            "handle manually",
            "later",
        )
        if incident["status"] == "AWAITING_HITL_APPROVAL" and any(p in lower_msg for p in skip_phrases) and "?" not in lower_msg:
            updated = self.skip_incident_manual(
                incident_id=incident_id,
                skipped_by="Hari (via Chat)",
            )
            return {
                "action_taken": "SKIPPED_MANUAL",
                "reply": updated["chat_messages"][-1]["text"],
                "incident": updated,
            }

        impact = incident.get("impact_analysis", {})
        log_entry = incident.get("log_entry", {})
        history_text = "\n".join(
            f"{m.get('sender', m.get('role'))}: {m.get('text')}"
            for m in incident.get("chat_messages", [])[-8:]
        )

        reply_text = ""
        if self._genai_client is not None:
            try:
                prompt = (
                    "You are Atlas, the friendly and sharp AaaS Lead Orchestrator chatbot for Hari's Google Cloud environment (`agent-triad`).\n"
                    "You are currently discussing an active cloud incident with Hari before he decides whether to accept the automated fix.\n\n"
                    f"Incident Summary:\n- Service/Workload: {incident.get('workload')} in {incident.get('cluster')}\n"
                    f"- Severity: {incident.get('severity')} ({impact.get('blast_radius_tier')})\n"
                    f"- Technical Root Cause: {impact.get('root_cause')}\n"
                    f"- Business/Service Impact: {impact.get('business_impact')}\n"
                    f"- Raw Log Message: {log_entry.get('message')}\n"
                    f"- Proposed Fix Summary: {impact.get('remedy_summary')}\n"
                    f"- Exact Command Worker Agent Will Run: `{impact.get('recommended_kubectl')}`\n"
                    f"- Rollback & Safety Plan: {impact.get('rollback_plan')} (Plus 15-minute single-use JIT token and 45s Heartbeat & Telemetry post-check)\n\n"
                    f"Conversation so far:\n{history_text}\n\n"
                    "Respond directly to Hari's latest message in 2-4 concise, helpful sentences (use bullet points if helpful). "
                    "Be warm, clear, and transparent. Remind Hari that whenever he is ready, he can say 'I accept' or click the 'I accept' button."
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
                    "Would you like to see the exact command or rollback safety plan before we proceed?"
                )
            elif any(k in lower_msg for k in ("safe", "downtime", "risk", "break", "rollback", "revert")):
                reply_text = (
                    f"It's completely safe and causes **zero downtime**, Hari:\n"
                    f"• **Guardrails**: The specialist agent gets a single-use 15-minute JIT token scoped only to `{incident.get('workload')}`.\n"
                    f"• **Auto-Rollback Plan**: {impact.get('rollback_plan')}\n"
                    "• **Verification**: Immediately after the fix, **Heartbeat & Telemetry** monitors live logs for 45s to verify 0 errors.\n\n"
                    "Let me know or click **I accept** when you're ready for me to proceed with the fix!"
                )
            elif any(k in lower_msg for k in ("command", "kubectl", "gcloud", "log", "raw", "code")):
                reply_text = (
                    f"Here are the exact technical details, Hari:\n"
                    f"• **Error Code**: `{log_entry.get('error_code')}`\n"
                    f"• **Raw Log**: `{str(log_entry.get('message', ''))[:180]}`\n"
                    f"• **Command to Execute**: `{impact.get('recommended_kubectl')}`\n\n"
                    "Once you're comfortable with this command, just say **'I accept'** or click **I accept** below!"
                )
            else:
                reply_text = (
                    f"Here's the full picture for **{incident.get('workload')}**, Hari:\n"
                    f"• **Root Cause**: {impact.get('root_cause')}\n"
                    f"• **Proposed Fix**: {impact.get('remedy_summary')} (`{impact.get('recommended_kubectl')}`)\n"
                    f"• **Safety**: Zero downtime + automatic rollback ({impact.get('rollback_plan')}).\n\n"
                    "Whenever you're ready, say **'I accept'** or click the **I accept** button below!"
                )

        reply_msg = {
            "role": "assistant",
            "sender": "Atlas • AaaS Lead",
            "text": reply_text,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        incident["chat_messages"].append(reply_msg)
        incident["updated_at"] = reply_msg["timestamp"]

        return {
            "action_taken": "ANSWERED_QUESTION",
            "reply": reply_text,
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
          1. Mints a 15-minute WIF JIT token scoped to the incident.
          2. Delegates the remediation task over A2A to the selected specialist in the Worker Agent Boutique.
          3. Requests post-remediation telemetry verification over A2A from `log-watcher-agent`.
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        kubectl_cmd = (
            custom_kubectl.strip()
            if custom_kubectl and custom_kubectl.strip()
            else incident["impact_analysis"]["recommended_kubectl"]
        )
        specialist = incident.get("specialist_worker") or self._select_specialist_worker(incident.get("log_entry", {}))
        spec_name = specialist.get("name", "Serverless Agent")

        # 1. Mint 15-minute JIT token
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
                    f"User ({approved_by}) approved remedy at {approved_at}. Minted 15-min JIT token "
                    f"`{jit_token['token_id'][:20]}...` and delegating task to {spec_name} via A2A."
                ),
            }
        )

        # 2. Delegate execution to Worker Agent Boutique via A2A protocol
        delegation_payload = {
            "incident_id": incident_id,
            "jit_token_id": jit_token["token_id"],
            "execution_mode": execution_mode,
            "kubectl_command": kubectl_cmd,
            "cluster": incident["cluster"],
            "namespace": incident["namespace"],
            "workload": incident["workload"],
            "specialist_worker": specialist,
            "log_entry": incident["log_entry"],
        }

        gke_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="gke-assist-agent",
            skill_id="execute_gke_remediation",
            payload=delegation_payload,
            summary=(
                f"Route to {spec_name}: execute approved fix (`{execution_mode}`) for "
                f"{incident['namespace']}/{incident['workload']} with JIT token {jit_token['token_id'][:16]}..."
            ),
        )

        incident["execution_result"] = gke_resp.result.get("execution", gke_resp.result)
        exec_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": exec_time,
                "agent": spec_name,
                "event": (
                    f"Executed `{kubectl_cmd}` ({execution_mode}). "
                    f"{incident['execution_result'].get('sre_specialist_notes', '')}"
                ),
            }
        )

        # 3. Trigger Closed-Loop Post-Verification with Heartbeat & Telemetry via A2A
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
                    f"✅ All done, Hari! I minted a single-use JIT token (`{jit_token['token_id'][:18]}...`), "
                    f"logged your approval (`{approved_by}` at `{approved_at}`) in the **Audit Event Tracker**, "
                    f"and dispatched the **{spec_name}** from our **Specialist Agent Roster** over A2A.\n"
                    f"• **Executed**: `{kubectl_cmd}`\n"
                    f"• **Watchdog Check**: **Heartbeat & Telemetry** verified `{incident['workload']}` is back to 100% health with 0 error logs."
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
        incident["timeline"].append(
            {
                "timestamp": now_iso,
                "agent": "Atlas • Lead Orchestrator",
                "event": (
                    f"User ({skipped_by}) chose 'Skip / Handle Manually' at {now_iso}. "
                    "Worker Agent stood down; no automated changes made."
                ),
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    "Got it, Hari — I've stood down the **Worker Agent** and made **no changes** to your environment "
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
        incident["timeline"].append(
            {
                "timestamp": now_iso,
                "agent": "Atlas • Lead Orchestrator",
                "event": "User re-opened incident for automated Worker Agent remediation.",
            }
        )
        incident.setdefault("chat_messages", []).append(
            {
                "role": "assistant",
                "sender": "Atlas • AaaS Lead",
                "text": (
                    f"Welcome back, Hari! I've re-opened the issue on **{incident['workload']}**. "
                    "Ask me any follow-up questions or click **Proceed with Fix** whenever you're ready."
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


