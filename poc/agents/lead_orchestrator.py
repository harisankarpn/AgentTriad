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
    "oom_killed": {
        "playbook_id": "PB-GKE-101",
        "title": "GKE Container OOMKilled / Exit Code 137 Remediation",
        "blast_radius_tier": "HIGH (Tier-1 Payment Checkout Flow)",
        "affected_services": [
            "payment-checkout-service",
            "cart-api-gateway (upstream 502s)",
            "stripe-webhook-dispatcher",
        ],
        "business_impact": (
            "18.4% of customer checkout requests are failing with HTTP 502/503 due to container "
            "OOM restarts (7 restarts in 5m). P99 checkout latency degraded to 3,850ms."
        ),
        "root_cause": (
            "Container `checkout-worker` hit its hard cgroup memory limit (512Mi) during a "
            "concurrent flash-sale payload spike, triggering Linux kernel OOM killer (SIGKILL 137)."
        ),
        "remedy_summary": (
            "Vertically scale `checkout-worker` memory limit from 512Mi to 1Gi (request 768Mi) "
            "via rolling update with pre-execution snapshot and GitOps reconciliation PR."
        ),
        "rollback_plan": (
            "Stateless compute atomic rollback (`kubectl rollout undo deployment/payment-checkout-service`) "
            "if post-change error rate > 1% within 45s watchdog window."
        ),
    },
    "cpu_throttling": {
        "playbook_id": "PB-GKE-204",
        "title": "GKE CFS CPU Quota Throttling & Horizontal Scaling",
        "blast_radius_tier": "MEDIUM-HIGH (Storefront API Latency Breach)",
        "affected_services": [
            "gke-web-v2",
            "cdn-edge-ingress",
            "product-catalog-bff",
        ],
        "business_impact": (
            "Storefront P99 latency spiked to 4,210ms (SLO target < 400ms) with 9.6% request timeouts "
            "across 2 overloaded replicas."
        ),
        "root_cause": (
            "High JVM worker thread contention (PID 40) holding CPU above 97% for >45s, causing Linux "
            "CFS bandwidth controller to throttle 84% of scheduling periods."
        ),
        "remedy_summary": (
            "Horizontally scale `deployment/gke-web-v2` from 2 to 6 replicas to distribute request concurrency "
            "below 45% CPU per pod."
        ),
        "rollback_plan": (
            "Scale back to baseline replicas (2) after 45-minute Temporal Hysteresis window or if "
            "cluster node CPU pressure exceeds 85%."
        ),
    },
    "image_pull_backoff": {
        "playbook_id": "PB-GKE-309",
        "title": "GKE Canary Rollout ImagePullBackOff Auto-Rollback",
        "blast_radius_tier": "HIGH (Order Fulfillment Pipeline Degraded)",
        "affected_services": [
            "order-processor (canary track)",
            "inventory-reservation-worker",
        ],
        "business_impact": (
            "50% of order-processor replicas are unavailable (`2/4 Ready`), causing 12.1% order queue "
            "backlog growth and delayed fulfillment confirmations."
        ),
        "root_cause": (
            "Canary deployment referenced non-existent Artifact Registry tag `v2.4.9-rc` (`manifest unknown`), "
            "stranding new pods in `ImagePullBackOff`."
        ),
        "remedy_summary": (
            "Execute atomic canary rollback of `deployment/order-processor` to known-good revision 14 "
            "(`v2.4.8-stable`) and quarantine broken image digest."
        ),
        "rollback_plan": (
            "Pin deployment to revision 14 and quarantine tag `v2.4.9-rc` in Poison-Pill Registry for 7 days."
        ),
    },
}


class LeadOrchestratorAgent:
    """
    Central ADK Lead/Orchestrator Agent that supervises all agents, computes
    incident impact & remedies, gates on user HITL approval, and delegates execution
    to specialist agents over A2A.
    """

    AGENT_ID = "lead-orchestrator-agent"

    def __init__(self, a2a_hub: A2AProtocolHub) -> None:
        self.a2a_hub = a2a_hub
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.adk_agent = self._build_adk_agent()
        self._genai_client = self._build_genai_client()
        self.card = AgentCard(
            id=self.AGENT_ID,
            name="Lead Orchestrator Agent",
            role="Central Operations Supervisor, Impact Analyzer & HITL Gatekeeper",
            description=(
                "Continuously monitors all specialist agents, ingests anomaly alerts from the "
                "Cloud Logging Watcher Agent via A2A, performs Gemini root-cause & business impact "
                "analysis, alerts the user with the recommended remedy, and delegates user-accepted "
                "remediations to the GKE Assist Bot over A2A."
            ),
            url="/a2a/lead-orchestrator-agent",
            skills=[
                AgentSkill(
                    id="ingest_anomaly_alert",
                    name="Ingest Anomaly & Compute Impact/Remedy",
                    description=(
                        "Receives anomaly alerts from Log Watcher, correlates with Golden Playbooks "
                        "and Vertex AI Gemini, and alerts the user with Impact Analysis + Remedy."
                    ),
                    tags=["orchestrator", "rca", "impact-analysis", "hitl"],
                ),
                AgentSkill(
                    id="delegate_approved_remediation",
                    name="Mint JIT Token & Delegate Fix to GKE Assist Bot",
                    description=(
                        "Mints a 15-minute WIF JIT token upon user acceptance and delegates the "
                        "remediation task to GKE Assist Bot via A2A."
                    ),
                    tags=["delegation", "a2a", "jit", "gke-assist"],
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
                    "Lead Orchestrator Agent that supervises Cloud Logging Watcher and GKE Assist Bot."
                ),
                instruction=(
                    "You are the Lead Orchestrator Agent in the AgentTriad AaaS Control Plane. "
                    "You monitor operations across all agents. When the Cloud Logging Watcher reports "
                    "an anomaly, determine the technical root cause, blast radius, and business/SLO impact, "
                    "formulate a safe GKE remediation command, and present it to the user for HITL approval. "
                    "Once approved, delegate execution to the GKE Assist Bot over the A2A protocol."
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
        determine the operational impact, blast radius, root cause, and recommended remedy.
        Falls back cleanly to structured Golden Playbook analysis if offline.
        """
        scenario_id = log_entry.get("scenario_id", "oom_killed")
        playbook = GOLDEN_PLAYBOOKS.get(scenario_id, GOLDEN_PLAYBOOKS["oom_killed"])
        default_kubectl = log_entry.get(
            "recommended_kubectl",
            "kubectl rollout restart deployment/payment-checkout-service -n prod-payments",
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
            "reasoning_engine": "Golden Playbook + Vertex AI Gemini",
        }

        if self._genai_client is not None:
            try:
                prompt = (
                    "You are the Lead Orchestrator Agent for Google Cloud AaaS (AgentTriad).\n"
                    "The Cloud Logging Watcher Agent just reported this GKE anomaly log via A2A:\n"
                    f"{json.dumps(log_entry, default=str)}\n\n"
                    f"Matched Golden Playbook Context:\n{json.dumps(playbook, default=str)}\n\n"
                    "Return a JSON object with keys:\n"
                    "- root_cause (string, 1-2 sentences)\n"
                    "- business_impact (string, 1-2 sentences quantifying user/SLO impact)\n"
                    "- blast_radius_tier (string, e.g. 'HIGH (Tier-1 Checkout Flow)')\n"
                    "- affected_services (array of strings)\n"
                    "- remedy_summary (string, 1-2 sentences explaining the fix)\n"
                    "- recommended_kubectl (string, exact kubectl command)\n"
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

    async def handle_a2a_task(self, request: A2ATaskRequest) -> A2ATaskResponse:
        """Handles incoming A2A `ingest_anomaly_alert` tasks from the Cloud Logging Watcher Agent."""
        skill_id = request.params.get("skill_id", "")
        parts = request.params.get("message", {}).get("parts", [])
        data = parts[0].get("data", {}) if parts else {}

        if skill_id == "ingest_anomaly_alert":
            log_entry = data.get("log_entry", {})
            incident_id = log_entry.get("log_id", f"inc-{len(self.incidents) + 1}")
            impact_and_remedy = self._analyze_impact_and_remedy(log_entry)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            incident_record: Dict[str, Any] = {
                "incident_id": incident_id,
                "created_at": now_iso,
                "updated_at": now_iso,
                "status": "AWAITING_HITL_APPROVAL",
                "reported_by_agent": data.get("detector_agent", "log-watcher-agent"),
                "assigned_orchestrator": self.AGENT_ID,
                "delegated_specialist_agent": "gke-assist-agent",
                "severity": log_entry.get("severity", "CRITICAL"),
                "title": log_entry.get("title", "GKE Cluster Anomaly"),
                "cluster": log_entry.get("cluster", "gke-prod-us-central1"),
                "namespace": log_entry.get("namespace", "default"),
                "workload": log_entry.get("workload", "deployment/app"),
                "pod": log_entry.get("pod", "unknown-pod"),
                "error_code": log_entry.get("error_code", "GKE_ERROR"),
                "log_entry": log_entry,
                "impact_analysis": impact_and_remedy,
                "jit_token": None,
                "execution_result": None,
                "verification_result": None,
                "timeline": [
                    {
                        "timestamp": data.get("detected_at", now_iso),
                        "agent": "Cloud Logging Watcher Agent",
                        "event": (
                            f"Detected [{log_entry.get('severity')}] {log_entry.get('error_code')} in "
                            f"Cloud Logging and alerted Lead Orchestrator via A2A."
                        ),
                    },
                    {
                        "timestamp": now_iso,
                        "agent": "Lead Orchestrator Agent",
                        "event": (
                            f"Evaluated blast radius ({impact_and_remedy['blast_radius_tier']}) and "
                            f"matched Playbook {impact_and_remedy['playbook_id']}. Alerting user with "
                            "Impact & Recommended Remedy for HITL acceptance."
                        ),
                    },
                ],
            }
            self.incidents[incident_id] = incident_record

            return A2ATaskResponse(
                id=request.id,
                result={
                    "status": "AWAITING_HITL_APPROVAL",
                    "incident_id": incident_id,
                    "orchestrator": self.AGENT_ID,
                    "impact_analysis": impact_and_remedy,
                },
            )

        return A2ATaskResponse(
            id=request.id,
            result={"status": "OK", "agent": self.AGENT_ID},
        )

    async def approve_and_delegate_to_gke_assist(
        self,
        incident_id: str,
        approved_by: str = "sre-operator@cognizant.com",
        execution_mode: str = "dry_run",
        custom_kubectl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Called when the user clicks 'Accept & Execute Remedy' in the Dashboard UI:
          1. Mints a 15-minute WIF JIT token scoped to the incident.
          2. Delegates the remediation task over A2A to `gke-assist-agent`.
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

        # 1. Mint 15-minute JIT token
        jit_token = self.a2a_hub.jit_broker.mint_token(
            incident_id=incident_id,
            approved_by=approved_by,
            scope=f"gke:{incident['cluster']}:{incident['namespace']}:{incident['workload']}",
            ttl_seconds=900,
        )
        incident["jit_token"] = jit_token
        incident["status"] = "DELEGATED_TO_GKE_ASSIST"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": now_iso,
                "agent": "Lead Orchestrator Agent",
                "event": (
                    f"User ({approved_by}) accepted remedy. Minted 15-min JIT token "
                    f"`{jit_token['token_id'][:20]}...` and delegating task to GKE Assist Bot via A2A."
                ),
            }
        )

        # 2. Delegate execution to GKE Assist Bot via A2A protocol
        delegation_payload = {
            "incident_id": incident_id,
            "jit_token_id": jit_token["token_id"],
            "execution_mode": execution_mode,
            "kubectl_command": kubectl_cmd,
            "cluster": incident["cluster"],
            "namespace": incident["namespace"],
            "workload": incident["workload"],
            "log_entry": incident["log_entry"],
        }

        gke_resp = await self.a2a_hub.send_a2a_task(
            sender_id=self.AGENT_ID,
            recipient_id="gke-assist-agent",
            skill_id="execute_gke_remediation",
            payload=delegation_payload,
            summary=(
                f"Delegate approved fix (`{execution_mode}`) for {incident['namespace']}/{incident['workload']} "
                f"with JIT token {jit_token['token_id'][:16]}..."
            ),
        )

        incident["execution_result"] = gke_resp.result.get("execution", gke_resp.result)
        exec_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": exec_time,
                "agent": "GKE Assist Bot",
                "event": (
                    f"Executed `{kubectl_cmd}` ({execution_mode}). "
                    f"{incident['execution_result'].get('sre_specialist_notes', '')}"
                ),
            }
        )

        # 3. Trigger Closed-Loop Post-Verification with Cloud Logging Watcher Agent via A2A
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
        incident["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        incident["timeline"].append(
            {
                "timestamp": incident["updated_at"],
                "agent": "Cloud Logging Watcher Agent",
                "event": verify_resp.result.get("summary", "Telemetry verified healthy. Incident closed."),
            }
        )
        return incident

    def list_incidents(self) -> List[Dict[str, Any]]:
        return sorted(
            self.incidents.values(),
            key=lambda item: item.get("created_at", ""),
            reverse=True,
        )
