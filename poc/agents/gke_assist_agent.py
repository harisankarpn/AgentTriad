"""
Agent 3: GKE Assist Bot (ADK + A2A Specialist Agent).

Receives delegated remediation tasks from the Lead Orchestrator Agent via the
A2A Protocol after the human operator accepts the proposed remedy. Validates the
15-minute JIT authorization token, executes the GKE remediation via the Agent
Harness (`GKERemediator`), and reports the result back over A2A.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from agents.a2a_protocol import (
    A2AProtocolHub,
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    AgentSkill,
)
from services.gke_remediator import GKERemediator

try:
    from google.adk.agents import Agent as AdkAgent
except ImportError:
    AdkAgent = None

try:
    from google import genai
except ImportError:
    genai = None


PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
LOCATION = os.getenv("GCP_LOCATION", "us-central1")
MODEL_NAME = os.getenv("AAAS_GEMINI_MODEL", "gemini-2.5-flash")


class GKEAssistAgent:
    """ADK Specialist Hub for the Boutique of Worker Agents (Serverless, Database, Infra, Networking, Data Analytics)."""

    AGENT_ID = "gke-assist-agent"

    def __init__(self, a2a_hub: A2AProtocolHub, remediator: GKERemediator) -> None:
        self.a2a_hub = a2a_hub
        self.remediator = remediator
        self.adk_agent = self._build_adk_agent()
        self._genai_client = self._build_genai_client()
        self.card = AgentCard(
            id=self.AGENT_ID,
            name="Worker Agent Boutique",
            role="Domain Remediation Specialists (Serverless, Database, Infra, Networking, Data Analytics)",
            description=(
                "Boutique of specialized domain Worker Agents (Serverless Agent, Database Agent, "
                "Infra Agent, Networking Agent, Data Analytics Agent) that execute Atlas-delegated "
                "remediations after verifying Stage 2 HITL JIT tokens and blast-radius guardrails."
            ),
            url="/a2a/gke-assist-agent",
            skills=[
                AgentSkill(
                    id="execute_gke_remediation",
                    name="Execute Domain Specialist Remediation",
                    description=(
                        "Dispatches the approved JIT token and remediation payload to the selected "
                        "domain specialist (Serverless, Database, Infra, Networking, or Data Analytics Agent)."
                    ),
                    tags=["serverless", "database", "infra", "networking", "data-analytics", "jit"],
                ),
            ],
        )
        self.a2a_hub.register_agent(self.card, self.handle_a2a_task)

    def _build_adk_agent(self) -> Any:
        if AdkAgent is None:
            return None
        try:
            return AdkAgent(
                name="worker_agent_boutique",
                model=MODEL_NAME,
                description="Boutique of specialist Worker Agents (Serverless, Database, Infra, Networking, Data Analytics).",
                instruction=(
                    "You are the Domain Specialist Worker Agent in the AaaS Control Plane. "
                    "When Atlas (Lead Orchestrator) delegates an approved incident task to you over A2A, "
                    "verify the JIT token, validate the command against blast-radius guardrails, "
                    "execute the remediation for your domain, and return a clear SRE execution summary."
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

    def _generate_sre_execution_notes(
        self, incident: Dict[str, Any], exec_result: Dict[str, Any], specialist_name: str
    ) -> str:
        """Uses Vertex AI Gemini to synthesize a concise post-execution SRE note (with deterministic fallback)."""
        if self._genai_client is not None:
            try:
                prompt = (
                    f"You are the {specialist_name} in the Google Cloud AaaS Worker Agent Boutique. "
                    "Summarize in 2 concise sentences what remediation you just executed for this incident "
                    "and why it resolves the root cause.\n"
                    f"Incident: {json.dumps(incident.get('log_entry', {}), default=str)}\n"
                    f"Command Executed: {exec_result.get('command')}\n"
                    f"Mode: {exec_result.get('execution_mode')}"
                )
                resp = self._genai_client.models.generate_content(
                    model=MODEL_NAME,
                    contents=prompt,
                )
                if resp and resp.text:
                    return resp.text.strip()
            except Exception:
                pass

        return (
            f"{specialist_name} validated JIT token and executed `{exec_result.get('command')}` "
            f"in `{exec_result.get('execution_mode')}` mode for `{incident.get('workload')}`. "
            f"Reconciliation PR {exec_result.get('reconciliation_pr')} opened to keep GitOps state synchronized."
        )

    async def handle_a2a_task(self, request: A2ATaskRequest) -> A2ATaskResponse:
        """Handles incoming A2A `execute_gke_remediation` tasks from Atlas (Lead Orchestrator)."""
        skill_id = request.params.get("skill_id", "")
        parts = request.params.get("message", {}).get("parts", [])
        data = parts[0].get("data", {}) if parts else {}

        if skill_id == "execute_gke_remediation":
            incident_id = data.get("incident_id", "")
            jit_token_id = data.get("jit_token_id", "")
            execution_mode = data.get("execution_mode", "live")
            kubectl_command = data.get("kubectl_command", "")
            cluster = data.get("cluster", "us-central1")
            namespace = data.get("namespace", "default")
            workload = data.get("workload", "deployment/app")
            specialist = data.get("specialist_worker") or {
                "id": "serverless-agent",
                "name": "Serverless Agent",
                "domain": "Cloud Run & Cloud Functions",
            }
            specialist_name = specialist.get("name", "Serverless Agent")

            # Enforce Zero-Standing Privilege: verify JIT token minted by Lead Orchestrator
            if not self.a2a_hub.jit_broker.validate_token(jit_token_id, incident_id):
                return A2ATaskResponse(
                    id=request.id,
                    result={
                        "status": "REJECTED_INVALID_JIT_TOKEN",
                        "incident_id": incident_id,
                        "error": f"{specialist_name} refused execution: missing or expired Stage 2 HITL JIT token.",
                    },
                )

            exec_result = self.remediator.execute_remediation(
                incident_id=incident_id,
                cluster=cluster,
                namespace=namespace,
                workload=workload,
                kubectl_command=kubectl_command,
                execution_mode=execution_mode,
                jit_token_id=jit_token_id,
                specialist_worker=specialist,
            )

            # Single-action envelope: revoke JIT token immediately after execution
            self.a2a_hub.jit_broker.revoke_token(jit_token_id)

            sre_notes = self._generate_sre_execution_notes(data, exec_result, specialist_name)
            exec_result["sre_specialist_notes"] = sre_notes
            exec_result["specialist_worker"] = specialist

            return A2ATaskResponse(
                id=request.id,
                result={
                    "status": "REMEDIATION_APPLIED",
                    "agent": self.AGENT_ID,
                    "specialist_worker": specialist,
                    "incident_id": incident_id,
                    "execution": exec_result,
                },
            )

        return A2ATaskResponse(
            id=request.id,
            result={"status": "UNSUPPORTED_SKILL", "skill_id": skill_id},
        )
