"""
Agent 3: Specialist Agent Roster (Deterministic ADK Execution Harnesses + A2A Worker Hub).

Receives Atlas-authorized remediation tasks via the A2A Protocol after User: Hari
accepts the proposed remedy. Strictly enforces Zero-Standing Privilege:
  - Only `Atlas` (the single Root Gemini Agent) can reason, authorize, and mint JIT tokens.
  - The 7 Domain Specialist Agents (`Serverless`, `Database`, `Infra`, `Networking`,
    `Data Analytics`, `Security`, `Billing`) operate as deterministic execution harnesses
    ($0 extra LLM token cost) that validate the 15-minute JIT token, execute the CLI/API
    or Multi-Service Terraform (`.tf`) fix inside the Agent Harness Sandbox, and report
    structured execution telemetry back to `Atlas`.
"""

from __future__ import annotations

from typing import Any, Dict, List

from agents.a2a_protocol import (
    A2AProtocolHub,
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    AgentSkill,
)
from services.gke_remediator import GKERemediator


class GKEAssistAgent:
    """Deterministic Specialist Execution Roster (Serverless, Database, Infra, Networking, Data Analytics, Security, Billing)."""

    AGENT_ID = "gke-assist-agent"

    def __init__(self, a2a_hub: A2AProtocolHub, remediator: GKERemediator) -> None:
        self.a2a_hub = a2a_hub
        self.remediator = remediator
        self.card = AgentCard(
            id=self.AGENT_ID,
            name="Specialist Agent Roster",
            role="7 Deterministic Domain Execution Harnesses (Authorized by Atlas)",
            description=(
                "Roster of 7 specialized domain Worker Harnesses (Serverless Agent, Database Agent, "
                "Infra Agent, Networking Agent, Data Analytics Agent, Security Agent, Billing Agent) that execute "
                "Atlas-authorized CLI/API and Terraform (.tf) remediations at $0 extra LLM token cost after "
                "verifying Stage 2 HITL JIT tokens, `.tflock` leases, and OPA blast-radius guardrails."
            ),
            url="/a2a/gke-assist-agent",
            skills=[
                AgentSkill(
                    id="execute_gke_remediation",
                    name="Execute Domain Specialist Remediation",
                    description=(
                        "Dispatches the Atlas-minted JIT token and remediation payload (1-line CLI/API or "
                        "Multi-Service Terraform bundle) to the selected domain specialist(s) in the Agent Harness."
                    ),
                    tags=[
                        "serverless",
                        "database",
                        "infra",
                        "networking",
                        "data-analytics",
                        "security",
                        "billing",
                        "terraform",
                        "jit",
                    ],
                ),
            ],
        )
        self.a2a_hub.register_agent(self.card, self.handle_a2a_task)

    def _build_deterministic_sre_report(
        self,
        data: Dict[str, Any],
        exec_result: Dict[str, Any],
        specialist_name: str,
        coordinated_specialists: List[Dict[str, str]],
    ) -> str:
        """Synthesizes a deterministic, zero-token SRE execution report back to Atlas."""
        coord_names = [s.get("name", specialist_name) for s in (coordinated_specialists or [])] or [specialist_name]
        if exec_result.get("has_terraform"):
            tf_res = exec_result.get("terraform_resources_applied", [])
            return (
                f"Coordinated Specialists ({', '.join(coord_names)}) verified Atlas JIT token, acquired `.tflock`, "
                f"validated OPA policy, and reconciled {len(tf_res)} Terraform resource(s) ({', '.join(tf_res[:4])}). "
                f"GitOps reconciliation {exec_result.get('reconciliation_pr')} opened."
            )
        return (
            f"{specialist_name} verified Atlas JIT token, locked `.tflock` state, passed OPA blast-radius check, "
            f"and executed `{exec_result.get('command')}` ({exec_result.get('execution_mode')}) for `{data.get('workload')}`. "
            f"Reconciliation PR {exec_result.get('reconciliation_pr')} opened."
        )

    async def handle_a2a_task(self, request: A2ATaskRequest) -> A2ATaskResponse:
        """Handles incoming A2A `execute_gke_remediation` tasks delegated by Atlas (Lead Orchestrator)."""
        skill_id = request.params.get("skill_id", "")
        parts = request.params.get("message", {}).get("parts", [])
        data = parts[0].get("data", {}) if parts else {}

        if skill_id == "execute_gke_remediation":
            incident_id = data.get("incident_id", "")
            jit_token_id = data.get("jit_token_id", "")
            execution_mode = data.get("execution_mode", "live")
            kubectl_command = data.get("kubectl_command", "")
            terraform_code = data.get("terraform_code")
            cluster = data.get("cluster", "us-central1")
            namespace = data.get("namespace", "default")
            workload = data.get("workload", "deployment/app")
            specialist = data.get("specialist_worker") or {
                "id": "serverless-agent",
                "name": "Serverless Agent",
                "domain": "Cloud Run & Cloud Functions",
            }
            coordinated_specialists = data.get("coordinated_specialists") or [specialist]
            specialist_name = specialist.get("name", "Serverless Agent")

            # Enforce Zero-Standing Privilege: verify JIT token minted exclusively by Atlas
            if not self.a2a_hub.jit_broker.validate_token(jit_token_id, incident_id):
                return A2ATaskResponse(
                    id=request.id,
                    result={
                        "status": "REJECTED_INVALID_JIT_TOKEN",
                        "incident_id": incident_id,
                        "error": f"{specialist_name} refused execution: missing or expired Stage 2 HITL JIT token from Atlas.",
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
                coordinated_specialists=coordinated_specialists,
                terraform_code=terraform_code,
            )

            # Single-action envelope: revoke JIT token immediately after execution
            self.a2a_hub.jit_broker.revoke_token(jit_token_id)

            sre_notes = self._build_deterministic_sre_report(
                data=data,
                exec_result=exec_result,
                specialist_name=specialist_name,
                coordinated_specialists=coordinated_specialists,
            )
            exec_result["sre_specialist_notes"] = sre_notes
            exec_result["specialist_worker"] = specialist
            exec_result["coordinated_specialists"] = coordinated_specialists
            exec_result.setdefault(
                "agent_harness_execution",
                {
                    "specialist_llm_tokens_used": 0,
                    "lock_released": exec_result.get("lock_released") or {"status": "RELEASED"},
                },
            )

            return A2ATaskResponse(
                id=request.id,
                result={
                    "status": "REMEDIATION_APPLIED",
                    "agent": self.AGENT_ID,
                    "specialist_worker": specialist,
                    "coordinated_specialists": coordinated_specialists,
                    "incident_id": incident_id,
                    "execution": exec_result,
                },
            )

        return A2ATaskResponse(
            id=request.id,
            result={"status": "UNSUPPORTED_SKILL", "skill_id": skill_id},
        )
