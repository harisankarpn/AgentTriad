"""
Agent2Agent (A2A) Protocol Implementation & JIT Token Broker.

Implements standard A2A AgentCard discovery (`/.well-known/agent.json`),
JSON-RPC 2.0 `tasks/send` envelopes, an observable A2A message trace ledger
for the Cloud Run Dashboard, and 15-minute JIT authorization tokens.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional
from pydantic import BaseModel, Field


JIT_SECRET_KEY = os.getenv("AAAS_JIT_SECRET", "aaas-triad-jit-ephemeral-secret-2026")


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    tags: List[str] = Field(default_factory=list)
    examples: List[str] = Field(default_factory=list)


class AgentCapabilities(BaseModel):
    streaming: bool = False
    pushNotifications: bool = True
    stateTransitionHistory: bool = True


class AgentCard(BaseModel):
    """Standard A2A AgentCard exposed at /.well-known/agent.json."""

    name: str
    id: str
    role: str
    description: str
    url: str
    version: str = "1.0.0"
    protocol: str = "A2A/1.0 (JSON-RPC 2.0)"
    framework: str = "Google ADK (Vertex AI Gemini)"
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    skills: List[AgentSkill] = Field(default_factory=list)
    status: str = "ONLINE"
    last_heartbeat: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class A2ATaskRequest(BaseModel):
    """A2A JSON-RPC 2.0 `tasks/send` request envelope."""

    jsonrpc: str = "2.0"
    id: str = Field(default_factory=lambda: f"rpc-{uuid.uuid4().hex[:8]}")
    method: str = "tasks/send"
    params: Dict[str, Any]


class A2ATaskResponse(BaseModel):
    """A2A JSON-RPC 2.0 `tasks/send` response envelope."""

    jsonrpc: str = "2.0"
    id: str
    result: Dict[str, Any]


class JITTokenBroker:
    """Mints and validates 15-minute ephemeral HITL authorization tokens across Cloud Run services."""

    def __init__(self, secret: str = JIT_SECRET_KEY) -> None:
        self._secret = secret.encode("utf-8")
        self._active_tokens: Dict[str, Dict[str, Any]] = {}
        self._revoked_tokens: set[str] = set()

    def _compute_sig(self, incident_id: str, expires_epoch: int, nonce: str) -> str:
        raw_msg = f"{incident_id}:{expires_epoch}:{nonce}".encode("utf-8")
        return hmac.new(self._secret, raw_msg, hashlib.sha256).hexdigest()[:24]

    def mint_token(self, incident_id: str, approved_by: str, scope: str, ttl_seconds: int = 900) -> Dict[str, Any]:
        issued_at = datetime.datetime.now(datetime.timezone.utc)
        expires_at = issued_at + datetime.timedelta(seconds=ttl_seconds)
        expires_epoch = int(expires_at.timestamp())
        nonce = uuid.uuid4().hex[:10]
        signature = self._compute_sig(incident_id, expires_epoch, nonce)
        token_id = f"jit-wif-{expires_epoch}-{nonce}-{signature}"

        token_record = {
            "token_id": token_id,
            "incident_id": incident_id,
            "approved_by": approved_by,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_epoch": expires_epoch,
            "revoked": False,
        }
        self._active_tokens[token_id] = token_record
        return token_record

    def validate_token(self, token_id: str, incident_id: str) -> bool:
        if not token_id or token_id in self._revoked_tokens:
            return False
        parts = token_id.split("-")
        # Expected format: jit-wif-{expires_epoch}-{nonce}-{signature}
        if len(parts) != 5 or parts[0] != "jit" or parts[1] != "wif":
            return False
        try:
            expires_epoch = int(parts[2])
        except ValueError:
            return False
        nonce = parts[3]
        sig = parts[4]
        now_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if now_epoch > expires_epoch:
            return False
        expected_sig = self._compute_sig(incident_id, expires_epoch, nonce)
        return hmac.compare_digest(sig, expected_sig)

    def revoke_token(self, token_id: str) -> None:
        self._revoked_tokens.add(token_id)
        if token_id in self._active_tokens:
            self._active_tokens[token_id]["revoked"] = True
            self._active_tokens[token_id]["revoked_at"] = (
                datetime.datetime.now(datetime.timezone.utc).isoformat()
            )


class A2AProtocolHub:
    """
    Central A2A registry & message router connecting:
      1. `log-watcher-agent` (Cloud Run Service: agent-triad-watcher)
      2. `lead-orchestrator-agent` (Cloud Run Service: agent-triad-control-plane)
      3. `gke-assist-agent` (Cloud Run Service: agent-triad-gke-assist)
    """

    ENV_URL_MAP = {
        "log-watcher-agent": "WATCHER_AGENT_URL",
        "lead-orchestrator-agent": "ORCHESTRATOR_AGENT_URL",
        "gke-assist-agent": "GKE_ASSIST_AGENT_URL",
    }

    def __init__(self) -> None:
        self.agents: Dict[str, AgentCard] = {}
        self.handlers: Dict[str, Callable[[A2ATaskRequest], Coroutine[Any, Any, A2ATaskResponse]]] = {}
        self.message_ledger: List[Dict[str, Any]] = []
        self.jit_broker = JITTokenBroker()

    def get_agent_endpoint(self, agent_id: str, default_path: str) -> str:
        env_key = self.ENV_URL_MAP.get(agent_id, "")
        base_url = os.getenv(env_key, "").rstrip("/") if env_key else ""
        if base_url:
            return f"{base_url}{default_path}"
        return default_path

    def register_agent(
        self,
        card: AgentCard,
        handler: Callable[[A2ATaskRequest], Coroutine[Any, Any, A2ATaskResponse]],
    ) -> None:
        card.url = self.get_agent_endpoint(card.id, card.url)
        self.agents[card.id] = card
        self.handlers[card.id] = handler

    def update_heartbeat(self, agent_id: str, status: str = "ONLINE") -> None:
        if agent_id in self.agents:
            self.agents[agent_id].url = self.get_agent_endpoint(
                agent_id, f"/a2a/{agent_id}"
            )
            self.agents[agent_id].status = status
            self.agents[agent_id].last_heartbeat = (
                datetime.datetime.now(datetime.timezone.utc).isoformat()
            )

    async def execute_local_handler(
        self,
        agent_id: str,
        request: A2ATaskRequest,
    ) -> A2ATaskResponse:
        """Executes the local agent handler when an inbound HTTP A2A JSON-RPC request arrives."""
        if agent_id not in self.handlers:
            raise ValueError(f"Unknown A2A agent: {agent_id}")
        self.update_heartbeat(agent_id, "PROCESSING")
        response = await self.handlers[agent_id](request)
        if isinstance(response.result, dict):
            response.result["executed_by_cloud_run_service"] = os.getenv(
                "K_SERVICE", f"local-{agent_id}"
            )
        self.update_heartbeat(agent_id, "ONLINE")
        return response

    async def send_a2a_task(
        self,
        sender_id: str,
        recipient_id: str,
        skill_id: str,
        payload: Dict[str, Any],
        summary: str,
    ) -> A2ATaskResponse:
        """Dispatches a JSON-RPC 2.0 `tasks/send` call over A2A (real Cloud Run HTTPS or local handler)."""
        if recipient_id not in self.handlers:
            raise ValueError(f"Unknown A2A recipient agent: {recipient_id}")

        task_id = f"task-{uuid.uuid4().hex[:8]}"
        rpc_id = f"a2a-rpc-{uuid.uuid4().hex[:6]}"
        sent_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_endpoint = self.get_agent_endpoint(recipient_id, f"/a2a/{recipient_id}")

        request = A2ATaskRequest(
            id=rpc_id,
            method="tasks/send",
            params={
                "id": task_id,
                "sender": sender_id,
                "recipient": recipient_id,
                "skill_id": skill_id,
                "message": {
                    "role": "agent",
                    "parts": [{"type": "data", "data": payload}],
                },
                "metadata": {
                    "protocol": "A2A/1.0",
                    "timestamp": sent_at,
                    "summary": summary,
                    "endpoint": target_endpoint,
                },
            },
        )

        self.update_heartbeat(sender_id, "ACTIVE")
        self.update_heartbeat(recipient_id, "PROCESSING")

        response: Optional[A2ATaskResponse] = None
        if target_endpoint.startswith("http://") or target_endpoint.startswith("https://"):
            try:
                import httpx
                async with httpx.AsyncClient(timeout=25.0) as client:
                    http_res = await client.post(
                        target_endpoint,
                        json=request.model_dump(),
                    )
                    http_res.raise_for_status()
                    response = A2ATaskResponse(**http_res.json())
            except Exception:
                response = await self.execute_local_handler(recipient_id, request)
        else:
            response = await self.execute_local_handler(recipient_id, request)

        completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.update_heartbeat(sender_id, "ONLINE")
        self.update_heartbeat(recipient_id, "ONLINE")

        trace_entry = {
            "trace_id": rpc_id,
            "task_id": task_id,
            "timestamp": sent_at,
            "completed_at": completed_at,
            "sender_id": sender_id,
            "sender_name": self.agents[sender_id].name if sender_id in self.agents else sender_id,
            "recipient_id": recipient_id,
            "recipient_name": self.agents[recipient_id].name if recipient_id in self.agents else recipient_id,
            "skill_id": skill_id,
            "endpoint": target_endpoint,
            "summary": summary,
            "request": request.model_dump(),
            "response": response.model_dump(),
        }
        self.message_ledger.insert(0, trace_entry)
        return response

