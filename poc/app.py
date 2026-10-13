"""
AgentTriad (AaaS) Cloud Run Control Plane & Multi-Agent A2A Server.

Hosts:
  1. Cloud Run Web Dashboard UI (`GET /`)
  2. REST API for live Cloud Logging monitoring, incident simulation, and HITL approval
  3. Standard A2A Protocol discovery (`GET /a2a/{agent_id}/.well-known/agent.json`)
     and JSON-RPC 2.0 task endpoints (`POST /a2a/{agent_id}`) for:
       - `log-watcher-agent` (Agent 1: Cloud Logging Watcher)
       - `lead-orchestrator-agent` (Agent 2: Lead Orchestrator / Supervisor)
       - `gke-assist-agent` (Agent 3: GKE Assist Bot)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.a2a_protocol import A2AProtocolHub, A2ATaskRequest
from agents.gke_assist_agent import GKEAssistAgent
from agents.lead_orchestrator import LeadOrchestratorAgent
from agents.watcher_agent import CloudLoggingWatcherAgent
from services.cloud_logging_service import GKE_SCENARIOS, CloudLoggingService
from services.gke_remediator import GKERemediator


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="AgentTriad (AaaS) Control Plane — ADK & A2A Multi-Agent PoC",
    version="1.0.0",
    description=(
        "Autonomous Cloud Operations Triad: Cloud Logging Watcher Agent, "
        "Lead Orchestrator Agent, and GKE Assist Bot connected via A2A Protocol."
    ),
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Initialize core services and the 3-Agent Triad on the A2A Protocol Hub
a2a_hub = A2AProtocolHub()
logging_service = CloudLoggingService()
remediator = GKERemediator()

watcher_agent = CloudLoggingWatcherAgent(a2a_hub=a2a_hub, logging_service=logging_service)
lead_orchestrator = LeadOrchestratorAgent(a2a_hub=a2a_hub)
gke_assist_bot = GKEAssistAgent(a2a_hub=a2a_hub, remediator=remediator)


class SimulateIncidentRequest(BaseModel):
    scenario_id: str = "oom_killed"
    custom_message: Optional[str] = None


class ApproveRemedyRequest(BaseModel):
    approved_by: str = "sre-lead@cognizant.com"
    execution_mode: str = "dry_run"
    custom_kubectl: Optional[str] = None


@app.get("/")
async def serve_dashboard() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI file not found")
    return FileResponse(index_file)


@app.get("/api/state")
async def get_system_state() -> Dict[str, Any]:
    """Returns real-time state of all 3 agents, Cloud Logging stream, incidents, and A2A traces."""
    return {
        "gcp_status": {
            "project_id": logging_service.project_id,
            "log_name": logging_service.log_name,
            "connected": logging_service.gcp_connected,
            "detail": logging_service.gcp_status_detail,
            "suppressed_routine_logs": logging_service.suppressed_routine_logs_count,
            "heartbeat_metric": "custom.googleapis.com/aaas/heartbeat_tick (15s PASS)",
        },
        "agents": [card.model_dump() for card in a2a_hub.agents.values()],
        "scenarios": list(GKE_SCENARIOS.values()),
        "logs": logging_service.fetch_recent_logs(limit=25, poll_gcp=False),
        "incidents": lead_orchestrator.list_incidents(),
        "a2a_ledger": a2a_hub.message_ledger[:30],
    }


@app.post("/api/simulate-incident")
async def simulate_incident(req: SimulateIncidentRequest) -> Dict[str, Any]:
    """
    1. Injects a structured GKE error log into GCP Cloud Logging (`stack-cognizant`).
    2. Cloud Logging Watcher Agent detects the log and reports it via A2A to Lead Orchestrator.
    3. Lead Orchestrator analyzes impact & remedy and alerts the user in the Dashboard.
    """
    log_entry = logging_service.inject_simulated_gke_error(
        scenario_id=req.scenario_id,
        custom_message=req.custom_message,
    )
    orchestrator_result = await watcher_agent.detect_and_report_anomaly(log_entry)
    incident_id = orchestrator_result.get("incident_id", log_entry["log_id"])
    return {
        "status": "INCIDENT_REPORTED_TO_ORCHESTRATOR",
        "incident_id": incident_id,
        "log_entry": log_entry,
        "orchestrator_result": orchestrator_result,
        "incident": lead_orchestrator.incidents.get(incident_id),
    }


@app.post("/api/poll-cloud-logging")
async def poll_cloud_logging() -> Dict[str, Any]:
    """Polls live GCP Cloud Logging for new severity>=ERROR entries and routes unseen alerts."""
    logs = logging_service.fetch_recent_logs(limit=25, poll_gcp=True)
    known_incident_ids = set(lead_orchestrator.incidents.keys())
    newly_reported = []
    for entry in logs:
        if entry.get("is_anomaly") and entry.get("log_id") not in known_incident_ids:
            res = await watcher_agent.detect_and_report_anomaly(entry)
            newly_reported.append(res.get("incident_id"))
    return {
        "status": "POLLED",
        "gcp_connected": logging_service.gcp_connected,
        "newly_reported_incidents": newly_reported,
        "total_logs": len(logs),
    }


@app.post("/api/incidents/{incident_id}/approve")
async def approve_incident_remedy(incident_id: str, req: ApproveRemedyRequest) -> Dict[str, Any]:
    """
    User accepts the Lead Orchestrator's impact & remedy proposal:
      1. Lead Orchestrator mints a 15-minute WIF JIT token.
      2. Lead Orchestrator delegates execution to GKE Assist Bot over A2A.
      3. Lead Orchestrator verifies recovery with Cloud Logging Watcher Agent over A2A.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    updated_incident = await lead_orchestrator.approve_and_delegate_to_gke_assist(
        incident_id=incident_id,
        approved_by=req.approved_by,
        execution_mode=req.execution_mode,
        custom_kubectl=req.custom_kubectl,
    )
    return {
        "status": "REMEDIATION_COMPLETED_AND_VERIFIED",
        "incident": updated_incident,
    }


# ---------------------------------------------------------------------------
# Standard A2A Protocol Endpoints (`/.well-known/agent.json` & JSON-RPC 2.0)
# ---------------------------------------------------------------------------


@app.get("/a2a/{agent_id}/.well-known/agent.json")
async def get_a2a_agent_card(agent_id: str) -> JSONResponse:
    """Standard A2A AgentCard discovery endpoint."""
    card = a2a_hub.agents.get(agent_id)
    if not card:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")
    return JSONResponse(content=card.model_dump())


@app.post("/a2a/{agent_id}")
async def handle_a2a_jsonrpc(agent_id: str, request: A2ATaskRequest) -> JSONResponse:
    """Standard A2A JSON-RPC 2.0 `tasks/send` endpoint."""
    if agent_id not in a2a_hub.handlers:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")
    sender = request.params.get("sender", "external-a2a-client")
    skill_id = request.params.get("skill_id", "unknown_skill")
    parts = request.params.get("message", {}).get("parts", [])
    payload = parts[0].get("data", {}) if parts else {}
    summary = request.params.get("metadata", {}).get("summary", f"External A2A call to {agent_id}")

    resp = await a2a_hub.send_a2a_task(
        sender_id=sender,
        recipient_id=agent_id,
        skill_id=skill_id,
        payload=payload,
        summary=summary,
    )
    return JSONResponse(content=resp.model_dump())
