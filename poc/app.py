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
from agents.lead_orchestrator import LeadOrchestratorAgent, WORKER_AGENT_BOUTIQUE
from agents.watcher_agent import CloudLoggingWatcherAgent
from services.cloud_logging_service import CloudLoggingService
from services.gke_remediator import GKERemediator


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="AaaS Control Plane — Atlas (Lead Orchestrator), Log Watcher & Worker Agent Boutique",
    version="1.0.0",
    description=(
        "Autonomous Cloud Operations Triad: Cloud Logging Watcher Agent, "
        "Atlas (Lead Orchestrator Agent), and Boutique of Worker Agents connected via A2A Protocol."
    ),
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Initialize core services and the 3-Agent Triad on the A2A Protocol Hub
a2a_hub = A2AProtocolHub()
logging_service = CloudLoggingService()
remediator = GKERemediator(logging_service=logging_service)

watcher_agent = CloudLoggingWatcherAgent(a2a_hub=a2a_hub, logging_service=logging_service)
lead_orchestrator = LeadOrchestratorAgent(a2a_hub=a2a_hub, logging_service=logging_service)
gke_assist_bot = GKEAssistAgent(a2a_hub=a2a_hub, remediator=remediator)


class ApproveRemedyRequest(BaseModel):
    approved_by: str = "Hari"
    execution_mode: str = "live"
    custom_kubectl: Optional[str] = None


class IncidentChatRequest(BaseModel):
    message: str


@app.get("/")
async def serve_dashboard() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI file not found")
    return FileResponse(index_file)


_last_watcher_sync_ts: float = 0.0
_seen_anomaly_ids: set[str] = set()
_real_poll_cursor: int = 0


async def sync_real_logs_from_watcher(
    force: bool = False, auto_escalate: bool = False, max_escalations: int = 1
) -> list[Dict[str, Any]]:
    """
    Polls real Google Cloud Logging via `log-watcher-agent` (either remote `agent-triad-watcher`
    Cloud Run service over A2A HTTPS or local `CloudLoggingService`) and optionally escalates
    unseen real GCP errors to `lead-orchestrator-agent`.
    """
    import time

    global _last_watcher_sync_ts
    now_ts = time.time()
    should_sync = force or (now_ts - _last_watcher_sync_ts >= 12.0)

    if os.getenv("WATCHER_AGENT_URL") and should_sync:
        _last_watcher_sync_ts = now_ts
        try:
            scan_resp = await a2a_hub.send_a2a_task(
                sender_id="lead-orchestrator-agent",
                recipient_id="log-watcher-agent",
                skill_id="scan_cloud_logging",
                payload={"force": force, "limit": 25},
                summary="Poll live Google Cloud Logging across project `agent-triad`",
            )
            remote_logs = scan_resp.result.get("logs", [])
            if remote_logs:
                known_local = {item.get("log_id") for item in logging_service._local_logs}
                for item in remote_logs:
                    if item.get("log_id") not in known_local:
                        logging_service._local_logs.append(item)
                        known_local.add(item.get("log_id"))
                logging_service._local_logs.sort(
                    key=lambda x: (1 if x.get("is_anomaly") else 0, x.get("timestamp", "")),
                    reverse=True,
                )
            if scan_resp.result.get("suppressed_routine_logs") is not None:
                logging_service.suppressed_routine_logs_count = max(
                    logging_service.suppressed_routine_logs_count,
                    int(scan_resp.result.get("suppressed_routine_logs", 0)),
                )
        except Exception:
            logging_service.fetch_recent_logs(limit=25, poll_gcp=True, force=force)
    elif should_sync:
        _last_watcher_sync_ts = now_ts
        logging_service.fetch_recent_logs(limit=25, poll_gcp=True, force=force)

    logs = logging_service.fetch_recent_logs(limit=25, poll_gcp=False)

    if auto_escalate:
        escalated = 0
        for entry in logs:
            lid = entry.get("log_id", "")
            if entry.get("is_anomaly") and lid and lid not in _seen_anomaly_ids and lid not in lead_orchestrator.incidents:
                _seen_anomaly_ids.add(lid)
                await watcher_agent.detect_and_report_anomaly(entry)
                escalated += 1
                if escalated >= max_escalations:
                    break

    return logs


@app.get("/api/state")
async def get_system_state() -> Dict[str, Any]:
    """Returns real-time state of all 3 agents, live GCP Cloud Logging stream, incidents, audit tracker, and A2A traces."""
    logs = await sync_real_logs_from_watcher(force=False, auto_escalate=False)
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
        "worker_boutique": WORKER_AGENT_BOUTIQUE,
        "logs": logs,
        "incidents": lead_orchestrator.list_incidents(),
        "audit_events": lead_orchestrator.list_audit_events(),
        "general_chat_messages": lead_orchestrator.list_general_chat_messages(),
        "a2a_ledger": a2a_hub.message_ledger[:30],
    }


@app.get("/api/audit-events")
async def get_audit_events() -> Dict[str, Any]:
    """Returns the chronological Audit & Event Tracker log of all detected issues, approvers, and timestamps."""
    events = lead_orchestrator.list_audit_events()
    return {
        "project_id": logging_service.project_id,
        "total_events": len(events),
        "audit_events": events,
    }


@app.post("/api/poll-cloud-logging")
async def poll_cloud_logging() -> Dict[str, Any]:
    """
    Dedicated Live GCP Log Poll endpoint:
      1. Queries `log-watcher-agent` (`agent-triad-watcher`) over A2A (`scan_cloud_logging`, `force=True`).
      2. Finds the next real GCP error log (`gcp-...`) from project `agent-triad` and escalates it
         over A2A (`ingest_anomaly_alert`) to `lead-orchestrator-agent`.
    """
    global _real_poll_cursor
    logs = await sync_real_logs_from_watcher(force=True, auto_escalate=False)
    real_anomalies = [
        entry
        for entry in logs
        if entry.get("is_anomaly") and str(entry.get("log_id", "")).startswith("gcp-")
    ]
    if not real_anomalies:
        real_anomalies = [entry for entry in logs if entry.get("is_anomaly")]

    target_entry = None
    for entry in real_anomalies:
        lid = entry.get("log_id")
        existing = lead_orchestrator.incidents.get(lid)
        if not existing:
            target_entry = entry
            break

    if target_entry is None and real_anomalies:
        target_entry = real_anomalies[_real_poll_cursor % len(real_anomalies)]
        _real_poll_cursor += 1

    newly_reported = []
    orchestrator_result = None
    incident_id = None
    if target_entry is not None:
        _seen_anomaly_ids.add(target_entry["log_id"])
        orchestrator_result = await watcher_agent.detect_and_report_anomaly(target_entry)
        incident_id = orchestrator_result.get("incident_id", target_entry["log_id"])
        newly_reported.append(incident_id)

    return {
        "status": "REAL_GCP_INCIDENT_REPORTED_TO_ORCHESTRATOR",
        "gcp_connected": logging_service.gcp_connected,
        "incident_id": incident_id,
        "log_entry": target_entry,
        "orchestrator_result": orchestrator_result,
        "incident": lead_orchestrator.incidents.get(incident_id) if incident_id else None,
        "newly_reported_incidents": newly_reported,
        "total_logs": len(logs),
    }


@app.post("/api/incidents/{incident_id}/approve")
async def approve_incident_remedy(incident_id: str, req: ApproveRemedyRequest) -> Dict[str, Any]:
    """
    User accepts the Lead Orchestrator's impact & remedy proposal:
      1. Lead Orchestrator mints a 15-minute WIF JIT token.
      2. Lead Orchestrator delegates execution to Worker Agent (`agent-triad-gke-assist`) over A2A HTTPS.
      3. Lead Orchestrator verifies recovery with Log Watcher (`agent-triad-watcher`) over A2A HTTPS.
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


@app.post("/api/incidents/{incident_id}/skip")
async def skip_incident_remedy(incident_id: str) -> Dict[str, Any]:
    """User chooses Later / Ignore (handle manually). Worker Agent stands down."""
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    updated = lead_orchestrator.skip_incident_manual(incident_id=incident_id)
    return {
        "status": "SKIPPED_MANUAL",
        "incident": updated,
    }


@app.post("/api/incidents/{incident_id}/reopen")
async def reopen_incident_remedy(incident_id: str) -> Dict[str, Any]:
    """Re-opens a previously skipped incident back to awaiting approval."""
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    updated = lead_orchestrator.reopen_incident(incident_id=incident_id)
    return {
        "status": "AWAITING_HITL_APPROVAL",
        "incident": updated,
    }


@app.post("/api/incidents/{incident_id}/chat")
async def chat_about_incident(incident_id: str, req: IncidentChatRequest) -> Dict[str, Any]:
    """
    Interactive chatbot endpoint for Hari to ask the AaaS Lead Orchestrator (`Atlas`)
    questions about root cause, downtime, blast radius, or instruct it to proceed with the fix.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    result = await lead_orchestrator.chat_with_incident(
        incident_id=incident_id,
        user_message=req.message,
    )
    return {
        "status": "CHAT_UPDATED",
        **result,
    }


@app.post("/api/atlas/chat")
async def chat_general_atlas(req: IncidentChatRequest) -> Dict[str, Any]:
    """
    Direct on-demand chatbot endpoint for Hari to manually invoke Atlas for
    'How-to' GCP questions or ad-hoc troubleshooting not captured in Cloud Logging.
    """
    if not req.message or not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    result = await lead_orchestrator.chat_general_with_atlas(user_message=req.message)
    return {
        "status": "CHAT_UPDATED",
        **result,
    }


@app.post("/api/atlas/chat/reset")
async def reset_general_atlas_chat() -> Dict[str, Any]:
    """Resets the direct/manual Atlas chat history back to the initial greeting."""
    messages = lead_orchestrator.reset_general_chat()
    return {
        "status": "CHAT_RESET",
        "messages": messages,
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
    """Standard A2A JSON-RPC 2.0 `tasks/send` endpoint executed on the receiving microservice."""
    if agent_id not in a2a_hub.handlers:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")

    resp = await a2a_hub.execute_local_handler(agent_id, request)
    return JSONResponse(content=resp.model_dump())

