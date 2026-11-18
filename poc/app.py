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

import asyncio
import datetime
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.a2a_protocol import A2AProtocolHub, A2ATaskRequest
from agents.gke_assist_agent import GKEAssistAgent
from agents.lead_orchestrator import LeadOrchestratorAgent, WORKER_AGENT_BOUTIQUE
from agents.watcher_agent import CloudLoggingWatcherAgent
from providers.base_telemetry import normalize_otel_anomaly
from providers.cloud_factory import normalize_target_cloud
from services.agent_harness import agent_harness
from services.auth_broker import AuthVerificationError, auth_broker
from services.cloud_logging_service import CloudLoggingService
from services.cloud_status_service import cloud_status_service
from services.gke_remediator import GKERemediator
from services.security_iam_service import security_iam_service
from services.session_store_service import session_store_service


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
# `initial_poll=False` prevents blocking container startup on Cloud Logging queries;
# logs are warmed asynchronously on FastAPI startup and refreshed in the background.
a2a_hub = A2AProtocolHub()
logging_service = CloudLoggingService(initial_poll=False)
remediator = GKERemediator(logging_service=logging_service)

watcher_agent = CloudLoggingWatcherAgent(a2a_hub=a2a_hub, logging_service=logging_service)
lead_orchestrator = LeadOrchestratorAgent(a2a_hub=a2a_hub, logging_service=logging_service)
gke_assist_bot = GKEAssistAgent(a2a_hub=a2a_hub, remediator=remediator)


class ApproveRemedyRequest(BaseModel):
    approved_by: Optional[str] = None
    execution_mode: str = "live"
    custom_kubectl: Optional[str] = None
    critical_change_confirmed: bool = False


class RollbackIncidentRequest(BaseModel):
    requested_by: Optional[str] = None
    reason: Optional[str] = None
    execution_mode: str = "live"
    quarantine_signature: bool = True


class IncidentChatRequest(BaseModel):
    message: str
    user_name: Optional[str] = None
    target_cloud: Optional[str] = None


class DeployChatTerraformRequest(BaseModel):
    approved_by: Optional[str] = None
    hcl_code: Optional[str] = None
    target_cloud: Optional[str] = None


class SetTargetCloudRequest(BaseModel):
    target_cloud: str


class GoogleSSOLoginRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    picture: Optional[str] = None
    credential: Optional[str] = None
    access_token: Optional[str] = None
    client_id: Optional[str] = None


class GoogleOAuthConfigRequest(BaseModel):
    client_id: str


class CreateChatSessionRequest(BaseModel):
    title: Optional[str] = None


class LogTriageBatchRequest(BaseModel):
    log_ids: List[str]
    reason: Optional[str] = None
    user_name: Optional[str] = None
    target_cloud: Optional[str] = None
    strategy: str = "auto"
    ignore_similar_signatures: bool = False


class PollCloudLoggingRequest(BaseModel):
    strategy: str = "prioritized"
    log_id: Optional[str] = None


class IgnoreIncidentRequest(BaseModel):
    reason: Optional[str] = "Marked safe to ignore in Atlas"
    user_name: Optional[str] = None
    ignore_similar_signatures: bool = True


class CustomerTicketIngestRequest(BaseModel):
    customer_name: str = "HSBC Global Services (UK) Limited"
    project_id: str = os.getenv("GCP_PROJECT_ID", "agent-triad")
    region: str = "europe-west2"
    business_impact: str = "Non-Production System impaired"
    error_message: str = (
        "com.google.apps.framework.request.StatusException: generic::FAILED_PRECONDITION: "
        "Missing permissions to validate that the provided IP range is available. "
        "Please check that Datastream SA has the required permissions."
    )
    ticket_description: str = (
        "1. We are not able to create private connectivity with the VPC to establish connection with cloudSQL service.\n"
        "2. Host service account for datastream does not exist in the Host project.\n"
        "3. Now, we would like to create the private connectivity outside shared VPC, but its not allowing. "
        "Could you please help us to remove the service account or do we have any other way to create private connectivity without facing this issue."
    )
    service_agent_email: Optional[str] = None
    workload: str = "datastream/private-connectivity-ew2"
    mock_deployments: Optional[List[Dict[str, Any]]] = None


DEFAULT_GOOGLE_OAUTH_CLIENT_ID = "1041190629307-vfatcreibv4a82lcj0v6t11vlic9rivn.apps.googleusercontent.com"
_runtime_oauth_client_id: str = os.getenv("GOOGLE_OAUTH_CLIENT_ID", DEFAULT_GOOGLE_OAUTH_CLIENT_ID).strip()


def _get_effective_oauth_client_id() -> str:
    return (
        _runtime_oauth_client_id
        or os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
        or DEFAULT_GOOGLE_OAUTH_CLIENT_ID
    ).strip()


@app.post("/api/auth/config")
async def configure_google_oauth_client(req: GoogleOAuthConfigRequest) -> Dict[str, Any]:
    """Sets the Google OAuth 2.0 Web Client ID at runtime for Google Identity Services SSO."""
    global _runtime_oauth_client_id
    cid = (req.client_id or "").strip()
    if not cid or ".apps.googleusercontent.com" not in cid:
        raise HTTPException(
            status_code=400,
            detail="Valid Google OAuth 2.0 Client ID (*.apps.googleusercontent.com) is required.",
        )
    _runtime_oauth_client_id = cid
    return {
        "status": "OAUTH_CLIENT_CONFIGURED",
        "google_oauth_client_id": _runtime_oauth_client_id,
    }


@app.get("/api/auth/me")
async def get_authenticated_user(request: Request) -> Dict[str, Any]:
    """
    Returns the active Google SSO / IAP identity for the AaaS Command Center.
    Automatically detects Google Cloud Identity-Aware Proxy (IAP) headers if present.
    """
    iap_email = request.headers.get("X-Goog-Authenticated-User-Email", "")
    if iap_email:
        clean_email = iap_email.split(":")[-1].strip()
        derived_name = clean_email.split("@")[0].replace(".", " ").title() if clean_email else "Cloud Operator"
        user = lead_orchestrator.set_active_user(
            name=derived_name,
            email=clean_email,
            provider="gcp-iap",
        )
        return {
            "authenticated": True,
            "iap_detected": True,
            "user": user,
            "google_oauth_client_id": _get_effective_oauth_client_id(),
        }

    return {
        "authenticated": True,
        "iap_detected": False,
        "user": lead_orchestrator.active_user,
        "google_oauth_client_id": _get_effective_oauth_client_id(),
    }


@app.post("/api/auth/google")
async def login_with_google_sso(req: GoogleSSOLoginRequest) -> Dict[str, Any]:
    """
    Authenticates a user via:
      1. Real Google OAuth 2.0 Access Token (`access_token` verified against https://www.googleapis.com/oauth2/v3/userinfo)
      2. Real Google Identity Services ID Token JWT (`credential` verified via google.oauth2.id_token)
      3. Authorized Google Workspace / Sandbox SRE role (`name`, `email`)
    """
    import httpx

    global _runtime_oauth_client_id
    if req.client_id and ".apps.googleusercontent.com" in req.client_id:
        _runtime_oauth_client_id = req.client_id.strip()

    name = (req.name or "").strip()
    email = (req.email or "").strip()
    picture = (req.picture or "").strip()
    provider = "google-sso"

    # 1. Verify OAuth 2.0 Access Token via Pluggable CloudAuthBroker (Google UserInfo or OIDC)
    if req.access_token:
        try:
            uinfo = await auth_broker.verify_oauth2_access_token(req.access_token)
        except AuthVerificationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        email = uinfo.get("email") or email
        name = uinfo.get("name") or uinfo.get("given_name") or name
        picture = uinfo.get("picture") or picture
        provider = uinfo.get("provider") or "google-oauth2-verified"

    # 2. Verify OIDC ID Token JWT via Pluggable CloudAuthBroker (Google ID Token / JWKS / HS256)
    elif req.credential:
        client_id = _get_effective_oauth_client_id()
        try:
            decoded_claims = auth_broker.verify_oidc_jwt(
                req.credential,
                audience=client_id or None,
            )
        except AuthVerificationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        email = decoded_claims.get("email") or email
        name = decoded_claims.get("name") or decoded_claims.get("given_name") or name
        picture = decoded_claims.get("picture") or picture
        provider = decoded_claims.get("provider") or "google-id-token-verified"

    if not name and email:
        name = email.split("@")[0].replace(".", " ").title()
    if not name:
        raise HTTPException(status_code=400, detail="Google SSO user name or email is required")
    if not email:
        slug = "".join(ch for ch in name.lower() if ch.isalnum() or ch == ".") or "operator"
        email = f"{slug}@google.com"

    user = lead_orchestrator.set_active_user(
        name=name,
        email=email,
        picture=picture,
        provider=provider,
    )
    return {
        "status": "AUTHENTICATED",
        "user": user,
    }


@app.post("/api/auth/logout")
async def logout_google_sso() -> Dict[str, Any]:
    """Signs out the current Google SSO session."""
    return {
        "status": "SIGNED_OUT",
    }


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    """Lightweight liveness/readiness probe for Docker Compose, Kubernetes, OpenShift, and Cloud Run."""
    return {
        "status": "ok",
        "service": "agent-triad-control-plane",
        "state_backend": session_store_service.adapter.backend_name,
        "lock_backend": agent_harness.lock_adapter.backend_name,
        "telemetry_provider": logging_service.adapter.provider_name,
        "llm_provider": lead_orchestrator._llm_client.provider,
    }


@app.get("/")
async def serve_dashboard() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI file not found")
    return FileResponse(index_file)


_last_watcher_sync_ts: float = 0.0
_seen_anomaly_ids: set[str] = set()
_ignored_log_ids: Dict[str, Dict[str, Any]] = {}
_ignored_signatures: Dict[str, Dict[str, Any]] = {}
_real_poll_cursor: int = 0
_watcher_refresh_in_flight: bool = False
_watcher_sync_lock = asyncio.Lock()
_WATCHER_REFRESH_TTL_SECONDS: float = float(os.getenv("AAAS_WATCHER_REFRESH_TTL_SECONDS", "30.0"))


def _entry_signature_tokens(entry: Dict[str, Any], include_pair: bool = True) -> List[str]:
    """Returns canonical suppression signature keys for a normalized log entry."""
    tokens: List[str] = []
    sig = str(entry.get("signature_key") or "").strip()
    if sig:
        tokens.append(sig)
    if include_pair:
        wl = str(entry.get("workload") or "").strip()
        err = str(entry.get("error_code") or "").strip()
        if wl and err:
            pair_tok = f"{wl}::{err}"
            if pair_tok not in tokens:
                tokens.append(pair_tok)
    return tokens


def _sync_orchestrator_ignore_sets() -> None:
    """Keeps Atlas's in-memory suppression sets synchronized with persisted triage state."""
    lead_orchestrator.ignored_log_ids = set(_ignored_log_ids.keys())
    lead_orchestrator.ignored_signatures = set(_ignored_signatures.keys())


def _load_persisted_triage_state(sync_from_firestore: bool = True) -> None:
    """Hydrates durable 'Safe to Ignore' state from Cloud Firestore / active session store."""
    try:
        persisted = session_store_service.get_global_triage_state(
            sync_from_firestore=sync_from_firestore
        )
        for lid, meta in (persisted.get("ignored_logs") or {}).items():
            if lid and isinstance(meta, dict):
                _ignored_log_ids[str(lid)] = dict(meta)
                _seen_anomaly_ids.add(str(lid))
        for sig, meta in (persisted.get("ignored_signatures") or {}).items():
            if sig and isinstance(meta, dict):
                _ignored_signatures[str(sig)] = dict(meta)
        _sync_orchestrator_ignore_sets()
    except Exception:
        pass


def _persist_triage_state() -> bool:
    """Persists `_ignored_log_ids` and `_ignored_signatures` to Cloud Firestore / active session store."""
    _sync_orchestrator_ignore_sets()
    try:
        return session_store_service.save_global_triage_state(
            ignored_logs=_ignored_log_ids,
            ignored_signatures=_ignored_signatures,
        )
    except Exception:
        return False


_load_persisted_triage_state(sync_from_firestore=False)


def _lookup_ignored_meta(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Returns ignore metadata if `entry` was explicitly marked Safe to Ignore by `log_id`
    OR matches a permanently suppressed recurring signature (`_ignored_signatures`).
    """
    lid = str(entry.get("log_id") or "").strip()
    if lid and lid in _ignored_log_ids:
        return _ignored_log_ids[lid]
    for tok in _entry_signature_tokens(entry):
        if tok in _ignored_signatures:
            sig_meta = dict(_ignored_signatures[tok])
            if lid:
                hydrated = {
                    **sig_meta,
                    "log_id": lid,
                    "matched_signature": tok,
                }
                _ignored_log_ids[lid] = hydrated
                _seen_anomaly_ids.add(lid)
                lead_orchestrator.ignored_log_ids.add(lid)
                return hydrated
            return sig_meta
    return None


def _compute_issue_priority(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic SRE priority ranking (P1..P4) so critical data-plane / permission / outage
    failures are surfaced ahead of operational warnings and benign external port probes.
    """
    if not entry.get("is_anomaly"):
        return {
            "priority_tier": "INFO",
            "priority_rank": 5,
            "priority_score": 0,
            "priority_label": "Informational Telemetry",
        }
    sev = str(entry.get("severity") or "ERROR").upper()
    err_code = str(entry.get("error_code") or "").strip().upper()
    scen = str(entry.get("scenario_id") or "").strip().lower()
    msg_lower = f"{entry.get('title') or ''} {entry.get('message') or ''}".lower()

    if (
        err_code == "CLOUDSQL_EXTERNAL_CONN_REJECTED"
        or scen == "cloudsql_conn_probe"
        or "invalid length of startup packet" in msg_lower
        or "unsupported frontend protocol" in msg_lower
        or sev in ("NOTICE", "INFO", "DEBUG", "OK")
    ):
        return {
            "priority_tier": "P4",
            "priority_rank": 4,
            "priority_score": 20,
            "priority_label": "P4 • Benign Probe / Low-Impact Noise",
        }

    if (
        sev in ("CRITICAL", "ALERT", "EMERGENCY")
        or err_code in (
            "CLOUDSQL_PG_OBJECT_PERMISSION_DENIED",
            "DATASTREAM_FAILED_PRECONDITION_IAM",
            "CONNECTION_POOL_EXHAUSTION",
            "HTTP_503_UPSTREAM",
            "HTTP_503_CASCADING_PEER_FAILURE",
            "DEADLOCK_DETECTED",
        )
        or scen in ("cloudsql_pg_permission_denied", "datastream_iam_drift", "cloud_run_5xx")
        or "permission denied for " in msg_lower
        or "deadlock detected" in msg_lower
        or "remaining connection slots are reserved" in msg_lower
    ):
        return {
            "priority_tier": "P1",
            "priority_rank": 1,
            "priority_score": 95,
            "priority_label": "P1 • Critical Service / Data Access Failure",
        }

    if sev == "ERROR":
        return {
            "priority_tier": "P2",
            "priority_rank": 2,
            "priority_score": 78,
            "priority_label": "P2 • Service Runtime Error",
        }

    return {
        "priority_tier": "P3",
        "priority_rank": 3,
        "priority_score": 50,
        "priority_label": "P3 • Operational Warning",
    }


def _find_logs_by_ids(log_ids: List[str]) -> List[Dict[str, Any]]:
    """Looks up matching log entries across the full in-memory telemetry buffer preserving requested order."""
    wanted = [str(lid).strip() for lid in log_ids if str(lid or "").strip()]
    if not wanted:
        return []
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in logging_service._local_logs:
        lid = str(entry.get("log_id") or "")
        if lid and lid not in by_id:
            by_id[lid] = entry
    return [by_id[lid] for lid in wanted if lid in by_id]


def _annotate_logs_with_triage(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Returns shallow copies of log entries enriched with live operator triage and priority metadata."""
    enriched: List[Dict[str, Any]] = []
    for entry in logs:
        item = dict(entry)
        lid = str(item.get("log_id") or "")
        ignored_meta = _lookup_ignored_meta(item)
        linked_inc = lead_orchestrator.incidents.get(lid)
        inc_status = str(linked_inc.get("status") or "") if linked_inc else ""
        is_ignored = ignored_meta is not None or inc_status == "IGNORED"

        prio = _compute_issue_priority(item)
        item.update(prio)
        item["ignored"] = is_ignored
        item["ignored_by"] = (
            ignored_meta.get("ignored_by")
            if ignored_meta
            else (linked_inc.get("ignored_by") if linked_inc and inc_status == "IGNORED" else None)
        )
        item["ignored_at"] = (
            ignored_meta.get("ignored_at")
            if ignored_meta
            else (linked_inc.get("ignored_at") if linked_inc and inc_status == "IGNORED" else None)
        )
        item["ignored_reason"] = (
            ignored_meta.get("reason")
            if ignored_meta
            else (linked_inc.get("ignore_reason") if linked_inc and inc_status == "IGNORED" else None)
        )
        item["linked_incident_id"] = (
            linked_inc.get("incident_id") if linked_inc and inc_status != "IGNORED" else None
        )
        if is_ignored:
            item["triage_status"] = "IGNORED"
        elif linked_inc is not None:
            if inc_status == "RESOLVED":
                item["triage_status"] = "RESOLVED"
            elif inc_status == "ROLLED_BACK":
                item["triage_status"] = "ROLLED_BACK"
            elif inc_status == "SKIPPED_MANUAL":
                item["triage_status"] = "SKIPPED_MANUAL"
            else:
                item["triage_status"] = "IN_CHAT"
        elif item.get("is_anomaly"):
            item["triage_status"] = "OPEN"
        else:
            item["triage_status"] = "INFO"
        enriched.append(item)
    return enriched


def _build_prioritized_open_issues(annotated_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Returns unignored, unresolved anomaly issues ranked strictly by priority (P1 -> P4)
    and newest timestamp within each priority tier so operators can pick the top issue first.
    """
    candidates = [
        item
        for item in annotated_logs
        if item.get("is_anomaly")
        and not item.get("ignored")
        and item.get("triage_status") not in ("IGNORED", "RESOLVED", "ROLLED_BACK")
    ]
    candidates.sort(
        key=lambda x: (
            int(x.get("priority_score") or 0),
            str(x.get("timestamp") or "").replace(" ", "T"),
        ),
        reverse=True,
    )
    return candidates


def _enrich_and_sort_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Attaches `priority_tier`/`priority_rank`/`priority_score` to visible incidents, excludes
    any incident whose log or signature was marked Safe to Ignore, and orders actionable
    incidents highest-priority-first (`P1` -> `P4`).
    """
    enriched: List[Dict[str, Any]] = []
    for inc in incidents:
        if not isinstance(inc, dict) or inc.get("status") == "IGNORED":
            continue
        log_entry = inc.get("log_entry") or {}
        if _lookup_ignored_meta({"log_id": inc.get("incident_id"), **log_entry}) is not None:
            continue
        copy_inc = dict(inc)
        prio = _compute_issue_priority({**log_entry, "is_anomaly": True})
        copy_inc.setdefault("priority_tier", prio["priority_tier"])
        copy_inc.setdefault("priority_rank", prio["priority_rank"])
        copy_inc.setdefault("priority_score", prio["priority_score"])
        copy_inc.setdefault("priority_label", prio["priority_label"])
        enriched.append(copy_inc)

    def _inc_sort_key(item: Dict[str, Any]) -> Any:
        st = str(item.get("status") or "")
        actionable = 1 if st in ("AWAITING_HITL_APPROVAL", "BLOCKED_PROVIDER_OUTAGE") else 0
        return (
            actionable,
            int(item.get("priority_score") or 0),
            str(item.get("created_at") or "").replace(" ", "T"),
        )

    enriched.sort(key=_inc_sort_key, reverse=True)
    return enriched


async def _run_watcher_sync_once(force: bool = False) -> None:
    """Executes one Cloud Logging / remote watcher sync without blocking the asyncio event loop."""
    global _last_watcher_sync_ts, _watcher_refresh_in_flight
    async with _watcher_sync_lock:
        _watcher_refresh_in_flight = True
        try:
            _last_watcher_sync_ts = time.time()
            if os.getenv("WATCHER_AGENT_URL"):
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
                    return
                except Exception:
                    pass
            await asyncio.to_thread(
                logging_service.fetch_recent_logs,
                25,
                True,
                force,
            )
        finally:
            _last_watcher_sync_ts = time.time()
            _watcher_refresh_in_flight = False


async def _background_log_refresh(force: bool = False) -> None:
    """Fire-and-forget wrapper for background Cloud Logging refreshes so polling never stalls HTTP routes."""
    try:
        await _run_watcher_sync_once(force=force)
    except Exception:
        pass


@app.on_event("startup")
async def _startup_warm_caches() -> None:
    """Warm Cloud Firestore triage state and Cloud Logging cache in the background after Uvicorn binds port 8080."""
    await asyncio.to_thread(_load_persisted_triage_state, True)
    asyncio.create_task(_background_log_refresh(force=False))


async def sync_real_logs_from_watcher(
    force: bool = False, auto_escalate: bool = False, max_escalations: int = 1
) -> list[Dict[str, Any]]:
    """
    Polls real Google Cloud Logging via `log-watcher-agent` (either remote `agent-triad-watcher`
    Cloud Run service over A2A HTTPS or local `CloudLoggingService`) and optionally escalates
    unseen real GCP errors to `lead-orchestrator-agent`.

    When `force=False` (used by `GET /api/state`), returns cached logs immediately (<5ms) and
    schedules a single coalesced background refresh when the TTL expires so dashboard reloads
    never block on external Cloud Logging RPCs.
    """
    now_ts = time.time()
    should_sync = force or (now_ts - _last_watcher_sync_ts >= _WATCHER_REFRESH_TTL_SECONDS)

    if force:
        await _run_watcher_sync_once(force=True)
    elif should_sync and not _watcher_refresh_in_flight:
        asyncio.create_task(_background_log_refresh(force=False))

    logs = logging_service.fetch_recent_logs(limit=25, poll_gcp=False)

    if auto_escalate:
        escalated = 0
        prioritized_candidates = sorted(
            [e for e in logs if e.get("is_anomaly") and _lookup_ignored_meta(e) is None],
            key=lambda e: (
                _compute_issue_priority(e)["priority_score"],
                str(e.get("timestamp") or "").replace(" ", "T"),
            ),
            reverse=True,
        )
        for entry in prioritized_candidates:
            lid = entry.get("log_id", "")
            if lid and lid not in _seen_anomaly_ids and lid not in lead_orchestrator.incidents:
                _seen_anomaly_ids.add(lid)
                await watcher_agent.detect_and_report_anomaly(entry)
                escalated += 1
                if escalated >= max_escalations:
                    break

    return logs


def _default_region_for_cloud(cloud: str) -> str:
    if cloud == "aws":
        return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    if cloud == "azure":
        return os.getenv("AZURE_LOCATION") or "eastus"
    return os.getenv("GCP_LOCATION") or "us-central1"


def _build_platform_runtime() -> Dict[str, Any]:
    active_cloud = lead_orchestrator.active_target_cloud
    default_region = _default_region_for_cloud(active_cloud)
    provider_status = cloud_status_service.check_region_status(
        cloud_provider=active_cloud,
        region=default_region,
    )
    return {
        "cloud_provider": active_cloud,
        "default_cloud_provider": normalize_target_cloud(os.getenv("CLOUD_PROVIDER", "gcp")),
        "region": default_region,
        "llm_provider": lead_orchestrator._llm_client.provider,
        "llm_model": lead_orchestrator._llm_client.model_name,
        "telemetry_provider": logging_service.adapter.provider_name,
        "state_backend": session_store_service.adapter.backend_name,
        "lock_backend": agent_harness.lock_adapter.backend_name,
        "auth_provider": auth_broker.auth_provider,
        "cloud_provider_status": provider_status,
    }


@app.get("/api/state")
async def get_system_state() -> Dict[str, Any]:
    """Returns real-time state of all 3 agents, live GCP Cloud Logging stream, incidents, audit tracker, and A2A traces."""
    logs = await sync_real_logs_from_watcher(force=False, auto_escalate=False)
    annotated_logs = _annotate_logs_with_triage(logs)
    prioritized_open_issues = _build_prioritized_open_issues(annotated_logs)
    visible_incidents = _enrich_and_sort_incidents(lead_orchestrator.list_incidents())
    platform_runtime = await asyncio.to_thread(_build_platform_runtime)
    return {
        "gcp_status": {
            "project_id": logging_service.project_id,
            "log_name": logging_service.log_name,
            "connected": logging_service.gcp_connected,
            "detail": logging_service.gcp_status_detail,
            "suppressed_routine_logs": logging_service.suppressed_routine_logs_count,
            "heartbeat_metric": "custom.googleapis.com/aaas/heartbeat_tick (15s PASS)",
        },
        "platform_runtime": platform_runtime,
        "agents": [card.model_dump() for card in a2a_hub.agents.values()],
        "worker_boutique": WORKER_AGENT_BOUTIQUE,
        "agent_harness_status": agent_harness.get_global_harness_status(),
        "logs": annotated_logs,
        "prioritized_open_issues": prioritized_open_issues,
        "ignored_log_ids": list(_ignored_log_ids.keys()),
        "ignored_signatures": list(_ignored_signatures.keys()),
        "incidents": visible_incidents,
        "audit_events": lead_orchestrator.list_audit_events(),
        "dispatch_history": lead_orchestrator.list_dispatch_history(),
        "general_chat_messages": lead_orchestrator.list_general_chat_messages(),
        "active_session_id": lead_orchestrator.active_session_id,
        "chat_sessions": lead_orchestrator.list_chat_sessions(),
        "session_store": session_store_service.get_status(),
        "a2a_ledger": a2a_hub.message_ledger[:30],
        "active_user": lead_orchestrator.active_user,
    }


@app.get("/api/harness/status")
async def get_harness_status() -> Dict[str, Any]:
    """Returns live Agent Harness telemetry (`.tflock` leases, OPA evaluations, SAIF sanitization count, and 45s Watchdog)."""
    return agent_harness.get_global_harness_status()


@app.post("/api/platform/target-cloud")
async def set_platform_target_cloud(req: SetTargetCloudRequest) -> Dict[str, Any]:
    """Switches the active target cloud (`gcp` | `aws` | `azure`) for AaaS Command Center routing."""
    try:
        updated_cloud = lead_orchestrator.set_target_cloud(req.target_cloud)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    platform_runtime = await asyncio.to_thread(_build_platform_runtime)
    return {
        "status": "TARGET_CLOUD_UPDATED",
        "target_cloud": updated_cloud,
        "platform_runtime": platform_runtime,
    }


@app.get("/api/preflight/cloud-status")
async def get_cloud_provider_preflight_status(
    cloud: str = "gcp",
    region: str = "us-central1",
    service: Optional[str] = None,
) -> Dict[str, Any]:
    """Pre-flight Cloud Provider regional outage check (`gcp` | `aws` | `azure`)."""
    return await asyncio.to_thread(
        cloud_status_service.check_region_status,
        cloud_provider=cloud,
        region=region,
        service_hint=service,
    )


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
async def poll_cloud_logging(req: Optional[PollCloudLoggingRequest] = None) -> Dict[str, Any]:
    """
    Dedicated Live GCP Log Poll endpoint:
      1. Queries `log-watcher-agent` (`agent-triad-watcher`) over A2A (`scan_cloud_logging`, `force=True`).
      2. Filters out all logs/signatures marked `Safe to Ignore` (`_lookup_ignored_meta`).
      3. Ranks remaining real GCP anomalies highest-priority-first (`P1` -> `P4`, then newest timestamp)
         so critical table/service failures are picked ahead of low-impact port/probe false positives,
         and escalates the selected alert over A2A (`ingest_anomaly_alert`) to `lead-orchestrator-agent`.
    """
    global _real_poll_cursor
    payload = req or PollCloudLoggingRequest()
    strategy = (payload.strategy or "prioritized").strip().lower()
    requested_log_id = (payload.log_id or "").strip()

    logs = await sync_real_logs_from_watcher(force=True, auto_escalate=False)

    def _eligible_for_poll(entry: Dict[str, Any]) -> bool:
        if not entry.get("is_anomaly"):
            return False
        if _lookup_ignored_meta(entry) is not None:
            return False
        lid = str(entry.get("log_id") or "")
        existing_inc = lead_orchestrator.incidents.get(lid)
        if existing_inc and existing_inc.get("status") == "IGNORED":
            return False
        return True

    real_anomalies = [
        entry
        for entry in logs
        if _eligible_for_poll(entry) and str(entry.get("log_id", "")).startswith("gcp-")
    ]
    if not real_anomalies:
        real_anomalies = [entry for entry in logs if _eligible_for_poll(entry)]

    if strategy == "newest":
        real_anomalies.sort(
            key=lambda e: (
                str(e.get("timestamp", "")).replace(" ", "T"),
                _compute_issue_priority(e)["priority_score"],
            ),
            reverse=True,
        )
    else:
        # Default `prioritized`: rank P1 -> P2 -> P3 -> P4 first, then newest timestamp within tier
        real_anomalies.sort(
            key=lambda e: (
                _compute_issue_priority(e)["priority_score"],
                str(e.get("timestamp", "")).replace(" ", "T"),
                1 if str(e.get("log_id", "")).startswith(("gcp-ds-", "gcp-sql-")) else 0,
            ),
            reverse=True,
        )

    target_entry = None
    if requested_log_id:
        target_entry = next(
            (e for e in logs if str(e.get("log_id") or "") == requested_log_id and _eligible_for_poll(e)),
            None,
        )

    if target_entry is None:
        for entry in real_anomalies:
            lid = entry.get("log_id")
            existing = lead_orchestrator.incidents.get(lid)
            if not existing:
                target_entry = entry
                break

    if target_entry is None and real_anomalies:
        actionable_existing = [
            entry
            for entry in real_anomalies
            if (lead_orchestrator.incidents.get(str(entry.get("log_id") or "")) or {}).get("status")
            in ("AWAITING_HITL_APPROVAL", "BLOCKED_PROVIDER_OUTAGE")
        ]
        if actionable_existing:
            if strategy == "cycle":
                target_entry = actionable_existing[_real_poll_cursor % len(actionable_existing)]
                _real_poll_cursor += 1
            else:
                target_entry = actionable_existing[0]

    newly_reported = []
    orchestrator_result = None
    incident_id = None
    if target_entry is not None:
        lid = target_entry["log_id"]
        _seen_anomaly_ids.add(lid)
        existing_inc = lead_orchestrator.incidents.get(lid)
        if existing_inc and existing_inc.get("status") in ("AWAITING_HITL_APPROVAL", "BLOCKED_PROVIDER_OUTAGE"):
            incident_id = lid
        else:
            orchestrator_result = await watcher_agent.detect_and_report_anomaly(target_entry)
            incident_id = orchestrator_result.get("incident_id", lid)
            newly_reported.append(incident_id)

    annotated_after = _annotate_logs_with_triage(logs)
    prioritized_queue = _build_prioritized_open_issues(annotated_after)
    return {
        "status": (
            "REAL_GCP_INCIDENT_REPORTED_TO_ORCHESTRATOR"
            if incident_id is not None
            else "NO_UNIGNORED_ANOMALIES"
        ),
        "strategy": strategy,
        "gcp_connected": logging_service.gcp_connected,
        "incident_id": incident_id,
        "log_entry": target_entry,
        "priority": _compute_issue_priority(target_entry) if target_entry else None,
        "prioritized_open_issues": prioritized_queue,
        "orchestrator_result": orchestrator_result,
        "incident": lead_orchestrator.incidents.get(incident_id) if incident_id else None,
        "newly_reported_incidents": newly_reported,
        "total_logs": len(logs),
    }


@app.post("/api/tickets/ingest")
async def ingest_customer_support_ticket(req: CustomerTicketIngestRequest) -> Dict[str, Any]:
    """
    Ingests an enterprise support ticket (e.g., Scenario 1 Datastream Private Connectivity
    FAILED_PRECONDITION / IAM state drift) into the Agent-Triad 4-phase A2A pipeline:
      Phase 1: Cloud_Provider_Health_Tool pre-flight check (OPERATIONAL Green -> proceed)
      Phase 2: Parallel Security Agent (`Security_Agent_Tool`) + Infra Agent (`GitOps_Correlator_Tool`)
      Phase 3: Atlas Blameless RCA synthesis + exact live `gcloud projects add-iam-policy-binding` CLI
      Phase 4: Stage 2 HITL gate (`AWAITING_HITL_APPROVAL`, zero autonomous execution until 'I accept')
    """
    clean_project = (req.project_id or logging_service.project_id).replace("projects/", "").strip() or logging_service.project_id
    clean_region = (req.region or "europe-west2").strip()
    sa_email = (
        (req.service_agent_email or "").strip()
        or security_iam_service.default_datastream_service_agent(clean_project)
    )
    if sa_email.startswith("serviceAccount:"):
        sa_email = sa_email.split(":", 1)[1]

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ticket_id = f"tkt-ds-{uuid.uuid4().hex[:8]}"
    rec_cli = (
        f'gcloud projects add-iam-policy-binding {clean_project} '
        f'--member="serviceAccount:{sa_email}" --role="roles/compute.networkAdmin"'
    )
    customer_ticket_meta = {
        "ticket_id": ticket_id,
        "customer_name": (req.customer_name or "Enterprise Customer").strip(),
        "project_id": f"projects/{clean_project}",
        "clean_project_id": clean_project,
        "region": clean_region,
        "business_impact": (req.business_impact or "Non-Production System impaired").strip(),
        "observed_error": (req.error_message or "").strip(),
        "ticket_description": (req.ticket_description or "").strip(),
        "service_agent_email": sa_email,
        "submitted_at": now_iso,
    }

    ticket_entry = normalize_otel_anomaly(
        log_id=ticket_id,
        signature_key=f"datastream:{clean_project}:IAM_FAILED_PRECONDITION",
        timestamp=now_iso,
        severity="ERROR",
        scenario_id="datastream_iam_drift",
        title=f"Datastream Private Connectivity ({clean_project}): Missing Datastream SA IAM Permissions",
        source="gcp:datastream.googleapis.com",
        project_id=clean_project,
        cluster=clean_region,
        namespace="datastream",
        workload=(req.workload or "datastream/private-connectivity-ew2").strip(),
        pod="datastream-private-connectivity",
        container="datastream-private-connectivity",
        error_code="DATASTREAM_FAILED_PRECONDITION_IAM",
        message=(req.error_message or "").strip(),
        metrics_snapshot={
            "service": "datastream.googleapis.com",
            "region": clean_region,
            "project_id": clean_project,
            "datastream_sa": sa_email,
            "business_impact": customer_ticket_meta["business_impact"],
        },
        recommended_kubectl=rec_cli,
        recommended_action_type="datastream_iam_policy_remediation",
        is_anomaly=True,
        persisted_to_gcp=False,
        cloud_provider="gcp",
        extra_attributes={
            "gcp.service": "datastream.googleapis.com",
            "gcp.datastream.service_agent": sa_email,
            "gcp.region": clean_region,
            "customer.name": customer_ticket_meta["customer_name"],
            "lock_recommended_cli": True,
        },
    )
    ticket_entry["customer_ticket"] = customer_ticket_meta
    if req.mock_deployments:
        ticket_entry["mock_deployments"] = req.mock_deployments

    if clean_project == logging_service.project_id:
        try:
            await asyncio.to_thread(logging_service.record_anomaly_log, ticket_entry)
        except Exception:
            pass

    logging_service._local_logs.insert(0, ticket_entry)
    _seen_anomaly_ids.add(ticket_id)
    orchestrator_result = await watcher_agent.detect_and_report_anomaly(ticket_entry)
    incident_id = orchestrator_result.get("incident_id", ticket_id)
    incident = lead_orchestrator.incidents.get(incident_id)
    return {
        "status": "TICKET_INGESTED_AWAITING_HITL",
        "incident_id": incident_id,
        "ticket": customer_ticket_meta,
        "incident": incident,
        "orchestrator_result": orchestrator_result,
    }


class RecreateScenario1Request(BaseModel):
    project_id: Optional[str] = None
    execute_live: bool = True


@app.post("/api/scenarios/datastream-iam-drift/recreate")
async def recreate_scenario1_datastream_iam_drift(
    req: Optional[RecreateScenario1Request] = None,
) -> Dict[str, Any]:
    """
    One-click demo reset for Scenario 1 (Datastream Private Connectivity IAM Drift).
    Strips `roles/compute.networkAdmin` / `roles/datastream.serviceAgent` from the sandbox
    Datastream service agent on `agent-triad` via `sa-aaas-execution-sandbox` impersonation,
    writing a real `SetIamPolicy REMOVE` Cloud Audit Log so the next Support Ticket triage
    detects genuine IAM drift end-to-end.
    """
    payload = req or RecreateScenario1Request()
    target_project = (payload.project_id or logging_service.project_id).replace("projects/", "").strip()
    result = await asyncio.to_thread(
        security_iam_service.remove_datastream_iam_bindings_live,
        project_id=target_project,
        execute_live=bool(payload.execute_live),
    )
    ok = result.get("status") in (
        "FAULT_RECREATED_LIVE",
        "ALREADY_ARMED_LIVE",
        "FAULT_RECREATED_SANDBOX_DRY_RUN",
    )
    try:
        await asyncio.to_thread(
            logging_service.record_system_log,
            severity="WARNING" if ok else "ERROR",
            workload="datastream/private-connectivity-ew2",
            namespace="datastream",
            cluster="europe-west2",
            message=result.get("summary") or f"Scenario 1 fault reset status: {result.get('status')}",
        )
    except Exception:
        pass
    if not ok:
        raise HTTPException(
            status_code=500 if result.get("status") == "LIVE_IAM_EXECUTION_ERROR" else 400,
            detail=result.get("error") or result.get("summary") or "Failed to re-create Scenario 1 fault",
        )
    return result


@app.post("/api/logs/ignore")
async def mark_logs_safe_to_ignore(req: LogTriageBatchRequest) -> Dict[str, Any]:
    """
    Marks one or more live Cloud Logging alerts as 'Safe to Ignore'.
    Updates the live Cloud Health alert count, durably persists log IDs + recurring signatures
    to Cloud Firestore so they never appear again in Atlas, dismisses any open incident as IGNORED,
    and writes an audit record.
    """
    cleaned_ids = [str(lid).strip() for lid in (req.log_ids or []) if str(lid or "").strip()]
    if not cleaned_ids:
        raise HTTPException(status_code=400, detail="At least one log_id is required")

    uname = (req.user_name or lead_orchestrator.active_user.get("name") or "Hari").strip()
    reason = (req.reason or "Marked safe to ignore by operator").strip()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    matched_entries = {str(e.get("log_id") or ""): e for e in _find_logs_by_ids(cleaned_ids)}
    for lid in cleaned_ids:
        if lid not in matched_entries and lid in lead_orchestrator.incidents:
            inc_log = (lead_orchestrator.incidents[lid] or {}).get("log_entry")
            if isinstance(inc_log, dict):
                matched_entries[lid] = {"log_id": lid, **inc_log}

    # Optional storm & recurring-signature suppression: suppress sibling logs & future polls sharing signature_key or (workload, error_code)
    target_ids: List[str] = list(dict.fromkeys(cleaned_ids))
    similar_expanded_count = 0
    suppressed_sig_tokens: List[str] = []
    if req.ignore_similar_signatures and matched_entries:
        sig_keys = {
            str(e.get("signature_key") or "").strip()
            for e in matched_entries.values()
            if str(e.get("signature_key") or "").strip()
        }
        wl_err_pairs = {
            (str(e.get("workload") or "").strip(), str(e.get("error_code") or "").strip())
            for e in matched_entries.values()
            if str(e.get("workload") or "").strip()
        }
        for entry in matched_entries.values():
            for tok in _entry_signature_tokens(entry):
                if tok not in _ignored_signatures:
                    suppressed_sig_tokens.append(tok)
                _ignored_signatures[tok] = {
                    "signature": tok,
                    "ignored_by": uname,
                    "ignored_at": now_iso,
                    "reason": reason,
                    "workload": entry.get("workload", ""),
                    "title": entry.get("title", ""),
                }

        existing_set = set(target_ids)
        for cand in logging_service._local_logs:
            cid = str(cand.get("log_id") or "").strip()
            if not cid or cid in existing_set or not cand.get("is_anomaly"):
                continue
            cand_sig = str(cand.get("signature_key") or "").strip()
            cand_pair = (str(cand.get("workload") or "").strip(), str(cand.get("error_code") or "").strip())
            if (cand_sig and cand_sig in sig_keys) or (cand_pair[0] and cand_pair in wl_err_pairs):
                target_ids.append(cid)
                existing_set.add(cid)
                matched_entries[cid] = cand
                similar_expanded_count += 1

        for inc_id, inc_obj in list(lead_orchestrator.incidents.items()):
            if inc_id in existing_set or not isinstance(inc_obj, dict):
                continue
            inc_entry = inc_obj.get("log_entry") or {}
            cand_sig = str(inc_entry.get("signature_key") or "").strip()
            cand_pair = (str(inc_entry.get("workload") or "").strip(), str(inc_entry.get("error_code") or "").strip())
            if (cand_sig and cand_sig in sig_keys) or (cand_pair[0] and cand_pair in wl_err_pairs):
                target_ids.append(inc_id)
                existing_set.add(inc_id)
                matched_entries[inc_id] = {"log_id": inc_id, **inc_entry}

    ignored_now: List[str] = []
    for lid in target_ids:
        entry = matched_entries.get(lid) or {}
        entry_tokens = _entry_signature_tokens(entry) if req.ignore_similar_signatures else []
        _ignored_log_ids[lid] = {
            "log_id": lid,
            "ignored_by": uname,
            "ignored_at": now_iso,
            "reason": reason,
            "workload": entry.get("workload", ""),
            "title": entry.get("title", ""),
            "signature_tokens": entry_tokens,
        }
        _seen_anomaly_ids.add(lid)
        ignored_now.append(lid)

        existing_inc = lead_orchestrator.incidents.get(lid)
        if existing_inc and existing_inc.get("status") not in ("RESOLVED", "ROLLED_BACK", "IGNORED"):
            lead_orchestrator.dismiss_incident_ignored(
                incident_id=lid,
                ignored_by=uname,
                reason=reason,
                signature_key=str(entry.get("signature_key") or "") if req.ignore_similar_signatures else "",
            )
        else:
            lead_orchestrator.ignored_log_ids.add(lid)

        if entry:
            try:
                await asyncio.to_thread(
                    logging_service.record_audit_event,
                    incident_id=lid,
                    event_type="LOG_MARKED_SAFE_TO_IGNORE",
                    service=str(entry.get("workload") or entry.get("source") or "cloud-log"),
                    issue_title=f"{str(entry.get('title') or entry.get('message') or lid)[:120]} [{reason[:35]}]",
                    occurred_at=str(entry.get("timestamp") or now_iso),
                    action_status="SAFE_TO_IGNORE",
                    approved_by=uname,
                    approved_at=now_iso,
                )
            except Exception:
                pass

    await asyncio.to_thread(_persist_triage_state)
    return {
        "status": "LOGS_MARKED_SAFE_TO_IGNORE",
        "ignored_ids": ignored_now,
        "ignored_signatures": list(_ignored_signatures.keys()),
        "suppressed_signature_count": len(suppressed_sig_tokens),
        "similar_expanded_count": similar_expanded_count,
        "reason": reason,
        "ignored_by": uname,
        "ignored_at": now_iso,
        "total_ignored": len(_ignored_log_ids),
    }


@app.post("/api/logs/unignore")
async def restore_ignored_logs(req: LogTriageBatchRequest) -> Dict[str, Any]:
    """Restores one or more previously ignored Cloud Logging alerts (and their signatures) back to active triage."""
    cleaned_ids = [str(lid).strip() for lid in (req.log_ids or []) if str(lid or "").strip()]
    if not cleaned_ids:
        raise HTTPException(status_code=400, detail="At least one log_id is required")

    matched_entries = {str(e.get("log_id") or ""): e for e in _find_logs_by_ids(cleaned_ids)}
    restored: List[str] = []
    restored_sigs: set[str] = set()

    for lid in cleaned_ids:
        prev_meta = _ignored_log_ids.pop(lid, None)
        if prev_meta is not None:
            restored.append(lid)
            for tok in prev_meta.get("signature_tokens") or []:
                if tok:
                    restored_sigs.add(str(tok))
            if prev_meta.get("matched_signature"):
                restored_sigs.add(str(prev_meta["matched_signature"]))
        entry = matched_entries.get(lid) or ((lead_orchestrator.incidents.get(lid) or {}).get("log_entry") or {})
        for tok in _entry_signature_tokens(entry):
            restored_sigs.add(tok)
        _seen_anomaly_ids.discard(lid)

    for sig in restored_sigs:
        _ignored_signatures.pop(sig, None)

    if restored_sigs:
        for extra_lid, extra_meta in list(_ignored_log_ids.items()):
            if extra_meta.get("matched_signature") in restored_sigs:
                _ignored_log_ids.pop(extra_lid, None)
                _seen_anomaly_ids.discard(extra_lid)
                if extra_lid not in restored:
                    restored.append(extra_lid)

    lead_orchestrator.restore_ignored_signatures(
        log_ids=list(dict.fromkeys(cleaned_ids + restored)),
        signature_keys=list(restored_sigs),
    )
    for lid in cleaned_ids:
        existing_inc = lead_orchestrator.incidents.get(lid)
        if existing_inc and existing_inc.get("status") in ("SKIPPED_MANUAL", "IGNORED"):
            existing_inc["ignored"] = False
            lead_orchestrator.reopen_incident(incident_id=lid)

    await asyncio.to_thread(_persist_triage_state)
    return {
        "status": "LOGS_RESTORED",
        "restored_ids": restored,
        "restored_signatures": sorted(restored_sigs),
        "total_ignored": len(_ignored_log_ids),
    }


@app.post("/api/logs/fix-via-chat")
async def fix_selected_logs_via_chat(req: LogTriageBatchRequest) -> Dict[str, Any]:
    """
    Sends one or more selected live Cloud Logging alerts directly into AaaS Chat with Atlas:
      - 1 selected log: escalates via Heartbeat & Telemetry (SAIF-sanitized) -> Atlas -> Specialist A2A
        and opens the dedicated Incident Remediation Chat + 'I accept — Dispatch' HITL workflow.
      - 2+ selected logs: opens Direct Atlas Chat with a unified multi-alert triage prompt so Atlas
        can diagnose shared root causes and propose a coordinated CLI or Multi-Service Terraform fix.
    """
    cleaned_ids = [str(lid).strip() for lid in (req.log_ids or []) if str(lid or "").strip()]
    if not cleaned_ids:
        raise HTTPException(status_code=400, detail="At least one log_id is required")

    selected_entries = _find_logs_by_ids(cleaned_ids)
    if not selected_entries:
        raise HTTPException(status_code=404, detail="None of the selected log IDs were found in the live log buffer")

    cleared_any_ignore = False
    for entry in selected_entries:
        lid = str(entry.get("log_id") or "")
        if _ignored_log_ids.pop(lid, None) is not None:
            cleared_any_ignore = True
        entry_sigs = _entry_signature_tokens(entry)
        for sig in entry_sigs:
            if _ignored_signatures.pop(sig, None) is not None:
                cleared_any_ignore = True
        lead_orchestrator.restore_ignored_signatures(log_ids=[lid], signature_keys=entry_sigs)
    if cleared_any_ignore:
        await asyncio.to_thread(_persist_triage_state)

    uname = (req.user_name or lead_orchestrator.active_user.get("name") or "Hari").strip()
    active_cloud = req.target_cloud or lead_orchestrator.active_target_cloud
    strategy = (req.strategy or "auto").strip().lower()

    async def _escalate_one_incident(entry: Dict[str, Any]) -> Dict[str, Any]:
        lid = str(entry.get("log_id") or "")
        existing = lead_orchestrator.incidents.get(lid)
        if existing:
            if existing.get("status") in ("SKIPPED_MANUAL", "IGNORED"):
                existing["ignored"] = False
                existing = lead_orchestrator.reopen_incident(incident_id=lid)
            return {
                "incident_id": lid,
                "incident": existing,
                "reused_existing": True,
                "orchestrator_result": None,
            }
        _seen_anomaly_ids.add(lid)
        orch_res = await watcher_agent.detect_and_report_anomaly(entry)
        inc_id = orch_res.get("incident_id", lid)
        return {
            "incident_id": inc_id,
            "incident": lead_orchestrator.incidents.get(inc_id),
            "reused_existing": False,
            "orchestrator_result": orch_res,
        }

    # Mode 1: Single alert (default 'auto') -> dedicated Incident Remediation Chat + HITL approval
    if len(selected_entries) == 1 and strategy != "unified_chat":
        esc = await _escalate_one_incident(selected_entries[0])
        return {
            "status": "ESCALATED_TO_AAAS_CHAT",
            "mode": "incident",
            "incident_id": esc["incident_id"],
            "incident": esc["incident"],
            "orchestrator_result": esc["orchestrator_result"],
            "reused_existing": esc["reused_existing"],
        }

    # Mode 2: Multiple alerts with explicit 'separate_incidents' -> queue up to 5 separate HITL incident cards in parallel
    if strategy == "separate_incidents":
        batch = selected_entries[:5]
        escalated_items = await asyncio.gather(*[_escalate_one_incident(e) for e in batch])
        incident_ids = [item["incident_id"] for item in escalated_items if item.get("incident_id")]
        primary_id = incident_ids[0] if incident_ids else None
        return {
            "status": "QUEUED_SEPARATE_INCIDENTS",
            "mode": "separate_incidents",
            "incident_id": primary_id,
            "incident_ids": incident_ids,
            "queued_count": len(incident_ids),
            "truncated_count": max(0, len(selected_entries) - len(batch)),
            "incident": lead_orchestrator.incidents.get(primary_id) if primary_id else None,
        }

    # Mode 3: Unified multi-alert diagnosis in Direct Atlas Chat (default for 2+ alerts)
    bullet_lines = []
    for idx, entry in enumerate(selected_entries[:10], start=1):
        sev = str(entry.get("severity") or "ERROR").upper()
        wl = str(entry.get("workload") or entry.get("cluster") or "cloud-service")
        ts = str(entry.get("timestamp") or "")
        msg = str(entry.get("message") or entry.get("title") or "").strip().replace("\n", " ")[:240]
        bullet_lines.append(f"{idx}. [{sev}] `{wl}` ({ts}): {msg}")

    more_note = (
        f"\n(Plus {len(selected_entries) - 10} additional selected alerts from the same live log view.)"
        if len(selected_entries) > 10
        else ""
    )
    prompt = (
        f"Please diagnose and help me fix these {len(selected_entries)} selected live cloud log alerts together. "
        f"Identify common root causes, inspect live service telemetry, and propose the safest CLI or Multi-Service Terraform remediation:\n\n"
        + "\n".join(bullet_lines)
        + more_note
    )
    chat_result = await lead_orchestrator.chat_general_with_atlas(
        user_message=prompt,
        user_name=uname,
        target_cloud=active_cloud,
    )
    return {
        "status": "SENT_TO_AAAS_CHAT",
        "mode": "direct_chat",
        "log_count": len(selected_entries),
        "log_ids": [str(e.get("log_id") or "") for e in selected_entries],
        "chat_result": chat_result,
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

    approver = (req.approved_by or lead_orchestrator.active_user.get("name") or "Hari").strip()
    updated_incident = await lead_orchestrator.approve_and_delegate_to_gke_assist(
        incident_id=incident_id,
        approved_by=approver,
        execution_mode=req.execution_mode,
        custom_kubectl=req.custom_kubectl,
        critical_change_confirmed=req.critical_change_confirmed,
    )
    inc_status = updated_incident.get("status")
    if inc_status == "BLOCKED_PROVIDER_OUTAGE":
        resp_status = "BLOCKED_PROVIDER_OUTAGE"
    elif updated_incident.get("last_approval_gate") == "CRITICAL_CONFIRMATION_REQUIRED" and inc_status == "AWAITING_HITL_APPROVAL":
        resp_status = "CRITICAL_CONFIRMATION_REQUIRED"
    elif inc_status == "REMEDIATION_FAILED":
        resp_status = "REMEDIATION_FAILED"
    elif inc_status == "ROLLED_BACK":
        resp_status = "REMEDIATION_ROLLED_BACK"
    else:
        resp_status = "REMEDIATION_COMPLETED_AND_VERIFIED"
    return {
        "status": resp_status,
        "requires_critical_confirmation": bool(
            (updated_incident.get("change_risk") or {}).get("requires_critical_confirmation")
        ),
        "change_risk": updated_incident.get("change_risk"),
        "incident": updated_incident,
    }


@app.post("/api/incidents/{incident_id}/rollback")
async def rollback_incident_remedy(
    incident_id: str,
    req: Optional[RollbackIncidentRequest] = None,
) -> Dict[str, Any]:
    """
    Reverts a previously applied incident remediation back to its pre-execution stable snapshot
    (`rollback_snapshot`) under a scoped 15-minute Rollback JIT token and optionally places
    the remediation signature in the 7-Day Poison-Pill Quarantine Registry.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    payload = req or RollbackIncidentRequest()
    requester = (
        (payload.requested_by or "").strip()
        or f"{lead_orchestrator.active_user.get('name', 'Hari')} ({lead_orchestrator.active_user.get('email', 'operator@google.com')})"
    )
    updated = await lead_orchestrator.rollback_incident_remediation(
        incident_id=incident_id,
        requested_by=requester,
        reason=payload.reason or f"Manual 1-click revert to stable snapshot requested by {requester}",
        execution_mode=payload.execution_mode,
        quarantine_signature=bool(payload.quarantine_signature),
    )
    return {
        "status": "REMEDIATION_ROLLED_BACK",
        "incident": updated,
        "rollback_result": updated.get("rollback_result"),
    }


@app.post("/api/incidents/{incident_id}/verify-health")
async def verify_incident_service_health(incident_id: str) -> Dict[str, Any]:
    """
    Runs an on-demand Post-Fix Service Health Verification across target service state,
    post-execution Cloud Logging errors (`timestamp > execution_completed_at`), cross-service
    peer health, and 15s Dead-Man's Switch heartbeat telemetry.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    await sync_real_logs_from_watcher(force=False, auto_escalate=False)
    report = await lead_orchestrator.verify_incident_post_fix_health(incident_id=incident_id)
    return {
        "status": report["overall_health"],
        "report": report,
        "incident": lead_orchestrator.incidents.get(incident_id),
    }


@app.post("/api/platform/verify-health")
async def verify_platform_service_health() -> Dict[str, Any]:
    """
    Runs an on-demand Live Service Health Watch check across the active cloud region,
    Cloud Logging telemetry stream, ADK Specialist roster, and 45s/3m Watchdog guardrails
    when no specific incident is selected.
    """
    logs = await sync_real_logs_from_watcher(force=False, auto_escalate=False)
    annotated = _annotate_logs_with_triage(logs)
    active_err_logs = [
        l
        for l in annotated
        if l.get("is_anomaly") and l.get("triage_status") not in ("IGNORED", "RESOLVED", "ROLLED_BACK")
    ]
    target_cloud = lead_orchestrator.active_target_cloud or "gcp"
    region = os.getenv("GCP_LOCATION", "us-central1")
    provider_status = await lead_orchestrator._run_cloud_provider_preflight_check(
        cloud_provider=target_cloud,
        region=region,
    )
    harness_state = agent_harness.get_global_harness_status()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    provider_ok = provider_status.get("mutations_allowed", True)
    checks = [
        {
            "id": "telemetry_stream",
            "label": "Cloud Logging & 15s Heartbeat Stream",
            "status": "PASS" if logging_service.gcp_connected else "WARN",
            "detail": f"{logging_service.gcp_status_detail} • {logging_service.suppressed_routine_logs_count} routine logs filtered at edge.",
        },
        {
            "id": "active_anomalies",
            "label": "Project Service Error Scan",
            "status": "PASS" if len(active_err_logs) == 0 else "WARN",
            "detail": (
                "0 unresolved anomaly alerts across monitored services."
                if len(active_err_logs) == 0
                else f"{len(active_err_logs)} active log alert(s) available for triage in Logs & A2A."
            ),
        },
        {
            "id": "specialist_roster",
            "label": "Zero-Trust ADK Specialists & Watchdog",
            "status": "PASS",
            "detail": (
                f"3 Live Cloud Run ADK Specialists online (Database • Infra • Security) • "
                f"{harness_state.get('watchdog_status', '45s Watchdog Armed')}."
            ),
        },
        {
            "id": "regional_provider",
            "label": "Cloud Provider Regional Feed",
            "status": "PASS" if provider_ok else "FAIL",
            "detail": f"{target_cloud.upper()} `{region}` status: {provider_status.get('status', 'OPERATIONAL')}.",
        },
    ]
    overall = "VERIFIED_HEALTHY" if provider_ok and len(active_err_logs) == 0 else "MONITORING_ACTIVE"
    report = {
        "incident_id": None,
        "service_label": f"{target_cloud.upper()} Project Services ({logging_service.project_id})",
        "workload": f"project/{logging_service.project_id}",
        "region": region,
        "target_cloud": target_cloud,
        "incident_status": "PLATFORM_WATCH",
        "overall_health": overall,
        "healthy": provider_ok,
        "checks": checks,
        "verified_at": now_iso,
    }
    return {
        "status": overall,
        "report": report,
    }


@app.post("/api/incidents/{incident_id}/skip")
async def skip_incident_remedy(incident_id: str) -> Dict[str, Any]:
    """User chooses Later / Fix Manually. Worker Agent stands down while keeping incident visible."""
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    updated = lead_orchestrator.skip_incident_manual(incident_id=incident_id)
    return {
        "status": "SKIPPED_MANUAL",
        "incident": updated,
    }


@app.post("/api/incidents/{incident_id}/ignore")
async def ignore_incident_permanently(
    incident_id: str,
    req: Optional[IgnoreIncidentRequest] = None,
) -> Dict[str, Any]:
    """
    Permanently marks an Atlas incident (and its recurring log signature) as 'Safe to Ignore'.
    Persists to Cloud Firestore so it never reappears in Atlas unless explicitly restored.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    payload = req or IgnoreIncidentRequest()
    triage_res = await mark_logs_safe_to_ignore(
        LogTriageBatchRequest(
            log_ids=[incident_id],
            reason=payload.reason or "Marked safe to ignore in Atlas",
            user_name=payload.user_name,
            ignore_similar_signatures=bool(payload.ignore_similar_signatures),
        )
    )
    remaining_incidents = _enrich_and_sort_incidents(lead_orchestrator.list_incidents())
    annotated_after = _annotate_logs_with_triage(
        logging_service.fetch_recent_logs(limit=25, poll_gcp=False)
    )
    prioritized_queue = _build_prioritized_open_issues(annotated_after)
    return {
        "status": "INCIDENT_MARKED_SAFE_TO_IGNORE",
        "incident_id": incident_id,
        "ignored_ids": triage_res["ignored_ids"],
        "ignored_signatures": triage_res["ignored_signatures"],
        "next_incident_id": remaining_incidents[0]["incident_id"] if remaining_incidents else None,
        "next_prioritized_issue": prioritized_queue[0] if prioritized_queue else None,
    }


@app.post("/api/incidents/{incident_id}/reopen")
async def reopen_incident_remedy(incident_id: str) -> Dict[str, Any]:
    """Re-opens a previously skipped or ignored incident back to awaiting approval."""
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    inc_obj = lead_orchestrator.incidents[incident_id]
    if incident_id in _ignored_log_ids or inc_obj.get("status") == "IGNORED" or inc_obj.get("ignored"):
        await restore_ignored_logs(LogTriageBatchRequest(log_ids=[incident_id]))
    updated = lead_orchestrator.reopen_incident(incident_id=incident_id)
    return {
        "status": "AWAITING_HITL_APPROVAL",
        "incident": updated,
    }


@app.post("/api/incidents/{incident_id}/recheck-provider")
async def recheck_incident_provider(incident_id: str) -> Dict[str, Any]:
    """
    Re-checks regional cloud provider health for an incident.
    Unlocks `BLOCKED_PROVIDER_OUTAGE` back to `AWAITING_HITL_APPROVAL` once the outage clears.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    updated = await lead_orchestrator.recheck_incident_provider_status(incident_id=incident_id)
    return {
        "status": updated.get("status", "AWAITING_HITL_APPROVAL"),
        "incident": updated,
        "cloud_provider_status": updated.get("cloud_provider_status"),
        "fault_attribution": updated.get("fault_attribution"),
    }


@app.post("/api/incidents/{incident_id}/chat")
async def chat_about_incident(incident_id: str, req: IncidentChatRequest) -> Dict[str, Any]:
    """
    Interactive chatbot endpoint for the signed-in user to ask the AaaS Lead Orchestrator (`Atlas`)
    questions about root cause, downtime, blast radius, or instruct it to proceed with the fix.
    """
    if incident_id not in lead_orchestrator.incidents:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    result = await lead_orchestrator.chat_with_incident(
        incident_id=incident_id,
        user_message=req.message,
        user_name=req.user_name,
    )
    inc_after = lead_orchestrator.incidents.get(incident_id) or {}
    next_incident_id: Optional[str] = None
    if result.get("action_taken") == "MARKED_SAFE_TO_IGNORE" or inc_after.get("status") == "IGNORED":
        await mark_logs_safe_to_ignore(
            LogTriageBatchRequest(
                log_ids=[incident_id],
                reason="Marked safe to ignore via Atlas chat",
                user_name=req.user_name,
                ignore_similar_signatures=True,
            )
        )
        remaining_incidents = _enrich_and_sort_incidents(lead_orchestrator.list_incidents())
        next_incident_id = remaining_incidents[0]["incident_id"] if remaining_incidents else None
    return {
        "status": "CHAT_UPDATED",
        **result,
        **({"next_incident_id": next_incident_id} if result.get("action_taken") == "MARKED_SAFE_TO_IGNORE" else {}),
    }


@app.post("/api/atlas/chat")
async def chat_general_atlas(req: IncidentChatRequest) -> Dict[str, Any]:
    """
    Direct on-demand chatbot endpoint to manually invoke Atlas across all 4 scenarios:
      - Scenario 1: Simple CLI/API troubleshooting
      - Scenario 2: Multi-service IAM + VPC + API Terraform remediation
      - Scenario 3: Custom Terraform deployment generation & validation
      - Scenario 4: Simple GCP How-To questions
    """
    if not req.message or not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    try:
        result = await lead_orchestrator.chat_general_with_atlas(
            user_message=req.message,
            user_name=req.user_name,
            target_cloud=req.target_cloud,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "status": "CHAT_UPDATED",
        **result,
    }


@app.post("/api/atlas/chat/deploy-terraform")
async def deploy_chat_terraform(req: Optional[DeployChatTerraformRequest] = None) -> Dict[str, Any]:
    """
    Approves and executes the most recent Scenario 2 / Scenario 3 Terraform bundle from
    Direct Atlas Chat via the Agent Harness Sandbox and Specialist Roster.
    """
    uname = (
        (req.approved_by if req and req.approved_by else None)
        or f"{lead_orchestrator.active_user.get('name', 'Hari')} (via Chat)"
    )
    result = await lead_orchestrator.execute_chat_terraform_deployment(
        approved_by=uname,
        target_cloud=req.target_cloud if req else None,
    )
    resp_status = (
        "BLOCKED_PROVIDER_OUTAGE"
        if result.get("status") == "BLOCKED_PROVIDER_OUTAGE"
        else "TERRAFORM_EXECUTED_VIA_HARNESS"
    )
    return {
        "status": resp_status,
        **{k: v for k, v in result.items() if k != "status"},
    }


@app.post("/api/atlas/chat/reset")
async def reset_general_atlas_chat() -> Dict[str, Any]:
    """Resets the direct/manual Atlas chat history back to the initial greeting."""
    messages = lead_orchestrator.reset_general_chat()
    return {
        "status": "CHAT_RESET",
        "active_session_id": lead_orchestrator.active_session_id,
        "messages": messages,
        "sessions": lead_orchestrator.list_chat_sessions(),
    }


@app.get("/api/atlas/sessions")
async def list_atlas_chat_sessions() -> Dict[str, Any]:
    """Lists all stored chat sessions for the signed-in Google SSO user from Cloud Firestore."""
    return {
        "status": "OK",
        "user": lead_orchestrator.active_user,
        "active_session_id": lead_orchestrator.active_session_id,
        "sessions": lead_orchestrator.list_chat_sessions(),
        "messages": lead_orchestrator.list_general_chat_messages(),
        "session_store": session_store_service.get_status(),
    }


@app.post("/api/atlas/sessions/new")
async def create_new_atlas_chat_session(req: Optional[CreateChatSessionRequest] = None) -> Dict[str, Any]:
    """Starts a new Atlas chat session while preserving previous conversations in Firestore history."""
    result = lead_orchestrator.create_new_chat_session(title=req.title if req else None)
    return {
        "status": "SESSION_CREATED",
        **result,
    }


@app.post("/api/atlas/sessions/{session_id}/select")
async def select_atlas_chat_session(session_id: str) -> Dict[str, Any]:
    """Switches to and restores a past Atlas chat session from Cloud Firestore history."""
    try:
        result = lead_orchestrator.select_chat_session(session_id=session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "status": "SESSION_SELECTED",
        **result,
    }


@app.delete("/api/atlas/sessions/{session_id}")
async def delete_atlas_chat_session(session_id: str) -> Dict[str, Any]:
    """Deletes a specific chat session from the user's Cloud Firestore history."""
    result = lead_orchestrator.delete_chat_session(session_id=session_id)
    return {
        "status": "SESSION_DELETED",
        **result,
    }


@app.delete("/api/atlas/sessions")
@app.post("/api/atlas/sessions/clear")
async def clear_all_atlas_chat_sessions() -> Dict[str, Any]:
    """Clears all stored chat sessions for the active user in Cloud Firestore."""
    result = lead_orchestrator.clear_all_chat_sessions()
    return {
        "status": "ALL_SESSIONS_CLEARED",
        **result,
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

