"""
GCP Cloud Logging Telemetry Adapter (`GCPCloudLoggingAdapter`).

Extracted directly from `poc/services/cloud_logging_service.py` to preserve 100% of existing
Google Cloud Logging, `cloud-sql-proxy` error capture, GKE Composer / GCE Guest Agent edge
noise filtering, and `AAAS_AUDIT_EVENT` persistence behind `TelemetryIngestionAdapter`,
enriched with the unified OpenTelemetry anomaly schema (`normalize_otel_anomaly`).
"""

from __future__ import annotations

import datetime
import os
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    from google.cloud import logging as gcp_logging
except ImportError:
    gcp_logging = None

from providers.base_telemetry import TelemetryIngestionAdapter, normalize_otel_anomaly
from services.gcp_auth import get_gcp_credentials


PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
LOG_NAME = os.getenv("AAAS_LOG_NAME", "aaas_gke_incidents")


class GCPCloudLoggingAdapter(TelemetryIngestionAdapter):
    """Concrete GCP Cloud Logging adapter implementing `TelemetryIngestionAdapter`."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        log_name: Optional[str] = None,
        initial_poll: bool = True,
    ) -> None:
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID", PROJECT_ID)
        self.log_name = log_name or os.getenv("AAAS_LOG_NAME", LOG_NAME)
        self._client: Optional[Any] = None
        self._logger: Optional[Any] = None
        self._gcp_connected: bool = False
        self._gcp_status_detail: str = "Initializing"
        self._local_logs: List[Dict[str, Any]] = []
        self._suppressed_routine_logs_count: int = 0
        self._last_poll_time: float = 0.0
        self._init_gcp_client()
        if initial_poll:
            self.fetch_recent_logs(limit=25, poll_remote=True, force=True)

    @property
    def provider_name(self) -> str:
        return "GCP Cloud Logging"

    @property
    def is_connected(self) -> bool:
        return self._gcp_connected

    @property
    def status_detail(self) -> str:
        return self._gcp_status_detail

    @property
    def suppressed_routine_logs_count(self) -> int:
        return self._suppressed_routine_logs_count

    @suppressed_routine_logs_count.setter
    def suppressed_routine_logs_count(self, value: int) -> None:
        self._suppressed_routine_logs_count = int(value)

    @property
    def local_logs(self) -> List[Dict[str, Any]]:
        return self._local_logs

    def _init_gcp_client(self) -> None:
        if gcp_logging is None:
            self._gcp_connected = False
            self._gcp_status_detail = "google-cloud-logging not installed; using local buffer"
            return
        try:
            creds = get_gcp_credentials()
            self._client = gcp_logging.Client(project=self.project_id, credentials=creds)
            self._logger = self._client.logger(self.log_name)
            self._gcp_connected = True
            self._gcp_status_detail = f"Live GCP Cloud Logging active (project: {self.project_id})"
        except Exception as exc:  # pragma: no cover - graceful fallback
            self._gcp_connected = False
            self._gcp_status_detail = f"Local fallback active ({exc})"

    def _is_routine_noise(self, raw_text: str, log_name: str, severity: str) -> bool:
        """Filters routine health checks, /api/state polling, and library deprecation warnings at the edge."""
        if not raw_text or raw_text == "None":
            if severity in ("DEFAULT", "INFO", "NOTICE", None, ""):
                return True
        noisy_substrings = (
            "GET /api/state",
            "GET /a2a/",
            "POST /a2a/",
            "POST /api/",
            "GET / HTTP",
            "GET /favicon.ico",
            "FutureWarning:",
            "UserWarning:",
            "DeprecationWarning:",
            "from google.cloud.aiplatform",
            "from vertexai.preview",
            "client.rag.create_corpus",
            "client = agentplatform.Client",
            "import agentplatform",
            "Waiting for application startup",
            "Application startup complete",
            "Waiting for application shutdown",
            "Application shutdown complete",
            "Finished server process",
            "Shutting down",
            "Started server process",
            "Uvicorn running on",
            "logging.googleapis.com/diagnostic",
            "LogPingOpsAgent",
            'Invalid user "',
            "The request was not authenticated. Either allow unauthenticated invocations",
        )
        for token in noisy_substrings:
            if token in raw_text:
                return True
        return False

    def _normalize_gcp_entry(self, entry: Any) -> Optional[Dict[str, Any]]:
        """Transforms a real Google Cloud Logging LogEntry into an OTel-compatible AaaS telemetry dict."""
        severity = (entry.severity or "INFO").upper()
        res_type = getattr(entry.resource, "type", "gcp_resource") if entry.resource else "gcp_resource"
        labels = dict(getattr(entry.resource, "labels", {}) or {}) if entry.resource else {}
        log_name = getattr(entry, "log_name", "") or ""
        ts_iso = (
            entry.timestamp.isoformat()
            if getattr(entry, "timestamp", None)
            else datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        trace_raw = getattr(entry, "trace", None) or ""
        trace_id = trace_raw.split("/")[-1] if trace_raw else None
        span_id = getattr(entry, "span_id", None) or None

        payload = entry.payload
        if isinstance(payload, dict):
            raw_msg = (
                payload.get("message")
                or (payload.get("status", {}) or {}).get("message")
                or (payload.get("errorEvent", {}) or {}).get("message")
                or str(payload)
            )
        else:
            raw_msg = str(payload) if payload is not None else ""

        if self._is_routine_noise(raw_msg, log_name, severity):
            self._suppressed_routine_logs_count += 1
            return None

        # Skip internal AaaS audit/simulated entries when scanning project-wide logs
        if isinstance(payload, dict) and payload.get("event") in ("AAAS_GKE_ANOMALY", "AAAS_AUDIT_EVENT"):
            self._suppressed_routine_logs_count += 1
            return None

        # Real Cloud Run revision logs (`cloud_run_revision`)
        if res_type == "cloud_run_revision":
            service_name = labels.get("service_name") or labels.get("configuration_name") or "cloud-run-service"
            revision_name = labels.get("revision_name") or service_name
            location = labels.get("location") or "us-central1"

            if (
                "failed to start and listen on the port" in raw_msg
                or "HealthCheckContainerError" in raw_msg
                or "STARTUP TCP probe failed" in raw_msg
            ):
                return normalize_otel_anomaly(
                    log_id=f"gcp-cr-port-{service_name}",
                    signature_key=f"cloud_run:{service_name}:PORT_ERROR",
                    timestamp=ts_iso,
                    severity="ERROR",
                    scenario_id="cloud_run_port_error",
                    title=f"Cloud Run '{service_name}' Failed Startup Port Probe (8080)",
                    source="gcp:cloud_run_revision",
                    project_id=self.project_id,
                    cluster=location,
                    namespace="cloud-run",
                    workload=f"service/{service_name}",
                    pod=revision_name,
                    container=service_name,
                    error_code="HEALTHCHECK_CONTAINER_PORT_8080_ERROR",
                    message=raw_msg.strip(),
                    metrics_snapshot={"port": 8080, "ready_status": "False", "region": location},
                    recommended_kubectl=(
                        f"gcloud run services update {service_name} "
                        f"--region={location} --project={self.project_id} --port=8080 --timeout=300"
                    ),
                    recommended_action_type="cloud_run_port_remediation",
                    is_anomaly=True,
                    persisted_to_gcp=True,
                    cloud_provider="gcp",
                    trace_id=trace_id,
                    span_id=span_id,
                )

            if "no available instance" in raw_msg or "abort-request" in raw_msg:
                return normalize_otel_anomaly(
                    log_id=f"gcp-cr-scale-{service_name}",
                    signature_key=f"cloud_run:{service_name}:MAX_SCALE",
                    timestamp=ts_iso,
                    severity="ERROR",
                    scenario_id="cloud_run_scale_limit",
                    title=f"Cloud Run '{service_name}' Hit Instance Capacity Limit",
                    source="gcp:cloud_run_revision",
                    project_id=self.project_id,
                    cluster=location,
                    namespace="cloud-run",
                    workload=f"service/{service_name}",
                    pod=revision_name,
                    container=service_name,
                    error_code="CLOUD_RUN_NO_AVAILABLE_INSTANCE",
                    message=raw_msg.strip(),
                    metrics_snapshot={"active_instances": "1/1 (maxed)", "region": location},
                    recommended_kubectl=(
                        f"gcloud run services update {service_name} "
                        f"--region={location} --project={self.project_id} --max-instances=10"
                    ),
                    recommended_action_type="cloud_run_autoscale_up",
                    is_anomaly=True,
                    persisted_to_gcp=True,
                    cloud_provider="gcp",
                    trace_id=trace_id,
                    span_id=span_id,
                )

            if not raw_msg.strip():
                self._suppressed_routine_logs_count += 1
                return None

            is_anom = severity in ("ERROR", "CRITICAL")
            return normalize_otel_anomaly(
                log_id=f"gcp-{entry.insert_id or uuid.uuid4().hex[:8]}",
                signature_key=f"cloud_run:{service_name}:{severity}",
                timestamp=ts_iso,
                severity=severity,
                scenario_id="real_gcp_anomaly" if is_anom else "info",
                title=f"Cloud Run ({service_name}): {raw_msg.strip()[:70]}",
                source="gcp:cloud_run_revision",
                project_id=self.project_id,
                cluster=location,
                namespace="cloud-run",
                workload=f"service/{service_name}",
                pod=revision_name,
                container=service_name,
                error_code="CLOUD_RUN_RUNTIME_ERROR" if is_anom else "OK",
                message=raw_msg.strip(),
                metrics_snapshot={"region": location, "revision": revision_name},
                recommended_kubectl=(
                    f"gcloud run services update {service_name} --region={location} --project={self.project_id}"
                ),
                is_anomaly=is_anom,
                persisted_to_gcp=True,
                cloud_provider="gcp",
                trace_id=trace_id,
                span_id=span_id,
            )

        # Real Cloud Functions (`cloud_function`)
        if res_type == "cloud_function":
            fn_name = labels.get("function_name") or "cloud-function"
            region = labels.get("region") or "us-central1"
            is_anom = severity in ("ERROR", "CRITICAL") or "Traceback" in raw_msg or "NameError" in raw_msg
            return normalize_otel_anomaly(
                log_id=f"gcp-cf-{fn_name}",
                signature_key=f"cloud_function:{fn_name}:CODE_ERROR",
                timestamp=ts_iso,
                severity="ERROR" if is_anom else severity,
                scenario_id="cloud_function_error",
                title=f"Cloud Function '{fn_name}' Code Load Crash (NameError)",
                source="gcp:cloud_function",
                project_id=self.project_id,
                cluster=region,
                namespace="cloud-functions",
                workload=f"function/{fn_name}",
                pod=fn_name,
                container="functions-framework-py310",
                error_code="CLOUD_FUNCTION_SYNTAX_LOAD_ERROR",
                message=raw_msg.strip()[:500],
                metrics_snapshot={"function_name": fn_name, "region": region, "runtime": "python310"},
                recommended_kubectl=(
                    f"gcloud functions deploy {fn_name} --region={region} "
                    f"--project={self.project_id} --runtime=python310 --entry-point=main"
                ),
                recommended_action_type="cloud_function_redeploy_rollback",
                is_anomaly=is_anom,
                persisted_to_gcp=True,
                cloud_provider="gcp",
                trace_id=trace_id,
                span_id=span_id,
            )

        # Real Vertex AI Reasoning Engine logs (`aiplatform.googleapis.com/ReasoningEngine`)
        if res_type == "aiplatform.googleapis.com/ReasoningEngine":
            engine_id = labels.get("reasoning_engine_id") or "reasoning-engine"
            location = labels.get("location") or "us-west1"
            is_anom = severity in ("ERROR", "CRITICAL") or "Traceback" in raw_msg
            first_line = raw_msg.strip().splitlines()[-1] if raw_msg.strip() else "Reasoning Engine runtime error"
            return normalize_otel_anomaly(
                log_id=f"gcp-re-{engine_id[-6:]}",
                signature_key=f"reasoning_engine:{engine_id}:ADK_EXCEPTION",
                timestamp=ts_iso,
                severity="ERROR" if is_anom else severity,
                scenario_id="reasoning_engine_exception",
                title=f"Vertex AI Reasoning Engine ({engine_id[-6:]}) Task Exception",
                source="gcp:ReasoningEngine",
                project_id=self.project_id,
                cluster=location,
                namespace="vertex-ai",
                workload=f"reasoning-engine/{engine_id}",
                pod=f"re-worker-{engine_id[-4:]}",
                container="adk-a2a-executor",
                error_code="ADK_RUNNER_TASK_EXCEPTION",
                message=raw_msg.strip()[:500],
                metrics_snapshot={"reasoning_engine_id": engine_id, "region": location, "tail": first_line[:80]},
                recommended_kubectl=(
                    f"gcloud alpha ai reasoning-engines update {engine_id} "
                    f"--region={location} --project={self.project_id}"
                ),
                recommended_action_type="restart_reasoning_engine_worker",
                is_anomaly=is_anom,
                persisted_to_gcp=True,
                cloud_provider="gcp",
                trace_id=trace_id,
                span_id=span_id,
            )

        # Real Cloud SQL logs (`cloudsql_database`) or Cloud SQL Auth Proxy / DB connectivity errors (`cloud-sql-proxy`)
        if res_type == "cloudsql_database" or "cloud-sql-proxy" in log_name:
            db_id = labels.get("database_id") or "agent-triad:testdbinstance1"
            instance_short = db_id.split(":")[-1]
            raw_region = labels.get("region") or labels.get("zone") or "us-west1"
            region = raw_region.split("/")[-1]
            clean_msg = " ".join(raw_msg.strip().split())
            if not clean_msg or clean_msg == "None":
                self._suppressed_routine_logs_count += 1
                return None
            is_proxy_log = "cloud-sql-proxy" in log_name
            is_anom = (
                severity in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY")
                or "FATAL:" in clean_msg
                or "Re-occured" in clean_msg
                or "Connection Refused" in clean_msg
                or "timeout expired" in clean_msg
            )
            sig_suffix = clean_msg[:48] if is_proxy_log else "FATAL_OR_ERROR"
            return normalize_otel_anomaly(
                log_id=f"gcp-sql-{entry.insert_id or uuid.uuid4().hex[:8]}",
                signature_key=f"cloudsql:{db_id}:{sig_suffix}",
                timestamp=ts_iso,
                severity=severity if severity in ("ERROR", "CRITICAL", "ALERT") else "ERROR",
                scenario_id="cloudsql_anomaly" if is_anom else "info",
                title=f"Cloud SQL ({instance_short}): {clean_msg[:65]}",
                source="gcp:cloudsql_database",
                project_id=self.project_id,
                cluster=region,
                namespace="cloud-sql",
                workload=f"cloudsql/{instance_short}",
                pod=instance_short,
                container="cloud-sql-proxy" if is_proxy_log else "postgres",
                error_code=(
                    "CLOUDSQL_PROXY_CONNECTION_TIMEOUT"
                    if is_proxy_log
                    else ("CLOUDSQL_POSTGRES_FATAL" if is_anom else "POSTGRES_TELEMETRY")
                ),
                message=clean_msg,
                metrics_snapshot={"database_id": db_id, "region": region, "log_source": log_name.split("/")[-1]},
                recommended_kubectl=(
                    f"gcloud sql instances patch {instance_short} --activation-policy=ALWAYS --project={self.project_id}"
                ),
                is_anomaly=is_anom,
                persisted_to_gcp=True,
                cloud_provider="gcp",
                trace_id=trace_id,
                span_id=span_id,
                extra_attributes={"db.system": "postgresql", "db.instance.id": db_id},
            )

        # Real GCE / GKE / Other GCP resource logs
        is_anom = severity in ("ERROR", "CRITICAL")
        clean_msg = " ".join(raw_msg.strip().split())
        if not clean_msg:
            return None
        workload_name = (
            labels.get("instance_id")
            or labels.get("pod_name")
            or labels.get("container_name")
            or res_type
        )
        return normalize_otel_anomaly(
            log_id=f"gcp-{entry.insert_id or uuid.uuid4().hex[:8]}",
            signature_key=f"{res_type}:{workload_name}:{severity}",
            timestamp=ts_iso,
            severity=severity,
            scenario_id="real_gcp_anomaly" if is_anom else "info",
            title=f"GCP {res_type} ({workload_name}): {clean_msg[:65]}",
            source=f"gcp:{res_type}",
            project_id=self.project_id,
            cluster=labels.get("zone") or labels.get("location") or "us-central1",
            namespace=labels.get("namespace_name") or "gcp-infra",
            workload=f"{res_type}/{workload_name}",
            pod=str(workload_name),
            container=res_type,
            error_code=f"GCP_{res_type.upper()}_ALERT" if is_anom else "GCP_TELEMETRY",
            message=clean_msg[:500],
            metrics_snapshot=labels,
            recommended_kubectl=f"gcloud logging read 'resource.type=\"{res_type}\"' --project={self.project_id} --limit=5",
            is_anomaly=is_anom,
            persisted_to_gcp=True,
            cloud_provider="gcp",
            trace_id=trace_id,
            span_id=span_id,
        )

    def record_audit_event(
        self,
        incident_id: str,
        event_type: str,
        service: str,
        issue_title: str,
        occurred_at: str,
        action_status: str,
        approved_by: Optional[str] = None,
        approved_at: Optional[str] = None,
        command: Optional[str] = None,
        jit_token_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Writes an immutable audit trail entry to Google Cloud Logging (`AAAS_AUDIT_EVENT`)."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_payload: Dict[str, Any] = {
            "event": "AAAS_AUDIT_EVENT",
            "audit_id": f"audit-{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "event_type": event_type,
            "service": service,
            "issue_title": issue_title,
            "occurred_at": occurred_at,
            "action_status": action_status,
            "approved_by": approved_by,
            "approved_at": approved_at,
            "command": command,
            "jit_token_id": jit_token_id,
            "recorded_at": now_iso,
            "persisted_to_gcp": False,
        }
        if self._logger is not None:
            try:
                self._logger.log_struct(audit_payload, severity="NOTICE")
                audit_payload["persisted_to_gcp"] = True
            except Exception as exc:
                audit_payload["gcp_write_warning"] = str(exc)
        return audit_payload

    def record_system_log(
        self,
        severity: str,
        workload: str,
        message: str,
        namespace: str = "aaas-control-plane",
        cluster: str = "gke-prod-us-central1",
    ) -> Dict[str, Any]:
        """Appends a verification or remediation log entry to Cloud Logging and local buffer."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = normalize_otel_anomaly(
            log_id=f"log-{uuid.uuid4().hex[:8]}",
            signature_key=f"watchdog:{workload}:{severity}",
            timestamp=now_iso,
            severity=severity,
            scenario_id="watchdog_telemetry",
            title=message[:75],
            source="aaas-watchdog",
            project_id=self.project_id,
            cluster=cluster,
            namespace=namespace,
            workload=workload,
            pod=workload.split("/")[-1],
            container="aaas-watchdog",
            error_code="OK",
            message=message,
            is_anomaly=False,
            persisted_to_gcp=False,
            cloud_provider="gcp",
        )
        if self._logger is not None:
            try:
                self._logger.log_struct(entry, severity=severity)
                entry["persisted_to_gcp"] = True
            except Exception:
                pass
        self._local_logs.insert(0, entry)
        return entry

    def fetch_recent_logs(
        self,
        limit: int = 25,
        poll_remote: bool = True,
        force: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Polls real Google Cloud Logging across project `agent-triad` (with a 10s TTL cache
        unless `force=True`) and merges unseen real logs & anomalies into the stream.
        """
        now_ts = time.time()
        should_poll = poll_remote and self._client is not None and (force or (now_ts - self._last_poll_time >= 10.0))

        if should_poll:
            self._last_poll_time = now_ts
            try:
                # 0. Prioritize real Cloud SQL (`testdbinstance1`) and Cloud SQL Auth Proxy FATAL/ALERT/ERROR logs
                cloudsql_anomaly_filter = (
                    '(resource.type="cloudsql_database" AND (severity>=WARNING OR textPayload:"FATAL")) '
                    'OR (logName:"cloud-sql-proxy" AND severity>=WARNING)'
                )
                # 1. Query real warnings/errors across Cloud SQL, GCE VMs, Cloud Run, Cloud Functions & ReasoningEngine
                anomaly_filter = (
                    '(resource.type="cloudsql_database" OR resource.type="gce_instance" '
                    'OR resource.type="cloud_run_revision" OR resource.type="cloud_function" '
                    'OR resource.type="aiplatform.googleapis.com/ReasoningEngine") '
                    'AND severity>=WARNING '
                    'AND NOT protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
                    'AND NOT logName:"GCEGuestAgent" '
                    f'AND NOT logName="projects/{self.project_id}/logs/{self.log_name}"'
                )
                # 2. Query recent general operational logs (Cloud SQL, Cloud Run startup/system, GCE)
                telemetry_filter = (
                    '(resource.type="cloudsql_database" OR resource.type="cloud_run_revision" '
                    'OR resource.type="gce_instance" OR resource.type="aiplatform.googleapis.com/ReasoningEngine") '
                    'AND NOT protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
                    'AND NOT logName:"ops-agent-health"'
                )

                raw_entries = []
                for flt, max_res in (
                    (cloudsql_anomaly_filter, 15),
                    (anomaly_filter, 25),
                    (telemetry_filter, 25),
                ):
                    try:
                        raw_entries.extend(
                            list(
                                self._client.list_entries(
                                    filter_=flt,
                                    order_by=gcp_logging.DESCENDING,
                                    max_results=max_res,
                                )
                            )
                        )
                    except Exception:
                        pass

                known_ids = {item.get("log_id") for item in self._local_logs}
                existing_sig_ts = {
                    item.get("signature_key"): str(item.get("timestamp", ""))
                    for item in self._local_logs
                    if item.get("signature_key") and item.get("is_anomaly")
                }
                batch_sigs: set[str] = set()

                new_items: List[Dict[str, Any]] = []
                for entry in raw_entries:
                    norm = self._normalize_gcp_entry(entry)
                    if not norm:
                        continue
                    lid = norm["log_id"]
                    sig = norm.get("signature_key")
                    norm_ts = str(norm.get("timestamp", ""))
                    if lid in known_ids:
                        continue
                    if norm.get("is_anomaly") and sig:
                        if sig in batch_sigs:
                            self._suppressed_routine_logs_count += 1
                            continue
                        prev_ts = existing_sig_ts.get(sig)
                        if prev_ts and norm_ts <= prev_ts:
                            self._suppressed_routine_logs_count += 1
                            continue
                        batch_sigs.add(sig)
                        existing_sig_ts[sig] = norm_ts
                    known_ids.add(lid)
                    new_items.append(norm)

                if new_items:
                    self._local_logs.extend(new_items)
                self._local_logs.sort(
                    key=lambda x: (1 if x.get("is_anomaly") else 0, x.get("timestamp", "")),
                    reverse=True,
                )
            except Exception as exc:
                self._gcp_status_detail = f"GCP Poll warning: {exc}"

        return self._local_logs[:limit]

    def get_status(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "telemetry_provider_mode": "gcp",
            "project_id": self.project_id,
            "log_name": self.log_name,
            "connected": self._gcp_connected,
            "detail": self._gcp_status_detail,
            "suppressed_routine_logs": self._suppressed_routine_logs_count,
        }
