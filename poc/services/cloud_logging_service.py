"""
Hybrid GCP Cloud Logging Service for AgentTriad PoC.

Reads and writes real structured GKE incident logs to Google Cloud Logging
in project `stack-cognizant` (`logName: aaas_gke_incidents`), while maintaining
an edge telemetry ring buffer for instant UI visualization and offline resilience.
"""

from __future__ import annotations

import datetime
import os
import uuid
from typing import Any, Dict, List, Optional

try:
    from google.cloud import logging as gcp_logging
except ImportError:
    gcp_logging = None

from services.gcp_auth import get_gcp_credentials


PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
LOG_NAME = os.getenv("AAAS_LOG_NAME", "aaas_gke_incidents")

# Pre-configured realistic GKE failure scenarios for 1-click simulation
GKE_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "oom_killed": {
        "scenario_id": "oom_killed",
        "title": "GKE Pod OOMKilled (CrashLoopBackOff)",
        "severity": "CRITICAL",
        "cluster": "gke-prod-us-central1",
        "namespace": "prod-payments",
        "workload": "deployment/payment-checkout-service",
        "pod": "payment-checkout-service-6b8f9d4c-x92lq",
        "container": "checkout-worker",
        "error_code": "EXIT_CODE_137_OOMKILLED",
        "message": (
            "Container checkout-worker in pod payment-checkout-service-6b8f9d4c-x92lq "
            "terminated with exit code 137 (OOMKilled). Memory usage spiked to 512Mi/512Mi "
            "limit during flash checkout surge. Back-off restarting failed container."
        ),
        "metrics_snapshot": {
            "memory_utilization_pct": 100.0,
            "memory_limit": "512Mi",
            "restart_count_5m": 7,
            "p99_latency_ms": 3850,
            "error_rate_pct": 18.4,
        },
        "recommended_kubectl": (
            "kubectl set resources deployment/payment-checkout-service "
            "-n prod-payments -c checkout-worker --limits=memory=1Gi,cpu=1000m --requests=memory=768Mi"
        ),
        "recommended_action_type": "vertical_scale_memory",
    },
    "cpu_throttling": {
        "scenario_id": "cpu_throttling",
        "title": "GKE Pod CPU Throttling & JVM Thread Contention",
        "severity": "ERROR",
        "cluster": "gke-prod-us-central1",
        "namespace": "prod-storefront",
        "workload": "deployment/gke-web-v2",
        "pod": "gke-web-v2-7d9f8b55-k4m2p",
        "container": "web-api",
        "error_code": "CFS_QUOTA_CPU_THROTTLED",
        "message": (
            "Heuristic breach: Pod gke-web-v2-7d9f8b55-k4m2p CPU threshold > 95% for 45s. "
            "High thread contention in worker pool (PID 40); CFS quota throttled 84% of scheduling periods."
        ),
        "metrics_snapshot": {
            "cpu_utilization_pct": 97.2,
            "cfs_throttled_periods_pct": 84.0,
            "current_replicas": 2,
            "target_replicas": 6,
            "p99_latency_ms": 4210,
            "error_rate_pct": 9.6,
        },
        "recommended_kubectl": (
            "kubectl scale deployment/gke-web-v2 -n prod-storefront --replicas=6"
        ),
        "recommended_action_type": "horizontal_scale_replicas",
    },
    "image_pull_backoff": {
        "scenario_id": "image_pull_backoff",
        "title": "Canary Rollout ImagePullBackOff",
        "severity": "ERROR",
        "cluster": "gke-prod-us-central1",
        "namespace": "prod-orders",
        "workload": "deployment/order-processor",
        "pod": "order-processor-canary-5c4d77b-v8n1z",
        "container": "order-engine",
        "error_code": "ERR_IMAGE_PULL_MANIFEST_UNKNOWN",
        "message": (
            "Failed to pull image 'us-central1-docker.pkg.dev/stack-cognizant/prod/order-processor:v2.4.9-rc': "
            "rpc error: code = NotFound desc = failed to pull and unpack image: manifest unknown. "
            "Canary pods stuck in ImagePullBackOff."
        ),
        "metrics_snapshot": {
            "ready_replicas": "2/4",
            "canary_failure_rate_pct": 100.0,
            "last_good_revision": "revision=14 (v2.4.8-stable)",
            "p99_latency_ms": 1450,
            "error_rate_pct": 12.1,
        },
        "recommended_kubectl": (
            "kubectl rollout undo deployment/order-processor -n prod-orders --to-revision=14"
        ),
        "recommended_action_type": "canary_rollout_undo",
    },
}


class CloudLoggingService:
    """Manages live GCP Cloud Logging I/O and real project-wide log monitoring in `agent-triad`."""

    def __init__(self, project_id: str = PROJECT_ID) -> None:
        self.project_id = project_id
        self.log_name = LOG_NAME
        self._client: Optional[Any] = None
        self._logger: Optional[Any] = None
        self.gcp_connected = False
        self.gcp_status_detail = "Initializing"
        self._local_logs: List[Dict[str, Any]] = []
        self.suppressed_routine_logs_count = 0
        self._last_poll_time: float = 0.0
        self._init_gcp_client()
        # Perform initial real GCP log fetch on startup
        self.fetch_recent_logs(limit=25, poll_gcp=True, force=True)

    def _init_gcp_client(self) -> None:
        if gcp_logging is None:
            self.gcp_connected = False
            self.gcp_status_detail = "google-cloud-logging not installed; using local buffer"
            return
        try:
            creds = get_gcp_credentials()
            self._client = gcp_logging.Client(project=self.project_id, credentials=creds)
            self._logger = self._client.logger(self.log_name)
            self.gcp_connected = True
            self.gcp_status_detail = f"Live GCP Cloud Logging active (project: {self.project_id})"
        except Exception as exc:  # pragma: no cover - graceful fallback
            self.gcp_connected = False
            self.gcp_status_detail = f"Local fallback active ({exc})"

    def _is_routine_noise(self, raw_text: str, log_name: str, severity: str) -> bool:
        """Filters routine health checks, /api/state polling, and library deprecation warnings at the edge."""
        if not raw_text or raw_text == "None":
            if severity in ("DEFAULT", "INFO", "NOTICE", None, ""):
                return True
        noisy_substrings = (
            "GET /api/state",
            "GET /a2a/",
            "POST /a2a/",
            "GET / HTTP",
            "GET /favicon.ico",
            "FutureWarning:",
            "UserWarning:",
            "DeprecationWarning:",
            "from google.cloud.aiplatform",
            "from vertexai.preview",
            "client.rag.create_corpus",
            "import agentplatform",
            "Waiting for application startup",
            "Application startup complete",
            "Started server process",
            "Uvicorn running on",
        )
        for token in noisy_substrings:
            if token in raw_text:
                return True
        return False

    def _normalize_gcp_entry(self, entry: Any) -> Optional[Dict[str, Any]]:
        """Transforms a real Google Cloud Logging LogEntry into a normalized AaaS telemetry dictionary."""
        severity = (entry.severity or "INFO").upper()
        res_type = getattr(entry.resource, "type", "gcp_resource") if entry.resource else "gcp_resource"
        labels = dict(getattr(entry.resource, "labels", {}) or {}) if entry.resource else {}
        log_name = getattr(entry, "log_name", "") or ""
        ts_iso = (
            entry.timestamp.isoformat()
            if getattr(entry, "timestamp", None)
            else datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

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
            self.suppressed_routine_logs_count += 1
            return None

        # Structured AaaS incident logs written to `aaas_gke_incidents`
        if isinstance(payload, dict) and (
            payload.get("event") == "AAAS_GKE_ANOMALY" or payload.get("log_id")
        ):
            lid = payload.get("log_id") or f"gcp-{entry.insert_id}"
            scen_id = payload.get("scenario_id")
            if not scen_id:
                err_code = payload.get("error_code", "")
                if "OOM" in err_code or "137" in err_code:
                    scen_id = "oom_killed"
                elif "CPU" in err_code or "CFS" in err_code:
                    scen_id = "cpu_throttling"
                elif "IMAGE" in err_code:
                    scen_id = "image_pull_backoff"
                else:
                    scen_id = "oom_killed"
            scen_defaults = GKE_SCENARIOS.get(scen_id, GKE_SCENARIOS["oom_killed"])
            is_anom = bool(payload.get("is_anomaly", severity in ("ERROR", "CRITICAL")))
            return {
                "log_id": lid,
                "signature_key": f"{payload.get('workload', 'gke')}:{payload.get('error_code', scen_id)}",
                "timestamp": ts_iso,
                "severity": severity,
                "scenario_id": scen_id,
                "title": payload.get("title") or scen_defaults["title"],
                "source": payload.get("source") or f"gcp:{res_type}",
                "project_id": self.project_id,
                "cluster": payload.get("cluster") or labels.get("location") or "us-central1",
                "namespace": payload.get("namespace") or labels.get("service_name") or "default",
                "workload": payload.get("workload") or labels.get("revision_name") or "k8s_container",
                "pod": payload.get("pod") or labels.get("revision_name") or "pod-0",
                "container": payload.get("container") or "app",
                "error_code": payload.get("error_code") or scen_defaults["error_code"],
                "message": raw_msg,
                "metrics_snapshot": payload.get("metrics_snapshot") or scen_defaults["metrics_snapshot"],
                "recommended_kubectl": payload.get("recommended_kubectl") or scen_defaults["recommended_kubectl"],
                "recommended_action_type": payload.get("recommended_action_type") or scen_defaults["recommended_action_type"],
                "is_anomaly": is_anom,
                "persisted_to_gcp": True,
            }

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
                return {
                    "log_id": f"gcp-cr-port-{service_name}",
                    "signature_key": f"cloud_run:{service_name}:PORT_ERROR",
                    "timestamp": ts_iso,
                    "severity": "ERROR",
                    "scenario_id": "cloud_run_port_error",
                    "title": f"Cloud Run '{service_name}' Failed Startup Port Probe (8080)",
                    "source": "gcp:cloud_run_revision",
                    "project_id": self.project_id,
                    "cluster": location,
                    "namespace": "cloud-run",
                    "workload": f"service/{service_name}",
                    "pod": revision_name,
                    "container": service_name,
                    "error_code": "HEALTHCHECK_CONTAINER_PORT_8080_ERROR",
                    "message": raw_msg.strip(),
                    "metrics_snapshot": {"port": 8080, "ready_status": "False", "region": location},
                    "recommended_kubectl": (
                        f"gcloud run services update {service_name} "
                        f"--region={location} --project={self.project_id} --port=8080 --timeout=300"
                    ),
                    "recommended_action_type": "cloud_run_port_remediation",
                    "is_anomaly": True,
                    "persisted_to_gcp": True,
                }

            if "no available instance" in raw_msg or "abort-request" in raw_msg:
                return {
                    "log_id": f"gcp-cr-scale-{service_name}",
                    "signature_key": f"cloud_run:{service_name}:MAX_SCALE",
                    "timestamp": ts_iso,
                    "severity": "ERROR",
                    "scenario_id": "cloud_run_scale_limit",
                    "title": f"Cloud Run '{service_name}' Hit Instance Capacity Limit",
                    "source": "gcp:cloud_run_revision",
                    "project_id": self.project_id,
                    "cluster": location,
                    "namespace": "cloud-run",
                    "workload": f"service/{service_name}",
                    "pod": revision_name,
                    "container": service_name,
                    "error_code": "CLOUD_RUN_NO_AVAILABLE_INSTANCE",
                    "message": raw_msg.strip(),
                    "metrics_snapshot": {"active_instances": "1/1 (maxed)", "region": location},
                    "recommended_kubectl": (
                        f"gcloud run services update {service_name} "
                        f"--region={location} --project={self.project_id} --max-instances=10"
                    ),
                    "recommended_action_type": "cloud_run_autoscale_up",
                    "is_anomaly": True,
                    "persisted_to_gcp": True,
                }

            if not raw_msg.strip():
                self.suppressed_routine_logs_count += 1
                return None

            is_anom = severity in ("ERROR", "CRITICAL")
            return {
                "log_id": f"gcp-{entry.insert_id or uuid.uuid4().hex[:8]}",
                "signature_key": f"cloud_run:{service_name}:{severity}",
                "timestamp": ts_iso,
                "severity": severity,
                "scenario_id": "real_gcp_anomaly" if is_anom else "info",
                "title": f"Cloud Run ({service_name}): {raw_msg.strip()[:70]}",
                "source": "gcp:cloud_run_revision",
                "project_id": self.project_id,
                "cluster": location,
                "namespace": "cloud-run",
                "workload": f"service/{service_name}",
                "pod": revision_name,
                "container": service_name,
                "error_code": "CLOUD_RUN_RUNTIME_ERROR" if is_anom else "OK",
                "message": raw_msg.strip(),
                "metrics_snapshot": {"region": location, "revision": revision_name},
                "recommended_kubectl": (
                    f"gcloud run services update {service_name} --region={location} --project={self.project_id}"
                ),
                "is_anomaly": is_anom,
                "persisted_to_gcp": True,
            }

        # Real Cloud Functions (`cloud_function`)
        if res_type == "cloud_function":
            fn_name = labels.get("function_name") or "cloud-function"
            region = labels.get("region") or "us-central1"
            is_anom = severity in ("ERROR", "CRITICAL") or "Traceback" in raw_msg or "NameError" in raw_msg
            return {
                "log_id": f"gcp-cf-{fn_name}",
                "signature_key": f"cloud_function:{fn_name}:CODE_ERROR",
                "timestamp": ts_iso,
                "severity": "ERROR" if is_anom else severity,
                "scenario_id": "cloud_function_error",
                "title": f"Cloud Function '{fn_name}' Code Load Crash (NameError)",
                "source": "gcp:cloud_function",
                "project_id": self.project_id,
                "cluster": region,
                "namespace": "cloud-functions",
                "workload": f"function/{fn_name}",
                "pod": fn_name,
                "container": "functions-framework-py310",
                "error_code": "CLOUD_FUNCTION_SYNTAX_LOAD_ERROR",
                "message": raw_msg.strip()[:500],
                "metrics_snapshot": {"function_name": fn_name, "region": region, "runtime": "python310"},
                "recommended_kubectl": (
                    f"gcloud functions deploy {fn_name} --region={region} "
                    f"--project={self.project_id} --runtime=python310 --entry-point=main"
                ),
                "recommended_action_type": "cloud_function_redeploy_rollback",
                "is_anomaly": is_anom,
                "persisted_to_gcp": True,
            }

        # Real Vertex AI Reasoning Engine logs (`aiplatform.googleapis.com/ReasoningEngine`)
        if res_type == "aiplatform.googleapis.com/ReasoningEngine":
            engine_id = labels.get("reasoning_engine_id") or "reasoning-engine"
            location = labels.get("location") or "us-west1"
            is_anom = severity in ("ERROR", "CRITICAL") or "Traceback" in raw_msg
            first_line = raw_msg.strip().splitlines()[-1] if raw_msg.strip() else "Reasoning Engine runtime error"
            return {
                "log_id": f"gcp-re-{engine_id[-6:]}",
                "signature_key": f"reasoning_engine:{engine_id}:ADK_EXCEPTION",
                "timestamp": ts_iso,
                "severity": "ERROR" if is_anom else severity,
                "scenario_id": "reasoning_engine_exception",
                "title": f"Vertex AI Reasoning Engine ({engine_id[-6:]}) Task Exception",
                "source": "gcp:ReasoningEngine",
                "project_id": self.project_id,
                "cluster": location,
                "namespace": "vertex-ai",
                "workload": f"reasoning-engine/{engine_id}",
                "pod": f"re-worker-{engine_id[-4:]}",
                "container": "adk-a2a-executor",
                "error_code": "ADK_RUNNER_TASK_EXCEPTION",
                "message": raw_msg.strip()[:500],
                "metrics_snapshot": {"reasoning_engine_id": engine_id, "region": location, "tail": first_line[:80]},
                "recommended_kubectl": (
                    f"gcloud alpha ai reasoning-engines update {engine_id} "
                    f"--region={location} --project={self.project_id}"
                ),
                "recommended_action_type": "restart_reasoning_engine_worker",
                "is_anomaly": is_anom,
                "persisted_to_gcp": True,
            }

        # Real Cloud SQL logs (`cloudsql_database`)
        if res_type == "cloudsql_database":
            db_id = labels.get("database_id") or "agent-triad:postgres"
            region = labels.get("region") or "us-west1"
            is_anom = severity in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY")
            clean_msg = " ".join(raw_msg.strip().split())
            return {
                "log_id": f"gcp-sql-{entry.insert_id or uuid.uuid4().hex[:8]}",
                "signature_key": f"cloudsql:{db_id}:{severity}",
                "timestamp": ts_iso,
                "severity": severity,
                "scenario_id": "cloudsql_anomaly" if is_anom else "info",
                "title": f"Cloud SQL ({db_id.split(':')[-1]}): {clean_msg[:65]}",
                "source": "gcp:cloudsql_database",
                "project_id": self.project_id,
                "cluster": region,
                "namespace": "cloud-sql",
                "workload": f"cloudsql/{db_id}",
                "pod": db_id.split(":")[-1],
                "container": "postgres",
                "error_code": "CLOUDSQL_POSTGRES_ERROR" if is_anom else "POSTGRES_TELEMETRY",
                "message": clean_msg,
                "metrics_snapshot": {"database_id": db_id, "region": region},
                "recommended_kubectl": f"gcloud sql instances restart {db_id.split(':')[-1]} --project={self.project_id}",
                "is_anomaly": is_anom,
                "persisted_to_gcp": True,
            }

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
        return {
            "log_id": f"gcp-{entry.insert_id or uuid.uuid4().hex[:8]}",
            "signature_key": f"{res_type}:{workload_name}:{severity}",
            "timestamp": ts_iso,
            "severity": severity,
            "scenario_id": "real_gcp_anomaly" if is_anom else "info",
            "title": f"GCP {res_type} ({workload_name}): {clean_msg[:65]}",
            "source": f"gcp:{res_type}",
            "project_id": self.project_id,
            "cluster": labels.get("zone") or labels.get("location") or "us-central1",
            "namespace": labels.get("namespace_name") or "gcp-infra",
            "workload": f"{res_type}/{workload_name}",
            "pod": str(workload_name),
            "container": res_type,
            "error_code": f"GCP_{res_type.upper()}_ALERT" if is_anom else "GCP_TELEMETRY",
            "message": clean_msg[:500],
            "metrics_snapshot": labels,
            "recommended_kubectl": f"gcloud logging read 'resource.type=\"{res_type}\"' --project={self.project_id} --limit=5",
            "is_anomaly": is_anom,
            "persisted_to_gcp": True,
        }

    def inject_simulated_gke_error(
        self, scenario_id: str = "oom_killed", custom_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Writes a structured GKE anomaly log to live GCP Cloud Logging + local stream."""
        scenario = GKE_SCENARIOS.get(scenario_id, GKE_SCENARIOS["oom_killed"]).copy()
        if custom_message:
            scenario["message"] = custom_message

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        log_id = f"gke-inc-{uuid.uuid4().hex[:8]}"

        log_payload: Dict[str, Any] = {
            "log_id": log_id,
            "signature_key": f"{scenario['workload']}:{scenario['error_code']}:{log_id}",
            "timestamp": now_iso,
            "severity": scenario["severity"],
            "scenario_id": scenario["scenario_id"],
            "title": scenario["title"],
            "source": "gcp-cloud-logging",
            "project_id": self.project_id,
            "cluster": scenario["cluster"],
            "namespace": scenario["namespace"],
            "workload": scenario["workload"],
            "pod": scenario["pod"],
            "container": scenario["container"],
            "error_code": scenario["error_code"],
            "message": scenario["message"],
            "metrics_snapshot": scenario["metrics_snapshot"],
            "recommended_kubectl": scenario["recommended_kubectl"],
            "recommended_action_type": scenario["recommended_action_type"],
            "is_anomaly": True,
            "persisted_to_gcp": False,
        }

        if self._logger is not None:
            try:
                self._logger.log_struct(
                    {
                        "event": "AAAS_GKE_ANOMALY",
                        "log_id": log_id,
                        "scenario_id": scenario["scenario_id"],
                        "title": scenario["title"],
                        "cluster": scenario["cluster"],
                        "namespace": scenario["namespace"],
                        "workload": scenario["workload"],
                        "pod": scenario["pod"],
                        "container": scenario["container"],
                        "error_code": scenario["error_code"],
                        "message": scenario["message"],
                        "metrics_snapshot": scenario["metrics_snapshot"],
                        "recommended_kubectl": scenario["recommended_kubectl"],
                        "recommended_action_type": scenario["recommended_action_type"],
                        "is_anomaly": True,
                        "timestamp": now_iso,
                    },
                    severity=scenario["severity"],
                )
                log_payload["persisted_to_gcp"] = True
            except Exception as exc:
                log_payload["gcp_write_warning"] = str(exc)

        self._local_logs.insert(0, log_payload)
        return log_payload

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
        entry = {
            "log_id": f"log-{uuid.uuid4().hex[:8]}",
            "timestamp": now_iso,
            "severity": severity,
            "title": message[:75],
            "source": "aaas-watchdog",
            "project_id": self.project_id,
            "cluster": cluster,
            "namespace": namespace,
            "workload": workload,
            "message": message,
            "is_anomaly": False,
            "persisted_to_gcp": False,
        }
        if self._logger is not None:
            try:
                self._logger.log_struct(entry, severity=severity)
                entry["persisted_to_gcp"] = True
            except Exception:
                pass
        self._local_logs.insert(0, entry)
        return entry

    def fetch_recent_logs(
        self, limit: int = 25, poll_gcp: bool = True, force: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Polls real Google Cloud Logging across project `agent-triad` (with a 10s TTL cache
        unless `force=True`) and merges unseen real logs & anomalies into the stream.
        """
        import time

        now_ts = time.time()
        should_poll = poll_gcp and self._client is not None and (force or (now_ts - self._last_poll_time >= 10.0))

        if should_poll:
            self._last_poll_time = now_ts
            try:
                # 1. Query real project-wide warnings/errors (Cloud Run, ReasoningEngine, CloudSQL, GKE, etc.)
                anomaly_filter = (
                    'severity>=WARNING '
                    'AND NOT protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
                    f'AND NOT logName="projects/{self.project_id}/logs/{self.log_name}"'
                )
                # 2. Query recent general operational logs (Cloud SQL, Cloud Run startup/system, GCE)
                telemetry_filter = (
                    '(resource.type="cloudsql_database" OR resource.type="cloud_run_revision" '
                    'OR resource.type="gce_instance" OR resource.type="aiplatform.googleapis.com/ReasoningEngine") '
                    'AND NOT protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"'
                )

                raw_entries = []
                try:
                    raw_entries.extend(
                        list(
                            self._client.list_entries(
                                filter_=anomaly_filter,
                                order_by=gcp_logging.DESCENDING,
                                max_results=20,
                            )
                        )
                    )
                except Exception:
                    pass

                try:
                    raw_entries.extend(
                        list(
                            self._client.list_entries(
                                filter_=telemetry_filter,
                                order_by=gcp_logging.DESCENDING,
                                max_results=25,
                            )
                        )
                    )
                except Exception:
                    pass

                known_ids = {item.get("log_id") for item in self._local_logs}
                known_sigs = {
                    item.get("signature_key")
                    for item in self._local_logs
                    if item.get("signature_key") and item.get("is_anomaly")
                }

                new_items: List[Dict[str, Any]] = []
                for entry in raw_entries:
                    norm = self._normalize_gcp_entry(entry)
                    if not norm:
                        continue
                    lid = norm["log_id"]
                    sig = norm.get("signature_key")
                    if lid in known_ids:
                        continue
                    if norm.get("is_anomaly") and sig and sig in known_sigs:
                        # Deduplicate multi-line stack traces from the same real anomaly
                        self.suppressed_routine_logs_count += 1
                        continue
                    known_ids.add(lid)
                    if norm.get("is_anomaly") and sig:
                        known_sigs.add(sig)
                    new_items.append(norm)

                if new_items:
                    self._local_logs.extend(new_items)
                    self._local_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            except Exception as exc:
                self.gcp_status_detail = f"GCP Poll warning: {exc}"

        return self._local_logs[:limit]

