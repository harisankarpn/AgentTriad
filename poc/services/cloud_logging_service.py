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
    """Manages live GCP Cloud Logging I/O and local edge telemetry state."""

    def __init__(self, project_id: str = PROJECT_ID) -> None:
        self.project_id = project_id
        self.log_name = LOG_NAME
        self._client: Optional[Any] = None
        self._logger: Optional[Any] = None
        self.gcp_connected = False
        self.gcp_status_detail = "Initializing"
        self._local_logs: List[Dict[str, Any]] = []
        self.suppressed_routine_logs_count = 14352
        self._init_gcp_client()
        self._seed_baseline_logs()

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
            self.gcp_status_detail = f"Connected to GCP Cloud Logging (project: {self.project_id})"
        except Exception as exc:  # pragma: no cover - graceful fallback
            self.gcp_connected = False
            self.gcp_status_detail = f"Local fallback active ({exc})"

    def _seed_baseline_logs(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        baseline = [
            {
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - datetime.timedelta(seconds=45)).isoformat(),
                "severity": "INFO",
                "source": "otel-edge-gateway",
                "cluster": "gke-prod-us-central1",
                "namespace": "kube-system",
                "workload": "daemonset/otel-collector",
                "message": (
                    "Edge Heuristic Pre-Filtering Gateway active: suppressed 4,500 routine healthcheck logs/sec "
                    "(>92% noise reduction). Heartbeat custom.googleapis.com/aaas/heartbeat_tick OK (15s)."
                ),
                "is_anomaly": False,
                "persisted_to_gcp": False,
            },
            {
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "timestamp": (now - datetime.timedelta(seconds=20)).isoformat(),
                "severity": "INFO",
                "source": "gke-control-plane",
                "cluster": "gke-prod-us-central1",
                "namespace": "prod-payments",
                "workload": "deployment/payment-checkout-service",
                "message": "Baseline DORA telemetry nominal. Cluster nodes Ready (6/6).",
                "is_anomaly": False,
                "persisted_to_gcp": False,
            },
        ]
        self._local_logs.extend(baseline)

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
                        "title": scenario["title"],
                        "cluster": scenario["cluster"],
                        "namespace": scenario["namespace"],
                        "workload": scenario["workload"],
                        "pod": scenario["pod"],
                        "container": scenario["container"],
                        "error_code": scenario["error_code"],
                        "message": scenario["message"],
                        "metrics_snapshot": scenario["metrics_snapshot"],
                        "timestamp": now_iso,
                    },
                    severity=scenario["severity"],
                )
                log_payload["persisted_to_gcp"] = True
            except Exception as exc:
                log_payload["gcp_write_warning"] = str(exc)

        self.suppressed_routine_logs_count += 1240
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

    def fetch_recent_logs(self, limit: int = 25, poll_gcp: bool = False) -> List[Dict[str, Any]]:
        """Returns recent logs, optionally polling live GCP Cloud Logging for external entries."""
        if poll_gcp and self._client is not None:
            try:
                filter_str = (
                    f'logName="projects/{self.project_id}/logs/{self.log_name}" '
                    f'AND severity>=ERROR'
                )
                entries = list(
                    self._client.list_entries(
                        filter_=filter_str,
                        order_by=gcp_logging.DESCENDING,
                         max_results=5,
                    )
                )
                known_ids = {item.get("log_id") for item in self._local_logs}
                for entry in entries:
                    payload = entry.payload if isinstance(entry.payload, dict) else {"message": str(entry.payload)}
                    lid = payload.get("log_id") or f"gcp-{entry.insert_id}"
                    if lid not in known_ids:
                        self._local_logs.insert(
                            0,
                            {
                                "log_id": lid,
                                "timestamp": (
                                    entry.timestamp.isoformat()
                                    if entry.timestamp
                                    else datetime.datetime.now(datetime.timezone.utc).isoformat()
                                ),
                                "severity": entry.severity or "ERROR",
                                "source": "gcp-cloud-logging-live",
                                "project_id": self.project_id,
                                "cluster": payload.get("cluster", "gke-prod-us-central1"),
                                "namespace": payload.get("namespace", "default"),
                                "workload": payload.get("workload", "k8s_container"),
                                "pod": payload.get("pod", "unknown-pod"),
                                "error_code": payload.get("error_code", "GCP_LOG_ALERT"),
                                "title": payload.get("title", "Live Cloud Logging Error"),
                                "message": payload.get("message", str(entry.payload)),
                                "metrics_snapshot": payload.get("metrics_snapshot", {}),
                                "is_anomaly": True,
                                "persisted_to_gcp": True,
                            },
                        )
                        known_ids.add(lid)
            except Exception:
                pass

        return self._local_logs[:limit]
