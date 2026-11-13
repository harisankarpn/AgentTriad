"""
Abstract Telemetry Ingestion Port & OpenTelemetry Anomaly Schema (`poc/providers/base_telemetry.py`).

Defines:
  - `normalize_otel_anomaly(...)`: Produces an OpenTelemetry Logs Data Model compatible
    anomaly record (`otel` structured envelope + 100% backward-compatible top-level AaaS keys).
  - `TelemetryIngestionAdapter` (alias `TelemetryProvider`): Cloud-agnostic Port interface
    implemented by `GCPCloudLoggingAdapter` (`AAAS_TELEMETRY_PROVIDER=gcp`) and
    `OTelLokiLogAdapter` (`AAAS_TELEMETRY_PROVIDER=otel`).
"""

from __future__ import annotations

import datetime
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


_OTEL_SEVERITY_NUMBERS: Dict[str, int] = {
    "TRACE": 1,
    "DEBUG": 5,
    "INFO": 9,
    "NOTICE": 10,
    "WARNING": 13,
    "WARN": 13,
    "ERROR": 17,
    "CRITICAL": 21,
    "ALERT": 22,
    "EMERGENCY": 24,
    "FATAL": 21,
}


def normalize_otel_anomaly(
    *,
    log_id: str,
    signature_key: str,
    timestamp: str,
    severity: str,
    scenario_id: str,
    title: str,
    source: str,
    project_id: str,
    cluster: str,
    namespace: str,
    workload: str,
    pod: str,
    container: str,
    error_code: str,
    message: str,
    metrics_snapshot: Optional[Dict[str, Any]] = None,
    recommended_kubectl: str = "",
    recommended_action_type: Optional[str] = None,
    is_anomaly: bool = False,
    persisted_to_gcp: bool = False,
    cloud_provider: str = "generic",
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    extra_attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Produces a unified, OpenTelemetry Logs Data Model compatible anomaly dictionary while
    preserving all existing AaaS Control Plane keys (`log_id`, `signature_key`, `is_anomaly`, etc.).
    """
    sev_upper = (severity or "INFO").upper()
    sev_num = _OTEL_SEVERITY_NUMBERS.get(sev_upper, 9)
    observed_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    resolved_ts = timestamp or observed_iso

    attributes: Dict[str, Any] = {
        "aaas.log_id": log_id,
        "aaas.signature_key": signature_key,
        "aaas.error_code": error_code,
        "aaas.scenario_id": scenario_id,
        "aaas.is_anomaly": bool(is_anomaly),
        "aaas.source": source,
    }
    if extra_attributes:
        attributes.update(extra_attributes)

    otel_envelope: Dict[str, Any] = {
        "schema_version": "opentelemetry.proto.logs.v1",
        "timestamp": resolved_ts,
        "observed_timestamp": observed_iso,
        "severity_text": sev_upper,
        "severity_number": sev_num,
        "body": message,
        "trace_id": trace_id or uuid.uuid4().hex,
        "span_id": span_id or uuid.uuid4().hex[:16],
        "resource": {
            "attributes": {
                "cloud.provider": cloud_provider,
                "cloud.account.id": project_id,
                "cloud.region": cluster,
                "service.namespace": namespace,
                "service.name": workload,
                "k8s.pod.name": pod,
                "container.name": container,
            }
        },
        "attributes": attributes,
    }

    entry: Dict[str, Any] = {
        "log_id": log_id,
        "signature_key": signature_key,
        "timestamp": resolved_ts,
        "severity": sev_upper,
        "scenario_id": scenario_id,
        "title": title,
        "source": source,
        "project_id": project_id,
        "cluster": cluster,
        "namespace": namespace,
        "workload": workload,
        "pod": pod,
        "container": container,
        "error_code": error_code,
        "message": message,
        "metrics_snapshot": dict(metrics_snapshot or {}),
        "recommended_kubectl": recommended_kubectl,
        "is_anomaly": bool(is_anomaly),
        "persisted_to_gcp": bool(persisted_to_gcp),
        "cloud_provider": cloud_provider,
        "otel": otel_envelope,
    }
    if recommended_action_type:
        entry["recommended_action_type"] = recommended_action_type
    return entry


class TelemetryIngestionAdapter(ABC):
    """Port interface for cloud-agnostic log ingestion, edge noise filtering, and audit emission."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable telemetry provider identifier (e.g., 'GCP Cloud Logging', 'OpenTelemetry/Loki')."""

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Whether the live telemetry backend is currently connected/reachable."""

    @property
    @abstractmethod
    def status_detail(self) -> str:
        """Human-readable connection/status detail for the dashboard."""

    @property
    @abstractmethod
    def suppressed_routine_logs_count(self) -> int:
        """Total count of routine noise entries suppressed at the edge."""

    @suppressed_routine_logs_count.setter
    @abstractmethod
    def suppressed_routine_logs_count(self, value: int) -> None:
        """Updates the suppressed routine noise counter (e.g. when syncing remote watcher stats)."""

    @property
    @abstractmethod
    def local_logs(self) -> List[Dict[str, Any]]:
        """In-memory ring buffer of normalized OpenTelemetry-compatible log entries."""

    @abstractmethod
    def fetch_recent_logs(
        self,
        limit: int = 25,
        poll_remote: bool = True,
        force: bool = False,
    ) -> List[Dict[str, Any]]:
        """Polls the configured telemetry backend and returns normalized OTel-compatible entries."""

    @abstractmethod
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
        """Emits an immutable audit trail entry to the telemetry backend."""

    @abstractmethod
    def record_system_log(
        self,
        severity: str,
        workload: str,
        message: str,
        namespace: str = "aaas-control-plane",
        cluster: str = "gke-prod-us-central1",
    ) -> Dict[str, Any]:
        """Records a watchdog verification or remediation system log entry."""

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns structured provider status metadata."""


# Alias matching AGENTS.md target architecture naming
TelemetryProvider = TelemetryIngestionAdapter
