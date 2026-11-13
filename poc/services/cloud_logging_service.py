"""
Pluggable Telemetry Ingestion Facade (`poc/services/cloud_logging_service.py`).

Controlled by `AAAS_TELEMETRY_PROVIDER=gcp|otel` (default: `gcp`):
  - `gcp`:  `GCPCloudLoggingAdapter` (100% backward-compatible Google Cloud Logging + `cloud-sql-proxy`
            capture, edge noise filtering, and `AAAS_AUDIT_EVENT` persistence)
  - `otel`: `OTelLokiLogAdapter` (OpenTelemetry / Grafana Loki / Prometheus / CloudWatch OTel streams)

All adapters emit normalized OpenTelemetry-compatible anomaly dictionaries via
`poc/providers/base_telemetry.py` while preserving every existing `CloudLoggingService`
attribute and method consumed by `poc/app.py` and `poc/agents/watcher_agent.py`.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from providers.base_telemetry import TelemetryIngestionAdapter
from providers.gcp.cloud_logging_adapter import GCPCloudLoggingAdapter
from providers.generic.otel_loki_adapter import OTelLokiLogAdapter


PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
LOG_NAME = os.getenv("AAAS_LOG_NAME", "aaas_gke_incidents")


def create_telemetry_adapter(
    provider: Optional[str] = None,
    project_id: Optional[str] = None,
    log_name: Optional[str] = None,
    initial_poll: bool = True,
) -> TelemetryIngestionAdapter:
    """Factory returning a concrete `TelemetryIngestionAdapter` for `AAAS_TELEMETRY_PROVIDER=gcp|otel`."""
    mode = (provider or os.getenv("AAAS_TELEMETRY_PROVIDER") or "gcp").strip().lower()
    if mode == "gcp":
        return GCPCloudLoggingAdapter(
            project_id=project_id or os.getenv("GCP_PROJECT_ID", PROJECT_ID),
            log_name=log_name or os.getenv("AAAS_LOG_NAME", LOG_NAME),
            initial_poll=initial_poll,
        )
    if mode in ("otel", "loki", "prometheus", "cloudwatch"):
        return OTelLokiLogAdapter(
            project_id=project_id or os.getenv("AAAS_CLOUD_ACCOUNT_ID") or os.getenv("GCP_PROJECT_ID", PROJECT_ID),
        )
    raise ValueError(
        f"Unsupported AAAS_TELEMETRY_PROVIDER={mode!r}. Expected one of: gcp, otel."
    )


class CloudLoggingService:
    """
    Backward-compatible facade over `TelemetryIngestionAdapter` (`GCPCloudLoggingAdapter` by default,
    or `OTelLokiLogAdapter` when `AAAS_TELEMETRY_PROVIDER=otel`).
    """

    def __init__(
        self,
        project_id: str = PROJECT_ID,
        provider: Optional[str] = None,
        adapter: Optional[TelemetryIngestionAdapter] = None,
    ) -> None:
        self.project_id = project_id
        self.log_name = LOG_NAME
        self.adapter: TelemetryIngestionAdapter = adapter or create_telemetry_adapter(
            provider=provider,
            project_id=project_id,
            log_name=self.log_name,
            initial_poll=True,
        )

    @property
    def gcp_connected(self) -> bool:
        return self.adapter.is_connected

    @property
    def gcp_status_detail(self) -> str:
        return self.adapter.status_detail

    @property
    def suppressed_routine_logs_count(self) -> int:
        return self.adapter.suppressed_routine_logs_count

    @suppressed_routine_logs_count.setter
    def suppressed_routine_logs_count(self, value: int) -> None:
        self.adapter.suppressed_routine_logs_count = int(value)

    @property
    def _local_logs(self) -> List[Dict[str, Any]]:
        return self.adapter.local_logs

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
        return self.adapter.record_audit_event(
            incident_id=incident_id,
            event_type=event_type,
            service=service,
            issue_title=issue_title,
            occurred_at=occurred_at,
            action_status=action_status,
            approved_by=approved_by,
            approved_at=approved_at,
            command=command,
            jit_token_id=jit_token_id,
        )

    def record_system_log(
        self,
        severity: str,
        workload: str,
        message: str,
        namespace: str = "aaas-control-plane",
        cluster: str = "gke-prod-us-central1",
    ) -> Dict[str, Any]:
        return self.adapter.record_system_log(
            severity=severity,
            workload=workload,
            message=message,
            namespace=namespace,
            cluster=cluster,
        )

    def fetch_recent_logs(
        self, limit: int = 25, poll_gcp: bool = True, force: bool = False
    ) -> List[Dict[str, Any]]:
        return self.adapter.fetch_recent_logs(
            limit=limit,
            poll_remote=poll_gcp,
            force=force,
        )

    def get_status(self) -> Dict[str, Any]:
        return self.adapter.get_status()


