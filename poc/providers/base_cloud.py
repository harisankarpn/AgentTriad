"""
Abstract Cloud Resource Diagnostic Ports (`poc/providers/base_cloud.py`).

Defines the Ports & Adapters strategy contracts for specialist ADK agents:
  - `DatabaseCloudAdapter`: Read-only inspection, performance telemetry, log triage,
    runtime identity introspection, and HITL remediation proposals across GCP Cloud SQL,
    AWS RDS, and Azure SQL.
  - `ComputeCloudAdapter`: Read-only VM/compute inspection, performance metrics, log triage,
    runtime identity introspection, and HITL remediation proposals across GCP Compute Engine,
    AWS EC2, and Azure Virtual Machines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class DatabaseCloudAdapter(ABC):
    """Strategy interface for cloud-agnostic database diagnostics (`gcp` | `aws` | `azure`)."""

    @property
    @abstractmethod
    def cloud_provider(self) -> str:
        """Canonical cloud provider identifier ('gcp', 'aws', or 'azure')."""

    @abstractmethod
    def inspect_instance(
        self,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inspects managed database instances (Cloud SQL / RDS / Azure SQL)."""

    @abstractmethod
    def get_performance_metrics(
        self,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
        window_minutes: int = 30,
    ) -> Dict[str, Any]:
        """Fetches database CPU, memory, storage, IOPS, and connection metrics."""

    @abstractmethod
    def analyze_logs_and_connections(
        self,
        symptom: str = "",
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries and classifies database error/audit/connection logs."""

    @abstractmethod
    def inspect_runtime_identity(
        self,
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Introspects the Database Specialist Agent's read-only cloud runtime identity."""

    @abstractmethod
    def generate_remediation_proposal(
        self,
        issue_type: str,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generates a cloud-native CLI command and Terraform (.tf) proposal gated by HITL."""

    def introspect_query_activity(
        self,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
        slow_query_threshold_ms: float = 500.0,
        activity_rows: Optional[Any] = None,
        statement_rows: Optional[Any] = None,
        log_lines: Optional[Any] = None,
        db_connection: Optional[Any] = None,
        readonly_dsn: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read-only query-level introspection (`pg_stat_activity` / slow-query log analysis).
        Defaults to combining out-of-band cloud database logs with the strictly read-only
        `analyze_pg_stat_activity_and_slow_queries` engine.
        """
        from services.db_query_introspection import analyze_pg_stat_activity_and_slow_queries

        resolved_logs = list(log_lines) if log_lines is not None else []
        if not resolved_logs and db_connection is None and not activity_rows and not readonly_dsn:
            try:
                log_res = self.analyze_logs_and_connections(
                    symptom="slow query duration lock wait",
                    instance_name=instance_name,
                    account_or_project_id=account_or_project_id,
                )
                resolved_logs = list(log_res.get("evidence") or [])
            except Exception:
                resolved_logs = []

        return analyze_pg_stat_activity_and_slow_queries(
            instance_name=instance_name,
            target_cloud=self.cloud_provider,
            slow_query_threshold_ms=slow_query_threshold_ms,
            activity_rows=activity_rows,
            statement_rows=statement_rows,
            log_lines=resolved_logs,
            db_connection=db_connection,
            readonly_dsn=readonly_dsn,
        )


class ComputeCloudAdapter(ABC):
    """Strategy interface for cloud-agnostic compute/VM diagnostics (`gcp` | `aws` | `azure`)."""

    @property
    @abstractmethod
    def cloud_provider(self) -> str:
        """Canonical cloud provider identifier ('gcp', 'aws', or 'azure')."""

    @abstractmethod
    def inspect_instances(
        self,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers and inspects compute VMs (GCE / AWS EC2 / Azure VMs)."""

    @abstractmethod
    def get_performance_metrics(
        self,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
        window_minutes: int = 30,
    ) -> Dict[str, Any]:
        """Fetches compute CPU, uptime, network, and disk I/O performance metrics."""

    @abstractmethod
    def analyze_logs(
        self,
        symptom: str = "",
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries and classifies compute/infrastructure warning and error logs."""

    @abstractmethod
    def inspect_runtime_identity(
        self,
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Introspects the Infra Specialist Agent's read-only cloud runtime identity."""

    @abstractmethod
    def generate_remediation_proposal(
        self,
        issue_type: str,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generates a cloud-native CLI command and Terraform (.tf) proposal gated by HITL."""
