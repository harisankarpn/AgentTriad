"""
Cloud-Agnostic OpenTelemetry / Grafana Loki / Prometheus / CloudWatch Log Adapter
(`OTelLokiLogAdapter` / `OTelLogAdapter`).

Activated via `AAAS_TELEMETRY_PROVIDER=otel`. Supports:
  1. Pull queries against Grafana Loki (`/loki/api/v1/query_range`) via `AAAS_OTEL_LOKI_URL`
  2. Pull queries against Prometheus Alertmanager (`/api/v2/alerts`) via `AAAS_PROMETHEUS_ALERTMANAGER_URL`
  3. Direct push ingestion of OTLP/OpenTelemetry JSON logs & AWS CloudWatch / Azure Monitor
     OTel-exported events (`ingest_otel_log`, `ingest_loki_payload`, `ingest_alertmanager_alerts`)

Outputs strictly normalized OpenTelemetry-compatible anomaly dictionaries via
`normalize_otel_anomaly(...)`, ready for `CloudLoggingWatcherAgent` and `Atlas`.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from providers.base_telemetry import TelemetryIngestionAdapter, normalize_otel_anomaly


class OTelLokiLogAdapter(TelemetryIngestionAdapter):
    """Cloud-agnostic OpenTelemetry / Loki / Prometheus / CloudWatch telemetry adapter."""

    def __init__(
        self,
        loki_url: Optional[str] = None,
        loki_query: Optional[str] = None,
        alertmanager_url: Optional[str] = None,
        project_id: Optional[str] = None,
        cloud_provider: Optional[str] = None,
    ) -> None:
        self.loki_url = (loki_url or os.getenv("AAAS_OTEL_LOKI_URL") or "").rstrip("/")
        self.loki_query = (
            loki_query
            or os.getenv("AAAS_OTEL_LOKI_QUERY")
            or '{level=~"error|fatal|critical|warn|ERROR|FATAL|CRITICAL|WARN"}'
        )
        self.alertmanager_url = (alertmanager_url or os.getenv("AAAS_PROMETHEUS_ALERTMANAGER_URL") or "").rstrip("/")
        self.project_id = project_id or os.getenv("AAAS_CLOUD_ACCOUNT_ID") or os.getenv("GCP_PROJECT_ID", "agent-triad")
        self.cloud_provider = (cloud_provider or os.getenv("CLOUD_PROVIDER") or "otel").strip().lower()
        self._connected: bool = bool(self.loki_url or self.alertmanager_url)
        self._status_detail: str = (
            f"OTel/Loki Telemetry active ({self.loki_url or self.alertmanager_url})"
            if self._connected
            else "OTel/Loki Telemetry active (local OTLP ring-buffer mode; set AAAS_OTEL_LOKI_URL to pull)"
        )
        self._local_logs: List[Dict[str, Any]] = []
        self._audit_events: List[Dict[str, Any]] = []
        self._suppressed_routine_logs_count: int = 0
        self._last_poll_time: float = 0.0

    @property
    def provider_name(self) -> str:
        return "OpenTelemetry / Loki"

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def status_detail(self) -> str:
        return self._status_detail

    @property
    def suppressed_routine_logs_count(self) -> int:
        return self._suppressed_routine_logs_count

    @suppressed_routine_logs_count.setter
    def suppressed_routine_logs_count(self, value: int) -> None:
        self._suppressed_routine_logs_count = int(value)

    @property
    def local_logs(self) -> List[Dict[str, Any]]:
        return self._local_logs

    def _is_routine_noise(self, message: str, severity: str) -> bool:
        if not message or not message.strip():
            return True
        if severity in ("DEBUG", "TRACE"):
            return True
        noisy_tokens = (
            "GET /healthz",
            "GET /metrics",
            "GET /api/state",
            "kube-probe/",
            "ELB-HealthChecker",
            "LogPingOpsAgent",
        )
        return any(tok in message for tok in noisy_tokens)

    def _add_normalized_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        existing_ids = {item.get("log_id") for item in self._local_logs}
        if entry["log_id"] in existing_ids:
            return None
        if entry.get("is_anomaly") and entry.get("signature_key"):
            sig = entry["signature_key"]
            ts = str(entry.get("timestamp", ""))
            for prev in self._local_logs:
                if prev.get("signature_key") == sig and str(prev.get("timestamp", "")) >= ts:
                    self._suppressed_routine_logs_count += 1
                    return None
        self._local_logs.append(entry)
        self._local_logs.sort(
            key=lambda x: (1 if x.get("is_anomaly") else 0, x.get("timestamp", "")),
            reverse=True,
        )
        return entry

    def ingest_otel_log(self, otel_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalizes and ingests a single OpenTelemetry / CloudWatch-OTel JSON log record."""
        resource_attrs = (otel_record.get("resource") or {}).get("attributes") or {}
        attrs = otel_record.get("attributes") or {}
        severity = str(
            otel_record.get("severity_text")
            or otel_record.get("severityText")
            or otel_record.get("severity")
            or "INFO"
        ).upper()
        raw_body = otel_record.get("body")
        if isinstance(raw_body, dict):
            raw_body = raw_body.get("stringValue") or raw_body.get("value") or str(raw_body)
        body = str(raw_body or otel_record.get("message") or "").strip()

        if self._is_routine_noise(body, severity):
            self._suppressed_routine_logs_count += 1
            return None

        provider = str(resource_attrs.get("cloud.provider") or self.cloud_provider)
        account_id = str(resource_attrs.get("cloud.account.id") or self.project_id)
        region = str(resource_attrs.get("cloud.region") or attrs.get("region") or "us-east-1")
        namespace = str(resource_attrs.get("service.namespace") or resource_attrs.get("k8s.namespace.name") or "default")
        service_name = str(
            resource_attrs.get("service.name")
            or attrs.get("service_name")
            or attrs.get("log_group")
            or attrs.get("service")
            or "otel-workload"
        )
        pod = str(resource_attrs.get("k8s.pod.name") or service_name)
        container = str(resource_attrs.get("container.name") or service_name)
        ts_val = otel_record.get("timestamp")
        if not ts_val and otel_record.get("timeUnixNano"):
            try:
                ts_val = datetime.datetime.fromtimestamp(
                    int(otel_record["timeUnixNano"]) / 1e9, tz=datetime.timezone.utc
                ).isoformat()
            except Exception:
                ts_val = None
        ts_iso = str(ts_val or datetime.datetime.now(datetime.timezone.utc).isoformat())

        is_anom = severity in ("ERROR", "CRITICAL", "FATAL", "ALERT", "EMERGENCY") or any(
            kw in body.lower() for kw in ("fatal:", "connection refused", "timeout expired", "oomkilled", "crashloop")
        )
        digest = hashlib.sha1(f"{service_name}:{severity}:{body[:80]}".encode()).hexdigest()[:10]
        log_id = str(otel_record.get("log_id") or f"otel-{digest}")
        sig_key = f"{provider}:{namespace}:{service_name}:{severity}:{body[:48]}"

        if any(k in body.lower() or k in service_name.lower() for k in ("postgres", "mysql", "rds", "sql", "db")):
            scenario_id = "cloudsql_anomaly" if is_anom else "info"
            error_code = "OTEL_DATABASE_CONNECTION_ERROR" if is_anom else "OTEL_DB_TELEMETRY"
            rec_cli = f"kubectl rollout status deployment/{service_name} -n {namespace}"
        else:
            scenario_id = "real_otel_anomaly" if is_anom else "info"
            error_code = f"OTEL_{provider.upper()}_ALERT" if is_anom else "OTEL_TELEMETRY"
            rec_cli = f"kubectl logs -n {namespace} -l app={service_name} --tail=100"

        entry = normalize_otel_anomaly(
            log_id=log_id,
            signature_key=sig_key,
            timestamp=ts_iso,
            severity=severity,
            scenario_id=scenario_id,
            title=f"OTel {service_name} ({provider}): {body[:65]}",
            source=f"otel:{provider}",
            project_id=account_id,
            cluster=region,
            namespace=namespace,
            workload=f"service/{service_name}",
            pod=pod,
            container=container,
            error_code=error_code,
            message=body[:1000],
            metrics_snapshot={**resource_attrs, **attrs},
            recommended_kubectl=rec_cli,
            is_anomaly=is_anom,
            persisted_to_gcp=False,
            cloud_provider=provider,
            trace_id=otel_record.get("trace_id") or otel_record.get("traceId"),
            span_id=otel_record.get("span_id") or otel_record.get("spanId"),
            extra_attributes=attrs,
        )
        return self._add_normalized_entry(entry)

    def ingest_loki_payload(self, loki_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses a Grafana Loki `/loki/api/v1/query_range` JSON response into OTel anomalies."""
        ingested: List[Dict[str, Any]] = []
        results = ((loki_json or {}).get("data") or {}).get("result") or []
        for stream_obj in results:
            labels = stream_obj.get("stream") or {}
            values = stream_obj.get("values") or []
            for pair in values:
                if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                    continue
                ns_str, line = str(pair[0]), str(pair[1])
                try:
                    ts_sec = int(ns_str) / 1e9
                    ts_iso = datetime.datetime.fromtimestamp(ts_sec, tz=datetime.timezone.utc).isoformat()
                except Exception:
                    ts_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

                record = {
                    "timestamp": ts_iso,
                    "severity_text": str(labels.get("level") or labels.get("severity") or "ERROR").upper(),
                    "body": line,
                    "resource": {
                        "attributes": {
                            "cloud.provider": labels.get("cloud_provider") or self.cloud_provider,
                            "cloud.region": labels.get("region") or labels.get("cluster") or "us-east-1",
                            "service.namespace": labels.get("namespace") or "default",
                            "service.name": labels.get("service_name") or labels.get("service") or labels.get("app") or labels.get("job") or "loki-stream",
                            "k8s.pod.name": labels.get("pod") or labels.get("instance") or "pod",
                            "container.name": labels.get("container") or labels.get("app") or "container",
                        }
                    },
                    "attributes": dict(labels),
                }
                norm = self.ingest_otel_log(record)
                if norm:
                    ingested.append(norm)
        return ingested

    def ingest_alertmanager_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalizes Prometheus Alertmanager `/api/v2/alerts` objects into OTel anomalies."""
        ingested: List[Dict[str, Any]] = []
        for alert in alerts or []:
            labels = alert.get("labels") or {}
            annotations = alert.get("annotations") or {}
            status = (alert.get("status") or {}).get("state", "active")
            if status != "active":
                continue
            alert_name = labels.get("alertname", "PrometheusAlert")
            summary = annotations.get("summary") or annotations.get("description") or alert_name
            record = {
                "log_id": f"prom-{alert.get('fingerprint') or uuid.uuid4().hex[:8]}",
                "timestamp": alert.get("startsAt") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "severity_text": str(labels.get("severity") or "ERROR").upper(),
                "body": f"[{alert_name}] {summary}",
                "resource": {
                    "attributes": {
                        "cloud.provider": labels.get("cloud_provider") or self.cloud_provider,
                        "cloud.region": labels.get("region") or labels.get("cluster") or "global",
                        "service.namespace": labels.get("namespace") or "monitoring",
                        "service.name": labels.get("service") or labels.get("job") or alert_name,
                        "k8s.pod.name": labels.get("pod") or labels.get("instance") or alert_name,
                    }
                },
                "attributes": {**labels, "alertname": alert_name},
            }
            norm = self.ingest_otel_log(record)
            if norm:
                ingested.append(norm)
        return ingested

    def fetch_recent_logs(
        self,
        limit: int = 25,
        poll_remote: bool = True,
        force: bool = False,
    ) -> List[Dict[str, Any]]:
        now_ts = time.time()
        should_poll = poll_remote and (force or (now_ts - self._last_poll_time >= 10.0))

        if should_poll:
            self._last_poll_time = now_ts
            if self.loki_url:
                try:
                    end_ns = int(now_ts * 1e9)
                    start_ns = int((now_ts - 900) * 1e9)
                    with httpx.Client(timeout=5.0) as client:
                        resp = client.get(
                            f"{self.loki_url}/loki/api/v1/query_range",
                            params={
                                "query": self.loki_query,
                                "start": str(start_ns),
                                "end": str(end_ns),
                                "limit": str(limit),
                                "direction": "BACKWARD",
                            },
                        )
                        if resp.status_code == 200:
                            self.ingest_loki_payload(resp.json())
                            self._connected = True
                            self._status_detail = f"Live OTel/Loki active ({self.loki_url})"
                except Exception as exc:
                    self._connected = False
                    self._status_detail = f"OTel/Loki poll fallback ({exc})"

            if self.alertmanager_url:
                try:
                    with httpx.Client(timeout=5.0) as client:
                        resp = client.get(f"{self.alertmanager_url}/api/v2/alerts")
                        if resp.status_code == 200 and isinstance(resp.json(), list):
                            self.ingest_alertmanager_alerts(resp.json())
                            self._connected = True
                except Exception:
                    pass

        return self._local_logs[:limit]

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
            "telemetry_provider": self.provider_name,
        }
        self._audit_events.insert(0, audit_payload)
        return audit_payload

    def record_system_log(
        self,
        severity: str,
        workload: str,
        message: str,
        namespace: str = "aaas-control-plane",
        cluster: str = "otel-cluster",
    ) -> Dict[str, Any]:
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
            cloud_provider=self.cloud_provider,
        )
        self._local_logs.insert(0, entry)
        return entry

    def get_status(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "telemetry_provider_mode": "otel",
            "project_id": self.project_id,
            "loki_url": self.loki_url or None,
            "alertmanager_url": self.alertmanager_url or None,
            "connected": self._connected,
            "detail": self._status_detail,
            "suppressed_routine_logs": self._suppressed_routine_logs_count,
        }


# Alias matching AGENTS.md target architecture naming
OTelLogAdapter = OTelLokiLogAdapter
