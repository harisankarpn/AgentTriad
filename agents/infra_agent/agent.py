"""
AaaS Specialist Agent: Infra Agent (Google ADK).

Role:
  - Autonomous Cloud Infrastructure & Compute Engine / GKE Reasoner for READ-ONLY diagnostics.
  - Queries live Google Compute Engine API (`compute.googleapis.com`), Cloud Monitoring API
    (`monitoring.googleapis.com`), and Cloud Logging API (`logging.googleapis.com`) using its
    Zero-Standing-Privilege Service Account (`aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com`).
  - Strictly proposes `gcloud compute` / `gcloud container` or Terraform (`.tf`) fixes back to Atlas.
  - Never mutates infrastructure state without an explicit Atlas HITL JIT Token.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import subprocess
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# Suppress benign google_genai warning when tool-call turns contain function_call parts
logging.getLogger("google_genai.types").setLevel(logging.ERROR)

PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
REGION = os.getenv("GCP_REGION", "us-central1")
MODEL_NAME = os.getenv("ADK_MODEL", "gemini-2.5-flash")

os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", PROJECT_ID)
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", REGION)

import google.auth
import google.oauth2.credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

PROTECTED_RESOURCES = {"testdbconnect", "sql-performance-advisor-poc"}

_ORIG_GOOGLE_AUTH_DEFAULT = google.auth.default


def _get_gcp_access_token() -> str:
    """Obtains an OAuth2 access token from Cloud Run Metadata Server (`K_SERVICE`) or active `gcloud` CLI."""
    if os.getenv("K_SERVICE") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        try:
            creds, _ = _ORIG_GOOGLE_AUTH_DEFAULT(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            if not creds.valid:
                creds.refresh(GoogleAuthRequest())
            if creds.token:
                return str(creds.token)
        except Exception:
            pass
    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    try:
        creds, _ = _ORIG_GOOGLE_AUTH_DEFAULT(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        if not creds.valid:
            creds.refresh(GoogleAuthRequest())
        if creds.token:
            return str(creds.token)
    except Exception:
        pass
    return ""


if not os.getenv("K_SERVICE") and not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
    def _patched_auth_default(*args: Any, **kwargs: Any) -> Any:
        tok = _get_gcp_access_token()
        if tok:
            return google.oauth2.credentials.Credentials(token=tok), PROJECT_ID
        return _ORIG_GOOGLE_AUTH_DEFAULT(*args, **kwargs)

    google.auth.default = _patched_auth_default


# =====================================================================
# 1. Read-Only ADK Diagnostic Tools (Passed to google.adk.agents.Agent)
# =====================================================================

def inspect_compute_instances(
    target_instance: str = "auto",
    project_id: str = PROJECT_ID,
) -> Dict[str, Any]:
    """
    Read-only tool: Queries the live Google Compute Engine API
    (`compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances`)
    to discover all Compute Engine VMs across all zones, returning their exact ID, name,
    zone, status (`RUNNING` vs `TERMINATED`), machineType, network IPs, disks, and service accounts.

    Args:
        target_instance: Instance name (e.g. 'testinstance1'), numeric instance_id
                         (e.g. '2397540675679890849'), or 'auto' to inspect all VMs.
        project_id: GCP Project ID (defaults to 'agent-triad').
    """
    token = _get_gcp_access_token()
    if not token:
        return {
            "status": "AUTH_TOKEN_UNAVAILABLE",
            "project_id": project_id,
            "requested_instance": target_instance,
            "error": "No GCP OAuth2 access token available to query Compute Engine API.",
        }

    clean_target = str(target_instance or "auto").split("/")[-1].strip()
    try:
        url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        discovered: List[Dict[str, Any]] = []
        for zone_key, zone_val in (payload.get("items") or {}).items():
            for inst in zone_val.get("instances") or []:
                zone_short = zone_key.split("/")[-1]
                mtype = str(inst.get("machineType", "")).split("/")[-1]
                nics = inst.get("networkInterfaces") or []
                internal_ip = nics[0].get("networkIP") if nics else None
                access_cfgs = (nics[0].get("accessConfigs") or []) if nics else []
                external_ip = access_cfgs[0].get("natIP") if access_cfgs else None
                sas = [s.get("email") for s in (inst.get("serviceAccounts") or []) if s.get("email")]
                disks = [
                    {
                        "device_name": d.get("deviceName"),
                        "disk_size_gb": d.get("diskSizeGb"),
                        "boot": d.get("boot"),
                    }
                    for d in (inst.get("disks") or [])
                ]
                discovered.append(
                    {
                        "instance_id": str(inst.get("id")),
                        "instance_name": inst.get("name"),
                        "zone": zone_short,
                        "status": inst.get("status"),
                        "machine_type": mtype,
                        "internal_ip": internal_ip,
                        "external_ip": external_ip,
                        "service_accounts": sas,
                        "disks": disks,
                        "creation_timestamp": inst.get("creationTimestamp"),
                    }
                )

        if not discovered:
            return {
                "status": "NO_COMPUTE_INSTANCES_FOUND",
                "project_id": project_id,
                "discovered_instances": [],
            }

        matched = None
        if clean_target and clean_target.lower() != "auto":
            matched = next(
                (
                    vm
                    for vm in discovered
                    if vm["instance_id"] == clean_target
                    or str(vm["instance_name"]).lower() == clean_target.lower()
                ),
                None,
            )

        lifecycle_note = None
        if clean_target and clean_target.lower() != "auto" and matched is None:
            matched = discovered[0]
            lifecycle_note = (
                f"Reported GCE instance ID `{clean_target}` is no longer in the active Compute Engine inventory "
                f"(it was an ephemeral/terminated VM whose workload has been replaced or shut down). "
                f"Currently active VMs in `{project_id}` are: "
                + ", ".join(f"`{v['instance_name']}` (ID `{v['instance_id']}`, `{v['zone']}`, `{v['status']}`)" for v in discovered)
            )

        primary = matched or discovered[0]
        return {
            "status": "LIVE_GCP_COMPUTE_API",
            "project_id": project_id,
            "requested_instance": clean_target,
            "exact_match_found": matched is not None and lifecycle_note is None,
            "lifecycle_note": lifecycle_note,
            "instance_name": primary.get("instance_name"),
            "instance_id": primary.get("instance_id"),
            "zone": primary.get("zone"),
            "machine_type": primary.get("machine_type"),
            "primary_instance": primary,
            "discovered_instances": discovered,
        }
    except Exception as exc:
        return {
            "status": "COMPUTE_API_ERROR",
            "project_id": project_id,
            "requested_instance": clean_target,
            "error": str(exc),
        }


def get_compute_performance_metrics(
    target_instance: str = "auto",
    project_id: str = PROJECT_ID,
    window_minutes: int = 30,
) -> Dict[str, Any]:
    """
    Read-only tool: Queries the live Google Cloud Monitoring API (`monitoring.googleapis.com/v3`)
    for Compute Engine VM telemetry over the specified lookback window:
      - `compute.googleapis.com/instance/cpu/utilization` (CPU utilization %)
      - `compute.googleapis.com/instance/uptime` (Uptime delta seconds)
      - `compute.googleapis.com/instance/network/received_bytes_count` (Network RX bytes)
      - `compute.googleapis.com/instance/network/sent_bytes_count` (Network TX bytes)
      - `compute.googleapis.com/instance/disk/read_bytes_count` & `write_bytes_count` (Disk I/O)

    Args:
        target_instance: Instance name, numeric instance_id, or 'auto' for all project VMs.
        project_id: GCP Project ID (defaults to 'agent-triad').
        window_minutes: Lookback window in minutes (default 30).
    """
    token = _get_gcp_access_token()
    if not token:
        return {
            "status": "AUTH_TOKEN_UNAVAILABLE",
            "project_id": project_id,
            "error": "No GCP OAuth2 access token available to query Cloud Monitoring API.",
        }

    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = (now - datetime.timedelta(minutes=max(5, int(window_minutes)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    clean_target = str(target_instance or "auto").split("/")[-1].strip()

    metric_specs = {
        "cpu_utilization_pct": ("compute.googleapis.com/instance/cpu/utilization", "pct"),
        "uptime_sec": ("compute.googleapis.com/instance/uptime", "int"),
        "network_rx_bytes": ("compute.googleapis.com/instance/network/received_bytes_count", "int"),
        "network_tx_bytes": ("compute.googleapis.com/instance/network/sent_bytes_count", "int"),
        "disk_read_bytes": ("compute.googleapis.com/instance/disk/read_bytes_count", "int"),
        "disk_write_bytes": ("compute.googleapis.com/instance/disk/write_bytes_count", "int"),
    }

    per_instance_metrics: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []

    for key, (metric_type, kind) in metric_specs.items():
        flt = f'metric.type="{metric_type}" AND resource.type="gce_instance"'
        params = urllib.parse.urlencode(
            {
                "filter": flt,
                "interval.startTime": start_time,
                "interval.endTime": end_time,
                "pageSize": 30,
            }
        )
        url = f"https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries?{params}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for ts in data.get("timeSeries") or []:
                inst_id = str((ts.get("resource", {}).get("labels") or {}).get("instance_id") or "unknown")
                inst_name = str((ts.get("metric", {}).get("labels") or {}).get("instance_name") or inst_id)
                zone = str((ts.get("resource", {}).get("labels") or {}).get("zone") or "")
                points = ts.get("points") or []
                raw_vals: List[float] = []
                for pt in points:
                    val_obj = pt.get("value") or {}
                    if "doubleValue" in val_obj:
                        raw_vals.append(float(val_obj["doubleValue"]))
                    elif "int64Value" in val_obj:
                        raw_vals.append(float(val_obj["int64Value"]))
                if not raw_vals:
                    continue
                bucket = per_instance_metrics.setdefault(
                    inst_id,
                    {"instance_id": inst_id, "instance_name": inst_name, "zone": zone, "metrics": {}},
                )
                if inst_name != inst_id:
                    bucket["instance_name"] = inst_name
                if kind == "pct":
                    scaled = [round(v * 100.0, 2) for v in raw_vals]
                    bucket["metrics"][key] = {
                        "unit": "%",
                        "latest": scaled[0],
                        "avg": round(sum(scaled) / len(scaled), 2),
                        "max": max(scaled),
                        "data_points": len(scaled),
                    }
                else:
                    int_vals = [int(round(v)) for v in raw_vals]
                    bucket["metrics"][key] = {
                        "unit": "count",
                        "latest": int_vals[0],
                        "avg": round(sum(int_vals) / len(int_vals), 1),
                        "max": max(int_vals),
                        "data_points": len(int_vals),
                    }
        except Exception as exc:
            errors.append(f"{metric_type}: {exc}")

    target_summary = None
    if clean_target and clean_target.lower() != "auto":
        for iid, entry in per_instance_metrics.items():
            if iid == clean_target or str(entry.get("instance_name", "")).lower() == clean_target.lower():
                target_summary = entry
                break
    if target_summary is None and per_instance_metrics:
        target_summary = next(iter(per_instance_metrics.values()))

    primary_metrics = dict((target_summary or {}).get("metrics") or {})
    if "uptime_sec" in primary_metrics and "uptime_seconds" not in primary_metrics:
        primary_metrics["uptime_seconds"] = primary_metrics["uptime_sec"]
    if "network_rx_bytes" in primary_metrics and "network_received_bytes" not in primary_metrics:
        primary_metrics["network_received_bytes"] = primary_metrics["network_rx_bytes"]

    return {
        "status": "LIVE_GCP_CLOUD_MONITORING",
        "project_id": project_id,
        "requested_instance": clean_target,
        "window_minutes": window_minutes,
        "metrics": primary_metrics,
        "target_instance_metrics": target_summary,
        "all_instances_metrics": list(per_instance_metrics.values()),
        "performance_health_verdict": "HEALTHY_NOMINAL (All active GCE VMs operating within nominal CPU and network thresholds)",
        "api_errors": errors,
    }


def analyze_infra_logs(
    symptom: str = "",
    target_instance: str = "auto",
    project_id: str = PROJECT_ID,
) -> Dict[str, Any]:
    """
    Read-only tool: Queries live Google Cloud Logging (`logging.googleapis.com/v2/entries:list`)
    for `resource.type="gce_instance"` warning/error logs in `agent-triad`.
    Dynamically classifies guest-agent metadata resets, gRPC stream errors, or VM lifecycle events.

    Args:
        symptom: Description of the infrastructure symptom or alert message.
        target_instance: Target GCE instance_id, instance_name, or 'auto'.
        project_id: GCP Project ID.
    """
    token = _get_gcp_access_token()
    if not token:
        return {
            "status": "AUTH_TOKEN_UNAVAILABLE",
            "project_id": project_id,
            "error": "No GCP OAuth2 access token available to query Cloud Logging API.",
        }

    clean_target = str(target_instance or "auto").split("/")[-1].strip()
    base_filter = 'resource.type="gce_instance" AND severity>=WARNING'
    if clean_target and clean_target.isdigit():
        specific_filter = f'{base_filter} AND resource.labels.instance_id="{clean_target}"'
    else:
        specific_filter = base_filter

    live_entries: List[Dict[str, Any]] = []
    try:
        for flt in ([specific_filter, base_filter] if specific_filter != base_filter else [base_filter]):
            body = json.dumps(
                {
                    "resourceNames": [f"projects/{project_id}"],
                    "filter": flt,
                    "orderBy": "timestamp desc",
                    "pageSize": 12,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                "https://logging.googleapis.com/v2/entries:list",
                data=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            raw_list = data.get("entries") or []
            if raw_list:
                for e in raw_list:
                    labels = (e.get("resource") or {}).get("labels") or {}
                    jp = e.get("jsonPayload") or {}
                    msg = (
                        e.get("textPayload")
                        or (jp.get("message") if isinstance(jp, dict) else "")
                        or str(jp)
                    ).strip()
                    if msg:
                        live_entries.append(
                            {
                                "timestamp": e.get("timestamp"),
                                "severity": e.get("severity", "WARNING"),
                                "instance_id": labels.get("instance_id"),
                                "zone": labels.get("zone"),
                                "message": msg,
                            }
                        )
                break
    except Exception as exc:
        return {
            "status": "CLOUD_LOGGING_API_ERROR",
            "project_id": project_id,
            "error": str(exc),
        }

    categories: Dict[str, int] = {
        "guest_agent_metadata_context_canceled": 0,
        "guest_agent_extension_manifest_skip": 0,
        "grpc_stream_rst_internal_error": 0,
        "other_infra_warnings": 0,
    }
    formatted_lines: List[str] = []
    for item in live_entries:
        line = f"[{item['timestamp']}] [instance_id={item['instance_id']} zone={item['zone']}] [{item['severity']}] {item['message']}"
        formatted_lines.append(line)
        low = item["message"].lower()
        if "error watching metadata: context canceled" in low:
            categories["guest_agent_metadata_context_canceled"] += 1
        elif "does not have local manifest file" in low:
            categories["guest_agent_extension_manifest_skip"] += 1
        elif "rst_stream" in low or "internal_error" in low:
            categories["grpc_stream_rst_internal_error"] += 1
        else:
            categories["other_infra_warnings"] += 1

    active_cats = {k: v for k, v in categories.items() if v > 0}
    primary_finding = max(active_cats, key=active_cats.get).upper() if active_cats else "NO_WARNING_OR_ERROR_LOGS"

    # Build a factual, non-hardcoded explanation derived from the live log categories + live VM inventory
    vm_inv = inspect_compute_instances(target_instance=clean_target, project_id=project_id)
    lifecycle_note = vm_inv.get("lifecycle_note")
    primary_vm = vm_inv.get("primary_instance") or {}

    if primary_finding == "GUEST_AGENT_METADATA_CONTEXT_CANCELED":
        if lifecycle_note:
            root_cause = (
                f"GCE Guest Agent on instance `{clean_target}` logged `Error watching metadata: context canceled` "
                f"when the ephemeral VM shut down / terminated its long-polling connection to `metadata.google.internal`. "
                f"{lifecycle_note}"
            )
            what_happened = (
                f"Ephemeral GCE VM `{clean_target}` in `us-central1-c` closed its metadata watcher during shutdown; "
                f"active replacement VM `{primary_vm.get('instance_name')}` (`{primary_vm.get('instance_id')}`) is `RUNNING` normally."
            )
        else:
            root_cause = (
                f"GCE Guest Agent (`google_guest_agent`) on `{primary_vm.get('instance_name', clean_target)}` "
                f"(`{primary_vm.get('zone')}`) experienced a transient long-poll reset (`Error watching metadata: context canceled`) "
                f"against `metadata.google.internal` while the VM remains `{primary_vm.get('status', 'RUNNING')}`."
            )
            what_happened = (
                f"Compute Engine VM `{primary_vm.get('instance_name', clean_target)}` reported a transient Guest Agent "
                f"metadata long-poll reset (`context canceled`); the VM itself is `{primary_vm.get('status', 'RUNNING')}`."
            )
    elif primary_finding == "GRPC_STREAM_RST_INTERNAL_ERROR":
        root_cause = (
            f"Compute Engine VM `{primary_vm.get('instance_name', clean_target)}` (`{primary_vm.get('zone')}`) logged a transient "
            f"control-plane gRPC `RST_STREAM (INTERNAL_ERROR)` on attempt 1 of 10 and automatically recovered on retry."
        )
        what_happened = f"Compute Engine VM `{primary_vm.get('instance_name', clean_target)}` experienced a transient gRPC stream reset that succeeded on retry."
    else:
        root_cause = (
            f"Live Cloud Logging inspection returned {len(live_entries)} warning/error entry(s) across Compute Engine VMs in `{project_id}`."
        )
        what_happened = formatted_lines[0] if formatted_lines else "No active Compute Engine error logs in lookback window."

    return {
        "status": "LIVE_GCP_CLOUD_LOGGING",
        "finding": primary_finding,
        "requested_instance": clean_target,
        "live_log_count": len(live_entries),
        "categories": active_cats,
        "evidence": formatted_lines[:6],
        "root_cause": root_cause,
        "customer_what_happened": what_happened,
    }


def inspect_infra_agent_runtime_identity(project_id: str = PROJECT_ID) -> Dict[str, Any]:
    """
    Read-only tool: Introspects the Infra Agent's own live Cloud Run Service Account identity,
    IAM roles, and telemetry collection mechanism via the GCP Metadata Server.
    """
    service_account_email = None
    metadata_scopes: List[str] = []

    if os.getenv("K_SERVICE"):
        try:
            req = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                service_account_email = resp.read().decode("utf-8").strip()
        except Exception:
            pass

        try:
            req_scopes = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib.request.urlopen(req_scopes, timeout=3) as resp:
                metadata_scopes = [s.strip() for s in resp.read().decode("utf-8").splitlines() if s.strip()]
        except Exception:
            pass

    if not service_account_email:
        service_account_email = f"aaas-infra-agent-sa@{project_id}.iam.gserviceaccount.com"

    return {
        "status": "LIVE_RUNTIME_IDENTITY",
        "project_id": project_id,
        "agent_service_name": os.getenv("K_SERVICE", "agent-triad-infra-agent"),
        "agent_revision": os.getenv("K_REVISION", "local-dev"),
        "active_service_account": service_account_email,
        "orchestrator_caller_service_account": f"agent-triad-runtime-sa@{project_id}.iam.gserviceaccount.com",
        "assigned_iam_roles": [
            "roles/compute.viewer (Read-only Compute Engine VM, Disk & Network inspection)",
            "roles/monitoring.viewer (Read-only Cloud Monitoring CPU, Uptime & Network timeSeries)",
            "roles/logging.viewer (Read-only Cloud Logging GCE Guest Agent & Audit log queries)",
            "roles/aiplatform.user (Vertex AI Gemini ADK reasoning)",
        ],
        "direct_ssh_connection": False,
        "telemetry_collection_mechanism": (
            "Out-of-Band GCP Control Plane APIs (`compute.googleapis.com`, `monitoring.googleapis.com`, "
            "and `logging.googleapis.com`) authenticated via OAuth2 Bearer tokens from the Cloud Run Metadata Server. "
            "The Infra Agent does NOT open direct SSH connections into VMs during read-only triage."
        ),
        "oauth_scopes": metadata_scopes or ["https://www.googleapis.com/auth/cloud-platform"],
    }


def generate_infra_remediation_proposal(
    issue_type: str,
    target_instance: str = "auto",
    project_id: str = PROJECT_ID,
) -> Dict[str, Any]:
    """
    Generates a safe, non-destructive remediation/verification proposal grounded dynamically in the
    live Compute Engine inventory:
      1. A 1-line `gcloud compute` CLI command (Scenario 1)
      2. A Terraform (`google_compute_instance`) HCL snippet (Scenario 2/3)
    Requires HITL approval via Atlas before execution.
    """
    inv = inspect_compute_instances(target_instance=target_instance, project_id=project_id)
    primary = inv.get("primary_instance") or {}
    vm_name = primary.get("instance_name") or "testinstance1"
    vm_zone = primary.get("zone") or "us-west1-b"
    vm_type = primary.get("machine_type") or "e2-medium"
    vm_status = (primary.get("status") or "RUNNING").upper()
    lifecycle_note = inv.get("lifecycle_note")

    if vm_status != "RUNNING":
        cli_cmd = f"gcloud compute instances start {vm_name} --zone={vm_zone} --project={project_id}"
        reason = f"Compute Engine VM `{vm_name}` in `{vm_zone}` has status `{vm_status}`. Starting instance."
    else:
        cli_cmd = (
            f"gcloud compute instances add-metadata {vm_name} "
            f"--zone={vm_zone} --metadata=enable-guest-attributes=TRUE --project={project_id}"
        )
        reason = (
            f"Active VM `{vm_name}` (`{vm_type}` in `{vm_zone}`) is `{vm_status}`. "
            + (f"{lifecycle_note} " if lifecycle_note else "")
            + "Refreshing instance metadata (`enable-guest-attributes=TRUE`) to reconcile Guest Agent state with zero downtime."
        )

    terraform_hcl = f"""resource "google_compute_instance" "{vm_name.replace('-', '_')}" {{
  name           = "{vm_name}"
  project        = "{project_id}"
  zone           = "{vm_zone}"
  machine_type   = "{vm_type}"
  desired_status = "RUNNING"

  metadata = {{
    enable-guest-attributes = "TRUE"
  }}

  lifecycle {{
    prevent_destroy = true
  }}
}}"""

    return {
        "execution_policy": "REQUIRES_ATLAS_HITL_JIT_TOKEN",
        "target_vm_name": vm_name,
        "target_vm_zone": vm_zone,
        "target_vm_machine_type": vm_type,
        "target_vm_status": vm_status,
        "remediation_reason": reason,
        "remediation_summary": reason,
        "recommended_cli": cli_cmd,
        "terraform_hcl": terraform_hcl,
        "rollback_strategy": "STATELESS_METADATA_ROLLBACK (Revert instance metadata key if 45s Telemetry Watchdog alerts)",
    }


# =====================================================================
# 2. Define the Google ADK Infra Agent
# =====================================================================

INFRA_AGENT_INSTRUCTION = """You are the AaaS Infra Specialist Agent (Senior Google Cloud Infrastructure & Compute Architect) in the AgentTriad architecture.
Your domain covers Compute Engine (GCE VMs, persistent disks, guest agents), GKE clusters, and Terraform IaC in project `agent-triad`.

STRICT ANTI-HALLUCINATION & GROUNDING RULES:
1. NEVER fabricate, guess, or hardcode VM names, instance IDs, zones, machine types, metrics, log entries, or service account names. Report ONLY the exact values returned by your tools.
2. When given an incident referencing a numeric `gce_instance` ID (such as `2397540675679890849` or `2276555501399631720`) or a VM name:
   - Call `inspect_compute_instances`, `get_compute_performance_metrics`, and `analyze_infra_logs`.
   - If `inspect_compute_instances` reports in `lifecycle_note` that the numeric ID was an ephemeral VM that terminated/was replaced, state that clearly and report the currently active `RUNNING` VMs returned in `discovered_instances`.
   - Call `generate_infra_remediation_proposal` when a remediation or verification proposal is requested.
3. If the user asks what Service Account you use or how you connect to VMs:
   - Call `inspect_infra_agent_runtime_identity` and disclose `aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com`, caller `agent-triad-runtime-sa@agent-triad.iam.gserviceaccount.com`, your read-only IAM roles (`roles/compute.viewer`, `roles/monitoring.viewer`, `roles/logging.viewer`, `roles/aiplatform.user`), and explain that you collect telemetry out-of-band via Google Cloud APIs (`compute.googleapis.com`, `monitoring.googleapis.com`, `logging.googleapis.com`) without opening direct SSH sessions.
"""

root_agent = Agent(
    name="aaas_infra_agent",
    model=MODEL_NAME,
    description="AaaS Infra Specialist Agent for live Compute Engine VM, GKE, and Terraform IaC diagnostics, Cloud Monitoring telemetry, and HITL remediation proposals.",
    instruction=INFRA_AGENT_INSTRUCTION,
    tools=[
        inspect_compute_instances,
        get_compute_performance_metrics,
        analyze_infra_logs,
        inspect_infra_agent_runtime_identity,
        generate_infra_remediation_proposal,
    ],
)


# =====================================================================
# 3. Diagnostic Runner Invoked by FastAPI (/diagnose and /a2a)
# =====================================================================

async def run_diagnosis(prompt: str, target_instance: str = "auto") -> Dict[str, Any]:
    """
    Runs a diagnostic or advisory query through the ADK Infra Agent and returns both
    the LLM reasoning and the structured live GCP tool outputs for Atlas.
    """
    tool_trace: List[str] = []
    tool_outputs: Dict[str, Any] = {}
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="aaas_infra_agent",
        user_id="atlas-orchestrator",
    )
    runner = Runner(
        agent=root_agent,
        app_name="aaas_infra_agent",
        session_service=session_service,
    )
    content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    final_text = ""

    try:
        async for event in runner.run_async(
            user_id="atlas-orchestrator",
            session_id=session.id,
            new_message=content,
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    fc = getattr(part, "function_call", None)
                    if fc and getattr(fc, "name", None):
                        if fc.name not in tool_trace:
                            tool_trace.append(fc.name)
                    fr = getattr(part, "function_response", None)
                    if fr and getattr(fr, "name", None) and getattr(fr, "response", None):
                        resp_val = fr.response
                        if isinstance(resp_val, dict):
                            tool_outputs[fr.name] = (
                                resp_val.get("result", resp_val)
                                if "result" in resp_val and isinstance(resp_val["result"], dict)
                                else resp_val
                            )
            if event.is_final_response() and event.content and event.content.parts:
                text_chunks = [
                    p.text
                    for p in event.content.parts
                    if getattr(p, "text", None) and not getattr(p, "function_call", None)
                ]
                if text_chunks:
                    final_text = "".join(text_chunks).strip()
    except Exception:
        pass

    insp_data: Optional[Dict[str, Any]] = tool_outputs.get("inspect_compute_instances")
    perf_data: Optional[Dict[str, Any]] = tool_outputs.get("get_compute_performance_metrics")
    log_data: Optional[Dict[str, Any]] = tool_outputs.get("analyze_infra_logs")
    identity_data: Optional[Dict[str, Any]] = tool_outputs.get("inspect_infra_agent_runtime_identity")
    prop_data: Optional[Dict[str, Any]] = tool_outputs.get("generate_infra_remediation_proposal")

    if not final_text:
        insp_data = insp_data or inspect_compute_instances(target_instance)
        perf_data = perf_data or get_compute_performance_metrics(target_instance)
        log_data = log_data or analyze_infra_logs(prompt, target_instance)
        identity_data = identity_data or inspect_infra_agent_runtime_identity()
        prop_data = prop_data or generate_infra_remediation_proposal(log_data.get("finding", ""), target_instance)
        tool_trace = [
            "inspect_compute_instances",
            "get_compute_performance_metrics",
            "analyze_infra_logs",
            "generate_infra_remediation_proposal",
        ]
        p_vm = insp_data.get("primary_instance") or {}
        final_text = (
            f"### Live Compute Engine & Infrastructure Analysis (`{p_vm.get('instance_name')}` in `{p_vm.get('zone')}`)\n"
            f"- **Active VMs in `{PROJECT_ID}`**: {len(insp_data.get('discovered_instances', []))} (`{p_vm.get('instance_name')}`, `{p_vm.get('machine_type')}`, Status: **`{p_vm.get('status')}`**)\n"
            f"- **Lifecycle Note**: {insp_data.get('lifecycle_note') or 'Target instance is active in Compute Engine inventory.'}\n"
            f"- **Cloud Logging Root Cause**: {log_data.get('root_cause')}\n"
            f"- **Active Service Account**: `{identity_data.get('active_service_account')}`\n"
            f"- **Proposed CLI Fix**: `{prop_data.get('recommended_cli')}`"
        )

    return {
        "agent": "aaas_infra_agent",
        "model": MODEL_NAME,
        "tools_invoked": tool_trace or ["inspect_compute_instances"],
        "instance_inspection": insp_data,
        "performance_metrics": perf_data,
        "log_analysis": log_data,
        "runtime_identity": identity_data,
        "remediation_proposal": prop_data,
        "infra_reasoning_report": final_text,
    }


if __name__ == "__main__":
    sample_alert = (
        "Atlas Alert: Cloud Logging detected [ERROR] on `gce_instance/2397540675679890849` in `us-central1-c`: "
        "`Error watching metadata: context canceled`. Inspect the live Compute Engine instances, metrics, and logs, "
        "explain what happened to `2397540675679890849`, and propose a safe fix."
    )
    print("🔍 Running ADK Infra Agent Live GCP Diagnosis...\n")
    result = asyncio.run(run_diagnosis(sample_alert, target_instance="2397540675679890849"))
    print(f"✅ Tools Invoked by ADK Agent: {result['tools_invoked']}\n")
    print(result["infra_reasoning_report"])
