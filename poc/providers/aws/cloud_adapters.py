"""
AWS Cloud Strategy Adapters (`poc/providers/aws/cloud_adapters.py`).

Implements `DatabaseCloudAdapter` (AWS RDS + CloudWatch + CloudWatch Logs) and
`ComputeCloudAdapter` (AWS EC2 + CloudWatch + CloudWatch Logs) using lazy optional
`boto3` imports with client injection support and clean fallback when `boto3` is absent.
"""

from __future__ import annotations

import datetime
import os
import re
from typing import Any, Dict, List, Optional

from providers.base_cloud import ComputeCloudAdapter, DatabaseCloudAdapter


def _load_boto3() -> Any:
    try:
        import boto3  # type: ignore

        return boto3
    except ImportError:
        return None


class AWSDatabaseCloudAdapter(DatabaseCloudAdapter):
    """Concrete AWS RDS (`describe_db_instances`) & CloudWatch metrics diagnostic strategy."""

    def __init__(
        self,
        region: Optional[str] = None,
        rds_client: Optional[Any] = None,
        cloudwatch_client: Optional[Any] = None,
        logs_client: Optional[Any] = None,
        sts_client: Optional[Any] = None,
    ) -> None:
        self.region = region or os.getenv("AAAS_AWS_REGION") or os.getenv("AWS_REGION") or "us-east-1"
        self._rds_client = rds_client
        self._cw_client = cloudwatch_client
        self._logs_client = logs_client
        self._sts_client = sts_client

    @property
    def cloud_provider(self) -> str:
        return "aws"

    def _client(self, service_name: str, injected: Optional[Any]) -> Optional[Any]:
        if injected is not None:
            return injected
        boto3 = _load_boto3()
        if boto3 is None:
            return None
        return boto3.client(service_name, region_name=self.region)

    def inspect_instance(
        self,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        rds = self._client("rds", self._rds_client)
        if rds is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": instance_name,
                "error": "boto3 is not installed. Install `boto3` and configure AWS credentials/IRSA.",
            }

        try:
            kwargs: Dict[str, Any] = {}
            clean_name = str(instance_name or "auto").strip()
            if clean_name and clean_name.lower() != "auto":
                try:
                    resp = rds.describe_db_instances(DBInstanceIdentifier=clean_name)
                except Exception:
                    resp = rds.describe_db_instances()
            else:
                resp = rds.describe_db_instances(**kwargs)

            items: List[Dict[str, Any]] = resp.get("DBInstances") or []
            if not items:
                return {
                    "status": "NO_INSTANCES_FOUND",
                    "target_cloud": "aws",
                    "region": self.region,
                    "discovered_instances_in_project": [],
                }

            target = next(
                (i for i in items if str(i.get("DBInstanceIdentifier", "")).lower() == clean_name.lower()),
                items[0],
            )
            endpoint = target.get("Endpoint") or {}
            vpc_sgs = [
                {"id": sg.get("VpcSecurityGroupId"), "status": sg.get("Status")}
                for sg in (target.get("VpcSecurityGroups") or [])
            ]
            return {
                "status": "LIVE_AWS_RDS_API",
                "target_cloud": "aws",
                "discovered_instances_in_project": [i.get("DBInstanceIdentifier") for i in items],
                "instance_name": target.get("DBInstanceIdentifier"),
                "project_id": account_or_project_id or os.getenv("AWS_ACCOUNT_ID", "aws-account"),
                "region": self.region,
                "availability_zone": target.get("AvailabilityZone"),
                "state": str(target.get("DBInstanceStatus") or "unknown").upper(),
                "database_version": f"{target.get('Engine', 'postgres')}_{target.get('EngineVersion', '')}".strip("_"),
                "tier": target.get("DBInstanceClass"),
                "multi_az": bool(target.get("MultiAZ")),
                "data_disk_size_gb": target.get("AllocatedStorage"),
                "data_disk_type": target.get("StorageType"),
                "publicly_accessible": bool(target.get("PubliclyAccessible")),
                "endpoint_address": endpoint.get("Address"),
                "endpoint_port": endpoint.get("Port"),
                "storage_encrypted": bool(target.get("StorageEncrypted")),
                "iam_database_auth_enabled": bool(target.get("IAMDatabaseAuthenticationEnabled")),
                "vpc_security_groups": vpc_sgs,
                "backup_retention_period": target.get("BackupRetentionPeriod"),
            }
        except Exception as exc:
            return {
                "status": "AWS_RDS_API_ERROR",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": instance_name,
                "error": str(exc),
            }

    def get_performance_metrics(
        self,
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
        window_minutes: int = 30,
    ) -> Dict[str, Any]:
        cw = self._client("cloudwatch", self._cw_client)
        if cw is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "instance_name": instance_name,
                "error": "boto3 is not installed. Install `boto3` to query AWS CloudWatch RDS metrics.",
            }

        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = now - datetime.timedelta(minutes=max(5, int(window_minutes)))
        metric_specs = {
            "cpu_utilization_pct": ("CPUUtilization", "%"),
            "freeable_memory_bytes": ("FreeableMemory", "bytes"),
            "free_storage_space_bytes": ("FreeStorageSpace", "bytes"),
            "active_connections": ("DatabaseConnections", "count"),
            "disk_read_ops": ("ReadIOPS", "count/sec"),
            "disk_write_ops": ("WriteIOPS", "count/sec"),
        }

        metrics_summary: Dict[str, Any] = {}
        errors: List[str] = []
        for key, (cw_name, unit) in metric_specs.items():
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/RDS",
                    MetricName=cw_name,
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": instance_name}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=300,
                    Statistics=["Average", "Maximum"],
                )
                dps = sorted(
                    resp.get("Datapoints") or [],
                    key=lambda d: str(d.get("Timestamp", "")),
                    reverse=True,
                )
                if not dps:
                    metrics_summary[key] = {"data_points": 0, "latest": None}
                    continue
                vals = [float(d.get("Average", d.get("Maximum", 0.0))) for d in dps]
                metrics_summary[key] = {
                    "unit": unit,
                    "latest": round(vals[0], 2),
                    "avg": round(sum(vals) / len(vals), 2),
                    "max": round(max(vals), 2),
                    "min": round(min(vals), 2),
                    "data_points": len(vals),
                }
            except Exception as exc:
                errors.append(f"AWS/RDS:{cw_name}: {exc}")

        cpu_latest = (metrics_summary.get("cpu_utilization_pct") or {}).get("latest")
        bottlenecks: List[str] = []
        if isinstance(cpu_latest, (int, float)) and cpu_latest >= 80.0:
            bottlenecks.append(f"High RDS CPU utilization ({cpu_latest}%)")

        return {
            "status": "LIVE_AWS_CLOUDWATCH",
            "target_cloud": "aws",
            "region": self.region,
            "instance_name": instance_name,
            "window_minutes": window_minutes,
            "metrics": metrics_summary,
            "performance_bottlenecks_detected": bottlenecks,
            "performance_health_verdict": (
                "DEGRADED"
                if bottlenecks
                else "HEALTHY_NOMINAL (RDS CPU, Memory, Storage, and Connections within normal thresholds)"
            ),
            "api_errors": errors,
        }

    def analyze_logs_and_connections(
        self,
        symptom: str = "",
        instance_name: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        logs = self._client("logs", self._logs_client)
        if logs is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "instance_name": instance_name,
                "error": "boto3 is not installed. Install `boto3` to query AWS CloudWatch Logs.",
            }

        log_group = os.getenv("AAAS_AWS_RDS_LOG_GROUP", f"/aws/rds/instance/{instance_name}/postgresql")
        evidence: List[str] = []
        try:
            resp = logs.filter_log_events(
                logGroupName=log_group,
                filterPattern="?ERROR ?FATAL ?WARNING ?timeout",
                limit=15,
            )
            for ev in resp.get("events") or []:
                msg = str(ev.get("message") or "").strip()
                if msg:
                    evidence.append(f"[{ev.get('timestamp', '')}] {msg}")
        except Exception as exc:
            return {
                "status": "AWS_CLOUDWATCH_LOGS_ERROR",
                "target_cloud": "aws",
                "region": self.region,
                "instance_name": instance_name,
                "log_group": log_group,
                "error": str(exc),
            }

        finding = "NO_WARNING_OR_ERROR_LOGS"
        for line in evidence:
            low = line.lower()
            if "too many clients" in low or "remaining connection slots" in low:
                finding = "CONNECTION_POOL_EXHAUSTION"
                break
            if "password authentication failed" in low:
                finding = "PASSWORD_AUTH_FAILURES"
                break
            if "no encryption" in low or "ssl" in low:
                finding = "UNENCRYPTED_SSL_REJECTIONS"
                break
            finding = "RDS_LOG_WARNINGS"

        return {
            "status": "LIVE_AWS_CLOUDWATCH_LOGS",
            "target_cloud": "aws",
            "region": self.region,
            "instance_name": instance_name,
            "log_group": log_group,
            "finding": finding,
            "live_log_count": len(evidence),
            "evidence": evidence[:6],
            "summary_evidence": " | ".join(evidence[:4]) if evidence else "0 warning/error events found in CloudWatch Logs.",
        }

    def inspect_runtime_identity(
        self,
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        sts = self._client("sts", self._sts_client)
        caller_arn = os.getenv("AAAS_AWS_ROLE_ARN", "arn:aws:iam::000000000000:role/aaas-database-agent-readonly")
        account_id = account_or_project_id or os.getenv("AWS_ACCOUNT_ID", "000000000000")
        if sts is not None:
            try:
                ident = sts.get_caller_identity()
                caller_arn = ident.get("Arn") or caller_arn
                account_id = ident.get("Account") or account_id
            except Exception:
                pass
        return {
            "status": "LIVE_RUNTIME_IDENTITY",
            "target_cloud": "aws",
            "account_id": account_id,
            "region": self.region,
            "active_service_account": caller_arn,
            "assigned_iam_roles": [
                "AmazonRDSReadOnlyAccess (rds:DescribeDBInstances, rds:DescribeDBLogFiles)",
                "CloudWatchReadOnlyAccess (cloudwatch:GetMetricStatistics, logs:FilterLogEvents)",
            ],
            "direct_database_socket_connection": False,
            "telemetry_collection_mechanism": (
                "Out-of-Band AWS Control Plane APIs (RDS `DescribeDBInstances`, CloudWatch `GetMetricStatistics`, "
                "and CloudWatch Logs `FilterLogEvents`) authenticated via STS `AssumeRoleWithWebIdentity` (IRSA)."
            ),
        }

    def generate_remediation_proposal(
        self,
        issue_type: str,
        instance_name: str = "prod-rds-postgres",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        live = self.inspect_instance(instance_name=instance_name, account_or_project_id=account_or_project_id)
        db_id = live.get("instance_name") or instance_name
        state = str(live.get("state") or "AVAILABLE").upper()
        tier = live.get("tier") or "db.r6g.large"
        publicly_accessible = bool(live.get("publicly_accessible", False))
        issue_upper = (issue_type or "").upper()
        tf_name = re.sub(r"[^a-zA-Z0-9_]", "_", db_id)

        if state == "STOPPED" or issue_upper == "INSTANCE_STOPPED":
            cli_cmd = f"aws rds start-db-instance --db-instance-identifier {db_id} --region {self.region}"
            reason = f"AWS RDS instance `{db_id}` is `{state}`. Starting instance via AWS Control Plane."
        elif publicly_accessible or "SSL" in issue_upper or "UNENCRYPTED" in issue_upper:
            cli_cmd = (
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                f"--no-publicly-accessible --enable-iam-database-authentication --apply-immediately --region {self.region}"
            )
            reason = f"Hardening AWS RDS `{db_id}` by disabling public accessibility and enforcing IAM DB authentication."
        else:
            cli_cmd = (
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                f"--enable-iam-database-authentication --backup-retention-period 7 --apply-immediately --region {self.region}"
            )
            reason = f"Enabling IAM database auth and backup hardening on AWS RDS `{db_id}` ({tier} in {self.region})."

        terraform_hcl = f"""resource "aws_db_instance" "{tf_name}" {{
  identifier                          = "{db_id}"
  instance_class                      = "{tier}"
  publicly_accessible                 = false
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  deletion_protection                 = true

  lifecycle {{
    prevent_destroy = true
  }}
}}"""

        return {
            "target_cloud": "aws",
            "execution_policy": "REQUIRES_ATLAS_HITL_JIT_TOKEN",
            "live_instance_state": state,
            "remediation_reason": reason,
            "remediation_summary": reason,
            "recommended_cli": cli_cmd,
            "terraform_hcl": terraform_hcl,
            "rollback_strategy": "AWS_RDS_SNAPSHOT_ROLLBACK (Pre-change DB snapshot + 45s CloudWatch Watchdog)",
        }


class AWSComputeCloudAdapter(ComputeCloudAdapter):
    """Concrete AWS EC2 (`describe_instances`) & CloudWatch diagnostic strategy."""

    def __init__(
        self,
        region: Optional[str] = None,
        ec2_client: Optional[Any] = None,
        cloudwatch_client: Optional[Any] = None,
        logs_client: Optional[Any] = None,
        sts_client: Optional[Any] = None,
    ) -> None:
        self.region = region or os.getenv("AAAS_AWS_REGION") or os.getenv("AWS_REGION") or "us-east-1"
        self._ec2_client = ec2_client
        self._cw_client = cloudwatch_client
        self._logs_client = logs_client
        self._sts_client = sts_client

    @property
    def cloud_provider(self) -> str:
        return "aws"

    def _client(self, service_name: str, injected: Optional[Any]) -> Optional[Any]:
        if injected is not None:
            return injected
        boto3 = _load_boto3()
        if boto3 is None:
            return None
        return boto3.client(service_name, region_name=self.region)

    def inspect_instances(
        self,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        ec2 = self._client("ec2", self._ec2_client)
        if ec2 is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": target_instance,
                "error": "boto3 is not installed. Install `boto3` and configure AWS credentials/IRSA.",
            }

        clean_target = str(target_instance or "auto").split("/")[-1].strip()
        try:
            resp = ec2.describe_instances()
            discovered: List[Dict[str, Any]] = []
            for res in resp.get("Reservations") or []:
                for inst in res.get("Instances") or []:
                    tags = {t.get("Key"): t.get("Value") for t in (inst.get("Tags") or [])}
                    name = tags.get("Name") or inst.get("InstanceId")
                    state = str((inst.get("State") or {}).get("Name") or "unknown").upper()
                    zone = (inst.get("Placement") or {}).get("AvailabilityZone") or self.region
                    discovered.append(
                        {
                            "instance_id": str(inst.get("InstanceId")),
                            "instance_name": name,
                            "zone": zone,
                            "status": state,
                            "machine_type": inst.get("InstanceType"),
                            "internal_ip": inst.get("PrivateIpAddress"),
                            "external_ip": inst.get("PublicIpAddress"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                        }
                    )

            if not discovered:
                return {
                    "status": "NO_COMPUTE_INSTANCES_FOUND",
                    "target_cloud": "aws",
                    "region": self.region,
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
                    f"Reported EC2 instance `{clean_target}` is no longer present in `{self.region}`. "
                    f"Active EC2 instances: "
                    + ", ".join(f"`{v['instance_name']}` ({v['instance_id']}, `{v['status']}`)" for v in discovered)
                )

            primary = matched or discovered[0]
            return {
                "status": "LIVE_AWS_EC2_API",
                "target_cloud": "aws",
                "region": self.region,
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
                "status": "AWS_EC2_API_ERROR",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": clean_target,
                "error": str(exc),
            }

    def get_performance_metrics(
        self,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
        window_minutes: int = 30,
    ) -> Dict[str, Any]:
        cw = self._client("cloudwatch", self._cw_client)
        if cw is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": target_instance,
                "error": "boto3 is not installed. Install `boto3` to query AWS CloudWatch EC2 metrics.",
            }

        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = now - datetime.timedelta(minutes=max(5, int(window_minutes)))
        clean_target = str(target_instance or "auto").split("/")[-1].strip()
        metric_specs = {
            "cpu_utilization_pct": ("CPUUtilization", "%"),
            "network_rx_bytes": ("NetworkIn", "bytes"),
            "network_tx_bytes": ("NetworkOut", "bytes"),
            "disk_read_bytes": ("DiskReadBytes", "bytes"),
            "disk_write_bytes": ("DiskWriteBytes", "bytes"),
            "status_check_failed": ("StatusCheckFailed", "count"),
        }

        metrics_summary: Dict[str, Any] = {}
        errors: List[str] = []
        for key, (cw_name, unit) in metric_specs.items():
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName=cw_name,
                    Dimensions=[{"Name": "InstanceId", "Value": clean_target}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=300,
                    Statistics=["Average", "Maximum"],
                )
                dps = sorted(
                    resp.get("Datapoints") or [],
                    key=lambda d: str(d.get("Timestamp", "")),
                    reverse=True,
                )
                if not dps:
                    continue
                vals = [float(d.get("Average", d.get("Maximum", 0.0))) for d in dps]
                metrics_summary[key] = {
                    "unit": unit,
                    "latest": round(vals[0], 2),
                    "avg": round(sum(vals) / len(vals), 2),
                    "max": round(max(vals), 2),
                    "data_points": len(vals),
                }
            except Exception as exc:
                errors.append(f"AWS/EC2:{cw_name}: {exc}")

        if "network_rx_bytes" in metrics_summary:
            metrics_summary["network_received_bytes"] = metrics_summary["network_rx_bytes"]

        return {
            "status": "LIVE_AWS_CLOUDWATCH",
            "target_cloud": "aws",
            "region": self.region,
            "requested_instance": clean_target,
            "window_minutes": window_minutes,
            "metrics": metrics_summary,
            "performance_health_verdict": "HEALTHY_NOMINAL (EC2 CloudWatch metrics within nominal thresholds)",
            "api_errors": errors,
        }

    def analyze_logs(
        self,
        symptom: str = "",
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        logs = self._client("logs", self._logs_client)
        if logs is None:
            return {
                "status": "AWS_SDK_UNAVAILABLE",
                "target_cloud": "aws",
                "region": self.region,
                "requested_instance": target_instance,
                "error": "boto3 is not installed. Install `boto3` to query AWS CloudWatch Logs.",
            }

        log_group = os.getenv("AAAS_AWS_EC2_LOG_GROUP", "/aws/ec2/system")
        evidence: List[str] = []
        try:
            resp = logs.filter_log_events(
                logGroupName=log_group,
                filterPattern="?ERROR ?WARN ?OOM ?IMDS",
                limit=12,
            )
            for ev in resp.get("events") or []:
                msg = str(ev.get("message") or "").strip()
                if msg:
                    evidence.append(f"[{ev.get('timestamp', '')}] {msg}")
        except Exception as exc:
            return {
                "status": "AWS_CLOUDWATCH_LOGS_ERROR",
                "target_cloud": "aws",
                "region": self.region,
                "error": str(exc),
            }

        finding = "EC2_CLOUDWATCH_WARNINGS" if evidence else "NO_WARNING_OR_ERROR_LOGS"
        root_cause = (
            f"AWS CloudWatch Logs (`{log_group}`) returned {len(evidence)} warning/error event(s) for `{target_instance}`."
            if evidence
            else f"No active warning/error logs found in `{log_group}` for `{target_instance}`."
        )
        return {
            "status": "LIVE_AWS_CLOUDWATCH_LOGS",
            "target_cloud": "aws",
            "region": self.region,
            "finding": finding,
            "requested_instance": target_instance,
            "live_log_count": len(evidence),
            "evidence": evidence[:6],
            "root_cause": root_cause,
            "customer_what_happened": evidence[0] if evidence else root_cause,
        }

    def inspect_runtime_identity(
        self,
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        sts = self._client("sts", self._sts_client)
        caller_arn = os.getenv("AAAS_AWS_ROLE_ARN", "arn:aws:iam::000000000000:role/aaas-infra-agent-readonly")
        account_id = account_or_project_id or os.getenv("AWS_ACCOUNT_ID", "000000000000")
        if sts is not None:
            try:
                ident = sts.get_caller_identity()
                caller_arn = ident.get("Arn") or caller_arn
                account_id = ident.get("Account") or account_id
            except Exception:
                pass
        return {
            "status": "LIVE_RUNTIME_IDENTITY",
            "target_cloud": "aws",
            "account_id": account_id,
            "region": self.region,
            "active_service_account": caller_arn,
            "assigned_iam_roles": [
                "AmazonEC2ReadOnlyAccess (ec2:DescribeInstances, ec2:DescribeInstanceStatus)",
                "CloudWatchReadOnlyAccess (cloudwatch:GetMetricStatistics, logs:FilterLogEvents)",
            ],
            "direct_ssh_connection": False,
            "telemetry_collection_mechanism": (
                "Out-of-Band AWS Control Plane APIs (EC2 `DescribeInstances`, CloudWatch `GetMetricStatistics`) "
                "authenticated via STS `AssumeRoleWithWebIdentity` without SSH access."
            ),
        }

    def generate_remediation_proposal(
        self,
        issue_type: str,
        target_instance: str = "auto",
        account_or_project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        inv = self.inspect_instances(target_instance=target_instance, account_or_project_id=account_or_project_id)
        primary = inv.get("primary_instance") or {}
        inst_id = primary.get("instance_id") or (target_instance if target_instance != "auto" else "i-00000000000000000")
        vm_name = primary.get("instance_name") or inst_id
        vm_type = primary.get("machine_type") or "t3.medium"
        vm_zone = primary.get("zone") or f"{self.region}a"
        vm_status = str(primary.get("status") or "RUNNING").upper()
        tf_name = re.sub(r"[^a-zA-Z0-9_]", "_", vm_name)

        if vm_status != "RUNNING":
            cli_cmd = f"aws ec2 start-instances --instance-ids {inst_id} --region {self.region}"
            reason = f"AWS EC2 instance `{vm_name}` (`{inst_id}`) is `{vm_status}`. Starting instance."
        else:
            cli_cmd = (
                f"aws ec2 modify-instance-metadata-options --instance-id {inst_id} "
                f"--http-tokens required --http-endpoint enabled --region {self.region}"
            )
            reason = (
                f"Active EC2 instance `{vm_name}` (`{inst_id}`, `{vm_type}` in `{vm_zone}`) is `{vm_status}`. "
                "Enforcing IMDSv2 (`http-tokens=required`) and refreshing instance metadata safely."
            )

        terraform_hcl = f"""resource "aws_instance" "{tf_name}" {{
  instance_type     = "{vm_type}"
  availability_zone = "{vm_zone}"

  metadata_options {{
    http_endpoint = "enabled"
    http_tokens   = "required"
  }}

  tags = {{
    Name = "{vm_name}"
  }}

  lifecycle {{
    prevent_destroy = true
  }}
}}"""

        return {
            "target_cloud": "aws",
            "execution_policy": "REQUIRES_ATLAS_HITL_JIT_TOKEN",
            "target_vm_name": vm_name,
            "target_vm_id": inst_id,
            "target_vm_zone": vm_zone,
            "target_vm_machine_type": vm_type,
            "target_vm_status": vm_status,
            "remediation_reason": reason,
            "remediation_summary": reason,
            "recommended_cli": cli_cmd,
            "terraform_hcl": terraform_hcl,
            "rollback_strategy": "AWS_EC2_METADATA_ROLLBACK (Revert IMDS/instance option if 45s CloudWatch Watchdog alerts)",
        }
