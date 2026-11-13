"""
GitOps & Recent Deployment Correlator (`poc/services/gitops_correlator.py`).

Provides two core capabilities on the Infra / Serverless diagnostic & remediation path:
  1. `correlate_recent_deployments(...)`: Correlates an incident occurrence timestamp against
     recent Git commits (via `git log`) and optional CI/CD deployment records (Cloud Run revisions,
     ArgoCD/Flux syncs, GitHub deployments) to identify high-confidence suspect releases.
  2. `build_gitops_reconciliation_pr_payload(...)`: Produces a structured, GitHub/GitLab-compatible
     Bidirectional GitOps Reconciliation Pull Request payload (declarative Terraform/manifest diff,
     metadata audit trail, branch names, PR body, and optional revert recommendation) rather than
     only emitting raw imperative CLI commands.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]


def _parse_iso_timestamp(ts: Optional[str]) -> datetime.datetime:
    if not ts:
        return datetime.datetime.now(datetime.timezone.utc)
    cleaned = str(ts).strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except ValueError:
        return datetime.datetime.now(datetime.timezone.utc)


def _read_local_git_commits(repo_path: Optional[Path] = None, max_commits: int = 20) -> List[Dict[str, Any]]:
    """Reads recent commits and touched files from the local Git repository (read-only)."""
    target_dir = Path(repo_path) if repo_path else REPO_ROOT
    if not target_dir.exists():
        return []
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(target_dir),
                "log",
                f"-n{max(1, int(max_commits))}",
                "--date=iso-strict",
                "--pretty=format:===COMMIT===%n%H|%h|%an|%ae|%ad|%s",
                "--name-only",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
    except Exception:
        return []

    commits: List[Dict[str, Any]] = []
    blocks = proc.stdout.split("===COMMIT===")
    for block in blocks:
        lines = [ln.strip() for ln in block.strip().splitlines() if ln.strip()]
        if not lines:
            continue
        header_parts = lines[0].split("|", 5)
        if len(header_parts) < 6:
            continue
        sha, short_sha, author, email, committed_at, subject = header_parts
        changed_files = [f for f in lines[1:] if f]
        commits.append(
            {
                "event_type": "git_commit",
                "commit_sha": sha,
                "short_sha": short_sha,
                "author": author,
                "author_email": email,
                "committed_at": committed_at,
                "subject": subject,
                "changed_files": changed_files,
            }
        )
    return commits


class GitOpsDeploymentCorrelator:
    """
    Correlates infrastructure/serverless incidents with recent Git commits & deployments
    and generates structured Bidirectional GitOps Reconciliation PR payloads.
    """

    def __init__(
        self,
        repo_path: Optional[Path] = None,
        default_repo_slug: Optional[str] = None,
        default_base_branch: str = "main",
    ) -> None:
        self.repo_path = Path(repo_path) if repo_path else REPO_ROOT
        self.default_repo_slug = (
            default_repo_slug
            or os.getenv("AAAS_GITOPS_REPO")
            or "harisankar/AgentTriad"
        )
        self.default_base_branch = os.getenv("AAAS_GITOPS_BASE_BRANCH", default_base_branch)

    def correlate_recent_deployments(
        self,
        incident_timestamp: Optional[str] = None,
        workload: str = "",
        window_minutes: int = 180,
        git_commits: Optional[List[Dict[str, Any]]] = None,
        deployments: Optional[List[Dict[str, Any]]] = None,
        max_commits: int = 20,
    ) -> Dict[str, Any]:
        """
        Correlates `incident_timestamp` and `workload` against recent Git commits and
        CI/CD deployment records within `window_minutes` prior to the incident.
        """
        inc_dt = _parse_iso_timestamp(incident_timestamp)
        commits = list(git_commits) if git_commits is not None else _read_local_git_commits(
            repo_path=self.repo_path, max_commits=max_commits
        )

        # Normalize optional deployment events into the same candidate schema
        candidates: List[Dict[str, Any]] = list(commits)
        for dep in deployments or []:
            candidates.append(
                {
                    "event_type": dep.get("event_type", "deployment"),
                    "commit_sha": dep.get("commit_sha") or dep.get("revision") or dep.get("id", "unknown"),
                    "short_sha": str(dep.get("commit_sha") or dep.get("revision") or "deploy")[:8],
                    "author": dep.get("author") or dep.get("actor") or "ci-cd-pipeline",
                    "author_email": dep.get("author_email", ""),
                    "committed_at": dep.get("deployed_at") or dep.get("timestamp") or dep.get("committed_at"),
                    "subject": dep.get("summary") or dep.get("subject") or f"Deployment {dep.get('revision', '')}",
                    "changed_files": list(dep.get("changed_files") or []),
                    "service": dep.get("service") or dep.get("workload") or "",
                    "revision": dep.get("revision"),
                    "environment": dep.get("environment", "production"),
                }
            )

        workload_tokens = [
            tok
            for tok in re.split(r"[^a-z0-9]+", (workload or "").lower())
            if len(tok) >= 3 and tok not in ("service", "deployment", "default", "prod", "app", "gce", "instance")
        ]
        infra_keywords = (
            "terraform",
            ".tf",
            "infra",
            "cloudrun",
            "cloud-run",
            "serverless",
            "dockerfile",
            "k8s",
            "helm",
            "cloudbuild",
            "deploy",
            "iam",
            "vpc",
            "firewall",
            "compute",
            "agent",
        )

        correlated: List[Dict[str, Any]] = []
        for item in candidates:
            ev_dt = _parse_iso_timestamp(item.get("committed_at"))
            delta_minutes = round((inc_dt - ev_dt).total_seconds() / 60.0, 2)
            # Only correlate changes that occurred BEFORE (or within 2 min clock skew of) the incident
            if delta_minutes < -2.0 or delta_minutes > float(window_minutes):
                continue

            # 1. Temporal proximity score (0.0 .. 0.65)
            abs_delta = max(0.0, delta_minutes)
            if abs_delta <= 15.0:
                time_score = 0.65
            elif abs_delta <= 45.0:
                time_score = 0.50
            elif abs_delta <= 120.0:
                time_score = 0.35
            else:
                time_score = 0.20

            # 2. Path / workload / infra relevance score (0.0 .. 0.35)
            changed_files = [str(f) for f in (item.get("changed_files") or [])]
            subject_lower = str(item.get("subject") or "").lower()
            service_lower = str(item.get("service") or "").lower()
            blob = " ".join([subject_lower, service_lower, *[f.lower() for f in changed_files]])

            relevance_score = 0.0
            matched_reasons: List[str] = []
            if any(tok in blob for tok in workload_tokens):
                relevance_score += 0.25
                matched_reasons.append(f"Touches workload identifier `{workload}`")
            if any(kw in blob for kw in infra_keywords):
                relevance_score += 0.10
                matched_reasons.append("Modifies infrastructure / deployment configuration")
            if not matched_reasons:
                matched_reasons.append(f"Occurred {abs_delta:.1f}m before incident window")

            total_score = round(min(0.99, time_score + relevance_score), 2)
            confidence = "HIGH" if total_score >= 0.70 else ("MEDIUM" if total_score >= 0.45 else "LOW")
            suggested_action = (
                "REVERT_COMMIT_VIA_GITOPS_PR"
                if confidence == "HIGH" and item.get("event_type") == "git_commit"
                else "PATCH_DECLARATIVE_MANIFEST_VIA_GITOPS_PR"
            )

            correlated.append(
                {
                    "event_type": item.get("event_type", "git_commit"),
                    "commit_sha": item.get("commit_sha"),
                    "short_sha": item.get("short_sha") or str(item.get("commit_sha") or "")[:8],
                    "author": item.get("author"),
                    "committed_at": ev_dt.isoformat(),
                    "delta_minutes_before_incident": delta_minutes,
                    "subject": item.get("subject"),
                    "changed_files": changed_files[:12],
                    "correlation_score": total_score,
                    "confidence": confidence,
                    "match_reasons": matched_reasons,
                    "suggested_action": suggested_action,
                }
            )

        correlated.sort(key=lambda c: (-c["correlation_score"], abs(c["delta_minutes_before_incident"])))
        top_match = correlated[0] if correlated else None

        return {
            "status": "CORRELATED_RECENT_DEPLOYMENT" if top_match else "NO_RECENT_DEPLOYMENT_CORRELATION",
            "incident_timestamp": inc_dt.isoformat(),
            "workload": workload or "unknown-workload",
            "window_minutes": int(window_minutes),
            "scanned_event_count": len(candidates),
            "correlated_count": len(correlated),
            "highest_confidence_match": top_match,
            "correlated_events": correlated[:5],
            "summary": (
                f"Correlated incident on `{workload}` with `{top_match['short_sha']}` by {top_match['author']} "
                f"({top_match['delta_minutes_before_incident']}m before incident, confidence={top_match['confidence']}, "
                f"score={top_match['correlation_score']}): {top_match['subject']}"
                if top_match
                else f"No Git commits or deployments matched within {window_minutes}m prior to incident on `{workload}`."
            ),
        }

    def build_gitops_reconciliation_pr_payload(
        self,
        incident_id: str,
        workload: str,
        target_cloud: str = "gcp",
        recommended_cli: str = "",
        terraform_hcl: Optional[str] = None,
        correlation_report: Optional[Dict[str, Any]] = None,
        reason: str = "",
        repo_slug: Optional[str] = None,
        base_branch: Optional[str] = None,
        pr_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Builds a Bidirectional GitOps Reconciliation PR payload (GitHub/GitLab API ready)
        capturing declarative IaC/manifest changes + suspect commit correlation + rollback metadata
        instead of relying solely on imperative CLI commands.
        """
        cloud = (target_cloud or "gcp").strip().lower()
        clean_workload = re.sub(r"[^a-zA-Z0-9_-]", "-", (workload or "workload").split("/")[-1]).strip("-") or "workload"
        short_id = re.sub(r"[^a-zA-Z0-9]", "", str(incident_id or uuid.uuid4().hex))[:8] or uuid.uuid4().hex[:8]
        resolved_pr_id = pr_id or f"PR-{uuid.uuid4().int % 900 + 100}"
        head_branch = f"aaas/gitops-reconcile-{clean_workload.lower()}-{short_id.lower()}"
        resolved_repo = repo_slug or self.default_repo_slug
        resolved_base = base_branch or self.default_base_branch

        top_match = (correlation_report or {}).get("highest_confidence_match")
        suspect_sha = top_match.get("commit_sha") if isinstance(top_match, dict) else None
        suspect_short = top_match.get("short_sha") if isinstance(top_match, dict) else None
        revert_recommended = bool(
            isinstance(top_match, dict) and top_match.get("suggested_action") == "REVERT_COMMIT_VIA_GITOPS_PR"
        )

        # Build declarative manifest / Terraform content if HCL wasn't already supplied
        if terraform_hcl and terraform_hcl.strip():
            declarative_path = f"gitops/reconciliations/{cloud}/{clean_workload}/main.tf"
            declarative_content = terraform_hcl.strip() + "\n"
            manifest_format = "terraform_hcl"
        else:
            declarative_path = f"gitops/reconciliations/{cloud}/{clean_workload}/remediation-patch.yaml"
            declarative_content = (
                f"apiVersion: aaas.agenttriad.io/v1alpha1\n"
                f"kind: GitOpsReconciliationPatch\n"
                f"metadata:\n"
                f"  name: {clean_workload}-{short_id.lower()}\n"
                f"  labels:\n"
                f"    cloud: {cloud}\n"
                f"    incidentId: \"{incident_id}\"\n"
                f"spec:\n"
                f"  workload: \"{workload}\"\n"
                f"  targetCloud: \"{cloud}\"\n"
                f"  remediationReason: {json.dumps(reason or 'Declarative GitOps state reconciliation')}\n"
                f"  revertCommitSha: {json.dumps(suspect_sha) if suspect_sha else 'null'}\n"
                f"  imperativeFallbackCli: {json.dumps(recommended_cli)}\n"
                f"  preventDestroy: true\n"
            )
            manifest_format = "gitops_yaml_patch"

        metadata_doc = {
            "pr_id": resolved_pr_id,
            "incident_id": incident_id,
            "workload": workload,
            "target_cloud": cloud,
            "reconciliation_mode": "BIDIRECTIONAL_GITOPS_PR",
            "correlated_suspect_commit": suspect_sha,
            "revert_recommended": revert_recommended,
            "cli_fallback_reference": recommended_cli,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        metadata_path = f"gitops/reconciliations/{cloud}/{clean_workload}/reconciliation-metadata.json"

        pr_title = (
            f"[AaaS GitOps] Reconcile {clean_workload} ({cloud.upper()}) — revert/patch after {suspect_short}"
            if suspect_short
            else f"[AaaS GitOps] Bidirectional reconciliation for {clean_workload} ({cloud.upper()})"
        )

        correlation_section = (
            f"- **Correlated Recent Deployment/Commit**: `{suspect_short}` (`{suspect_sha}`)\n"
            f"  - **Author**: {top_match.get('author')} • **Delta**: `{top_match.get('delta_minutes_before_incident')}m` before incident\n"
            f"  - **Subject**: {top_match.get('subject')}\n"
            f"  - **Confidence**: `{top_match.get('confidence')}` (score `{top_match.get('correlation_score')}`)\n"
            f"  - **Recommended GitOps Action**: `{top_match.get('suggested_action')}`\n"
            if isinstance(top_match, dict)
            else "- **Correlated Recent Deployment/Commit**: None within lookback window (state-drift reconciliation).\n"
        )

        pr_body = (
            f"## Bidirectional GitOps Reconciliation ({resolved_pr_id})\n\n"
            f"- **Incident ID**: `{incident_id}`\n"
            f"- **Target Workload**: `{workload}` (`{cloud.upper()}`)\n"
            f"- **Summary**: {reason or 'Synchronizes declarative Git repository state with approved runtime remediation.'}\n"
            f"{correlation_section}\n"
            f"### Declarative Files Updated\n"
            f"- `{declarative_path}` (`{manifest_format}`)\n"
            f"- `{metadata_path}` (Audit & drift-tracking metadata)\n\n"
            f"### Imperative CLI Reference (Audited Fallback Only)\n"
            f"```bash\n{recommended_cli or '# Declarative-only GitOps change'}\n```\n\n"
            f"> Generated by **AgentTriad AaaS** with `prevent_destroy = true` and 45s Telemetry Watchdog protection.\n"
        )

        return {
            "reconciliation_mode": "BIDIRECTIONAL_GITOPS_PR",
            "pr_id": resolved_pr_id,
            "repository": resolved_repo,
            "base_branch": resolved_base,
            "head_branch": head_branch,
            "title": pr_title,
            "body": pr_body,
            "labels": [
                "aaas-gitops",
                "bidirectional-reconciliation",
                f"cloud:{cloud}",
                "auto-generated",
            ],
            "draft": False,
            "manifest_format": manifest_format,
            "correlated_suspect_commit": suspect_sha,
            "revert_recommended": revert_recommended,
            "revert_command": f"git revert --no-edit {suspect_sha}" if (revert_recommended and suspect_sha) else None,
            "files": [
                {
                    "path": declarative_path,
                    "action": "upsert",
                    "content": declarative_content,
                },
                {
                    "path": metadata_path,
                    "action": "upsert",
                    "content": json.dumps(metadata_doc, indent=2) + "\n",
                },
            ],
            "cli_fallback_reference": recommended_cli,
            "drift_prevention_guarantee": (
                "Reconciles declarative Git source of truth bidirectionally so ArgoCD / Flux / Terraform CI "
                "converges with runtime state without configuration drift."
            ),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


gitops_correlator = GitOpsDeploymentCorrelator()


def correlate_gitops_deployments_tool(
    workload: str,
    incident_timestamp: str = "",
    window_minutes: int = 180,
    target_cloud: str = "gcp",
    recommended_cli: str = "",
) -> Dict[str, Any]:
    """
    ADK FunctionTool: Correlates an infrastructure/serverless incident timestamp with recent
    Git commits & deployments and builds a Bidirectional GitOps Reconciliation PR payload.
    """
    correlation = gitops_correlator.correlate_recent_deployments(
        incident_timestamp=incident_timestamp or None,
        workload=workload,
        window_minutes=window_minutes,
    )
    pr_payload = gitops_correlator.build_gitops_reconciliation_pr_payload(
        incident_id=f"corr-{uuid.uuid4().hex[:8]}",
        workload=workload,
        target_cloud=target_cloud,
        recommended_cli=recommended_cli,
        correlation_report=correlation,
        reason=correlation.get("summary", ""),
    )
    return {
        "correlation": correlation,
        "gitops_pr_payload": pr_payload,
    }
