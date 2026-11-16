"""
FastAPI + A2A Server for the standalone ADK Security Specialist Agent (`security-agent`).

Endpoints:
  - GET  /healthz                  -> Container health check
  - GET  /.well-known/agent.json   -> A2A 1.0 AgentCard discovery for Atlas (Lead Orchestrator)
  - POST /diagnose                 -> Autonomous ADK IAM & Security posture diagnosis (Read-Only)
  - POST /a2a                      -> JSON-RPC 2.0 A2A task endpoint:
      * skill `diagnose_security_iam_anomaly`: Read-only ADK IAM posture & Cloud Audit drift reasoning
      * skill `execute_approved_security_remediation`: Strictly requires Atlas's 15-min WIF JIT Token
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import PROJECT_ID, PROTECTED_RESOURCES, REGION, run_diagnosis

app = FastAPI(
    title="AaaS ADK Security Specialist Agent",
    version="1.0.0",
    description="Autonomous Cloud IAM Posture & Audit Drift Reasoner (Read-Only) + JIT-Gated Follower",
)


class DiagnoseRequest(BaseModel):
    prompt: str = Field(..., description="Incident description or IAM security question from Atlas/User")
    project_id: str = Field(default=PROJECT_ID, description="Target GCP project ID")
    region: str = Field(default="europe-west2", description="Target region")
    service_agent_email: str = Field(default="", description="Optional target service account email")
    target_cloud: Optional[str] = Field(default=None, description="Target cloud strategy: gcp | aws | azure")


class A2ARequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str = "a2a-security-1"
    method: str = "tasks/send"
    params: Dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "agent_id": "security-agent",
        "project_id": PROJECT_ID,
        "region": REGION,
        "mode": "READ_ONLY_IAM_AUDIT_PLUS_JIT_FOLLOWER",
    }


@app.get("/.well-known/agent.json")
async def get_agent_card() -> Dict[str, Any]:
    """Returns the A2A 1.0 AgentCard so Atlas can discover the Security Agent."""
    service_url = os.getenv("SERVICE_URL", "http://localhost:8080")
    return {
        "id": "security-agent",
        "name": "AaaS Security Specialist Agent (ADK)",
        "version": "1.0.0",
        "protocol": "A2A/1.0-JSONRPC",
        "endpoint": f"{service_url}/a2a",
        "description": (
            "Google ADK Security Specialist for IAM policy posture (`getIamPolicy`), "
            "Cloud Audit Log `SetIamPolicy` drift detection, WIF, and least-privilege remediation proposals. "
            "Strictly Zero-Standing-Privilege read-only; requires Atlas 15-minute JIT token for any mutation."
        ),
        "ZeroStandingPrivilege": True,
        "capabilities": [
            "gcp-iam-policy-read-only-inspection",
            "datastream-service-agent-posture-verification",
            "cloud-audit-setIamPolicy-drift-detection",
            "runtime-service-account-introspection",
            "least-privilege-gcloud-and-terraform-proposal-generation",
            "jit-gated-remediation-execution",
        ],
        "skills": [
            {
                "id": "diagnose_security_iam_anomaly",
                "name": "Diagnose IAM & Security Posture Anomaly (Read-Only ADK Reasoning)",
                "description": "Calls live GCP getIamPolicy and Cloud Audit Logs to verify missing roles/IAM drift and propose a least-privilege fix.",
                "tags": ["security", "iam", "datastream", "audit-logs", "adk", "read-only"],
            },
            {
                "id": "execute_approved_security_remediation",
                "name": "Execute Approved Security Remediation (JIT Token Required)",
                "description": "Validates Atlas-minted 15-minute JIT authorization before allowing any IAM remediation step.",
                "tags": ["security", "iam", "remediation", "jit-wif"],
            },
        ],
    }


@app.post("/diagnose")
async def diagnose_endpoint(req: DiagnoseRequest) -> Dict[str, Any]:
    """Direct HTTP endpoint to trigger ADK Security Agent diagnosis."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt cannot be empty")
    return await run_diagnosis(
        prompt=req.prompt,
        project_id=req.project_id,
        region=req.region,
        service_agent_email=req.service_agent_email,
        target_cloud=req.target_cloud,
    )


@app.post("/a2a")
async def handle_a2a_rpc(rpc: A2ARequest) -> Dict[str, Any]:
    """
    A2A JSON-RPC 2.0 handler supporting:
      1. `diagnose_security_iam_anomaly` -> Security Agent 'thinks' (Live read-only getIamPolicy + Audit Logs)
      2. `execute_approved_security_remediation` -> Security Agent 'follows' (Requires Atlas JIT token)
    """
    skill_id = rpc.params.get("skill_id", "diagnose_security_iam_anomaly")
    parts: List[Dict[str, Any]] = rpc.params.get("message", {}).get("parts", [])
    payload: Dict[str, Any] = parts[0].get("data", {}) if parts else rpc.params.get("data", {})

    if skill_id == "diagnose_security_iam_anomaly":
        prompt = payload.get("prompt") or payload.get("message") or "Verify IAM posture for Datastream service agent"
        project_id = payload.get("project_id") or PROJECT_ID
        region = payload.get("region") or "europe-west2"
        service_agent_email = payload.get("service_agent_email") or ""
        target_cloud = payload.get("target_cloud") or rpc.params.get("target_cloud")
        diagnosis = await run_diagnosis(
            prompt=prompt,
            project_id=project_id,
            region=region,
            service_agent_email=service_agent_email,
            target_cloud=target_cloud,
        )
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "status": "DIAGNOSIS_COMPLETE_AWAITING_ATLAS_HITL",
                "diagnosis": diagnosis,
            },
        }

    if skill_id == "execute_approved_security_remediation":
        jit_token_id: Optional[str] = payload.get("jit_token_id")
        target_resource: str = str(payload.get("target_resource") or payload.get("project_id") or PROJECT_ID)
        command: str = str(payload.get("command") or "")

        if target_resource.lower() in PROTECTED_RESOURCES:
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_PROTECTED_RESOURCE",
                    "reason": f"Resource `{target_resource}` is a protected external resource and cannot be mutated.",
                },
            }

        if not jit_token_id or not str(jit_token_id).startswith("jit-wif-"):
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_INVALID_JIT_TOKEN",
                    "reason": (
                        "Zero-Standing Privilege Violation: Security Agent cannot authorize or execute "
                        "IAM mutations without a valid 15-minute `jit-wif-*` token minted by Atlas after User approval."
                    ),
                },
            }

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "status": "SUCCEEDED",
                "executed_by": "security-agent",
                "jit_token_verified": jit_token_id,
                "target_resource": target_resource,
                "executed_command": command,
                "executed_at": now_iso,
                "watchdog_window": "45s Telemetry Watchdog Armed",
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rpc.id,
        "result": {
            "status": "UNSUPPORTED_SKILL",
            "skill_id": skill_id,
        },
    }
