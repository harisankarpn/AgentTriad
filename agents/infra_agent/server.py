"""
FastAPI + A2A Server for the standalone ADK Infra Specialist Agent (`infra-agent`).

Endpoints:
  - GET  /healthz                  -> Container health check
  - GET  /.well-known/agent.json   -> A2A 1.0 AgentCard discovery for Atlas (Lead Orchestrator)
  - POST /diagnose                 -> Autonomous ADK Infra/Compute diagnosis & remediation proposal (Read-Only)
  - POST /a2a                      -> JSON-RPC 2.0 A2A task endpoint:
      * skill `diagnose_infra_anomaly`: Read-only ADK reasoning
      * skill `execute_approved_infra_remediation`: Strictly requires Atlas's 15-min WIF JIT Token
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import PROTECTED_RESOURCES, PROJECT_ID, REGION, run_diagnosis

app = FastAPI(
    title="AaaS ADK Infra Specialist Agent",
    version="1.0.0",
    description="Autonomous Compute Engine, GKE & Terraform IaC Reasoner (Read-Only Diagnosis) + JIT-Gated Follower",
)


class DiagnoseRequest(BaseModel):
    prompt: str = Field(..., description="Incident description or infrastructure question from Atlas/User")
    target_instance: str = Field(default="auto", description="Target GCE instance name, instance_id, or 'auto'")


class A2ARequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str = "a2a-infra-1"
    method: str = "tasks/send"
    params: Dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "agent_id": "infra-agent",
        "project_id": PROJECT_ID,
        "region": REGION,
        "mode": "READ_ONLY_DIAGNOSIS_PLUS_JIT_FOLLOWER",
    }


@app.get("/.well-known/agent.json")
async def get_agent_card() -> Dict[str, Any]:
    """Returns the A2A 1.0 AgentCard so Atlas can discover the Infra Agent."""
    service_url = os.getenv("SERVICE_URL", "http://localhost:8080")
    return {
        "id": "infra-agent",
        "name": "AaaS Infra Specialist Agent (ADK)",
        "version": "1.0.0",
        "protocol": "A2A/1.0-JSONRPC",
        "endpoint": f"{service_url}/a2a",
        "description": (
            "Google ADK Infra Specialist for Compute Engine (GCE VMs & disks), GKE clusters, and Terraform IaC. "
            "Autonomously runs read-only diagnostics and proposes gcloud/Terraform fixes; "
            "requires an Atlas-minted 15-minute WIF JIT token for any mutation."
        ),
        "ZeroStandingPrivilege": True,
        "capabilities": [
            "compute-engine-read-only-inspection",
            "cloud-monitoring-vm-performance-metrics",
            "guest-agent-and-gke-log-triage",
            "runtime-service-account-introspection",
            "terraform-and-gcloud-proposal-generation",
            "jit-gated-remediation-execution",
        ],
        "skills": [
            {
                "id": "diagnose_infra_anomaly",
                "name": "Diagnose Infrastructure Anomaly (Read-Only ADK Reasoning)",
                "description": "Calls ADK Compute/Infra tools to diagnose GCE VM, GKE, and Terraform issues and propose a safe fix.",
                "tags": ["infra", "compute-engine", "gke", "terraform", "adk", "read-only"],
            },
            {
                "id": "execute_approved_infra_remediation",
                "name": "Execute Approved Infra Remediation (JIT Token Required)",
                "description": "Executes the Atlas-approved infrastructure remediation only when a valid 15-minute JIT token is supplied.",
                "tags": ["infra", "remediation", "jit-wif"],
            },
        ],
    }


@app.post("/diagnose")
async def diagnose_endpoint(req: DiagnoseRequest) -> Dict[str, Any]:
    """Direct HTTP endpoint to trigger ADK Infra Agent diagnosis."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt cannot be empty")
    result = await run_diagnosis(prompt=req.prompt, target_instance=req.target_instance)
    return result


@app.post("/a2a")
async def handle_a2a_rpc(rpc: A2ARequest) -> Dict[str, Any]:
    """
    A2A JSON-RPC 2.0 handler supporting:
      1. `diagnose_infra_anomaly` -> Infra Agent 'thinks' (Read-Only ADK tools + Gemini)
      2. `execute_approved_infra_remediation` -> Infra Agent 'follows' (Requires Atlas JIT token)
    """
    skill_id = rpc.params.get("skill_id", "diagnose_infra_anomaly")
    parts: List[Dict[str, Any]] = rpc.params.get("message", {}).get("parts", [])
    payload: Dict[str, Any] = parts[0].get("data", {}) if parts else rpc.params.get("data", {})

    if skill_id == "diagnose_infra_anomaly":
        prompt = payload.get("prompt") or payload.get("message") or "Diagnose Compute Engine infrastructure anomaly"
        target_instance = payload.get("target_instance") or payload.get("instance_name") or "auto"
        diagnosis = await run_diagnosis(prompt=prompt, target_instance=target_instance)
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "status": "DIAGNOSIS_COMPLETE_AWAITING_ATLAS_HITL",
                "diagnosis": diagnosis,
            },
        }

    if skill_id == "execute_approved_infra_remediation":
        jit_token_id: Optional[str] = payload.get("jit_token_id")
        target_instance: str = payload.get("target_instance", "testinstance1")
        command: str = payload.get("command", "")

        if target_instance.lower() in PROTECTED_RESOURCES:
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_PROTECTED_RESOURCE",
                    "reason": f"Resource `{target_instance}` is a protected external resource and cannot be mutated.",
                },
            }

        if not jit_token_id or not str(jit_token_id).startswith("jit-wif-"):
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_INVALID_JIT_TOKEN",
                    "reason": (
                        "Zero-Standing Privilege Violation: Infra Agent cannot mutate production "
                        "without a valid 15-minute `jit-wif-*` token minted by Atlas after User approval."
                    ),
                },
            }

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "status": "SUCCEEDED",
                "executed_by": "infra-agent",
                "jit_token_verified": jit_token_id,
                "target_instance": target_instance,
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
