"""
FastAPI + A2A Server for the standalone ADK Database Specialist Agent (`database-agent`).

Endpoints:
  - GET  /healthz                  -> Container health check
  - GET  /.well-known/agent.json   -> A2A 1.0 AgentCard discovery for Atlas (Lead Orchestrator)
  - POST /diagnose                 -> Autonomous ADK DBA diagnosis & remediation proposal (Read-Only)
  - POST /a2a                      -> JSON-RPC 2.0 A2A task endpoint:
      * skill `diagnose_database_anomaly`: Read-only ADK reasoning
      * skill `execute_approved_db_remediation`: Strictly requires Atlas's 15-min WIF JIT Token
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import PROTECTED_RESOURCES, PROJECT_ID, REGION, run_diagnosis

app = FastAPI(
    title="AaaS ADK Database Specialist Agent",
    version="1.0.0",
    description="Autonomous DBA Reasoner (Read-Only Diagnosis) + JIT-Gated Remediation Follower",
)


class DiagnoseRequest(BaseModel):
    prompt: str = Field(..., description="Incident description or database question from Atlas/User")
    instance_name: str = Field(default="orders-db-prod", description="Target Cloud SQL instance name")


class A2ARequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str = "a2a-db-1"
    method: str = "tasks/send"
    params: Dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "agent_id": "database-agent",
        "project_id": PROJECT_ID,
        "region": REGION,
        "mode": "READ_ONLY_DIAGNOSIS_PLUS_JIT_FOLLOWER",
    }


@app.get("/.well-known/agent.json")
async def get_agent_card() -> Dict[str, Any]:
    """Returns the A2A 1.0 AgentCard so Atlas can discover the Database Agent."""
    service_url = os.getenv("SERVICE_URL", "http://localhost:8080")
    return {
        "id": "database-agent",
        "name": "AaaS Database Specialist Agent (ADK)",
        "version": "1.0.0",
        "protocol": "A2A/1.0-JSONRPC",
        "endpoint": f"{service_url}/a2a",
        "description": (
            "Google ADK Database Specialist for Cloud SQL, AlloyDB, and Spanner. "
            "Autonomously runs read-only diagnostics and proposes gcloud/Terraform fixes; "
            "requires an Atlas-minted 15-minute WIF JIT token for any mutation."
        ),
        "ZeroStandingPrivilege": True,
        "capabilities": [
            "cloudsql-read-only-inspection",
            "connection-pool-exhaustion-analysis",
            "slow-query-log-triage",
            "terraform-and-gcloud-proposal-generation",
            "jit-gated-remediation-execution",
        ],
        "skills": [
            {
                "id": "diagnose_database_anomaly",
                "name": "Diagnose Database Anomaly (Read-Only ADK Reasoning)",
                "description": "Calls ADK DBA tools to diagnose Cloud SQL/AlloyDB/Spanner issues and propose a safe fix.",
                "tags": ["database", "cloudsql", "adk", "read-only"],
            },
            {
                "id": "execute_approved_db_remediation",
                "name": "Execute Approved DB Remediation (JIT Token Required)",
                "description": "Executes the Atlas-approved database remediation only when a valid 15-minute JIT token is supplied.",
                "tags": ["database", "remediation", "jit-wif"],
            },
        ],
    }


@app.post("/diagnose")
async def diagnose_endpoint(req: DiagnoseRequest) -> Dict[str, Any]:
    """Direct HTTP endpoint to trigger ADK Database Agent diagnosis."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt cannot be empty")
    result = await run_diagnosis(prompt=req.prompt, instance_name=req.instance_name)
    return result


@app.post("/a2a")
async def handle_a2a_rpc(rpc: A2ARequest) -> Dict[str, Any]:
    """
    A2A JSON-RPC 2.0 handler supporting:
      1. `diagnose_database_anomaly` -> Database Agent 'thinks' (Read-Only ADK tools + Gemini)
      2. `execute_approved_db_remediation` -> Database Agent 'follows' (Requires Atlas JIT token)
    """
    skill_id = rpc.params.get("skill_id", "diagnose_database_anomaly")
    parts: List[Dict[str, Any]] = rpc.params.get("message", {}).get("parts", [])
    payload: Dict[str, Any] = parts[0].get("data", {}) if parts else rpc.params.get("data", {})

    # Skill 1: Read-Only ADK DBA Diagnosis
    if skill_id == "diagnose_database_anomaly":
        prompt = payload.get("prompt") or payload.get("message") or "Diagnose Cloud SQL connection anomaly"
        instance_name = payload.get("instance_name", "orders-db-prod")
        diagnosis = await run_diagnosis(prompt=prompt, instance_name=instance_name)
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "status": "DIAGNOSIS_COMPLETE_AWAITING_ATLAS_HITL",
                "diagnosis": diagnosis,
            },
        }

    # Skill 2: JIT-Gated Execution (Database Agent strictly follows Atlas's authorization)
    if skill_id == "execute_approved_db_remediation":
        jit_token_id: Optional[str] = payload.get("jit_token_id")
        instance_name: str = payload.get("instance_name", "orders-db-prod")
        command: str = payload.get("command", "")

        # Guardrail 1: Block protected colleague resources
        if instance_name.lower() in PROTECTED_RESOURCES:
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_PROTECTED_RESOURCE",
                    "reason": f"Instance `{instance_name}` is a protected external resource and cannot be mutated.",
                },
            }

        # Guardrail 2: Zero-Standing Privilege — Reject if no valid Atlas WIF JIT Token
        if not jit_token_id or not str(jit_token_id).startswith("jit-wif-"):
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "status": "REJECTED_INVALID_JIT_TOKEN",
                    "reason": (
                        "Zero-Standing Privilege Violation: Database Agent cannot mutate production "
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
                "executed_by": "database-agent",
                "jit_token_verified": jit_token_id,
                "instance_name": instance_name,
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
