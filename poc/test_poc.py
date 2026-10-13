"""
End-to-End Integration Tests for the AgentTriad ADK + A2A Cloud Run PoC.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient
from app import app


def run_e2e_tests() -> None:
    client = TestClient(app)

    # 1. Verify Dashboard UI loads
    res_ui = client.get("/")
    assert res_ui.status_code == 200, f"Dashboard failed: {res_ui.status_code}"
    assert "AgentTriad Control Plane Dashboard" in res_ui.text

    # 2. Verify all 3 A2A AgentCards (/.well-known/agent.json)
    for agent_id in ("log-watcher-agent", "lead-orchestrator-agent", "gke-assist-agent"):
        card_res = client.get(f"/a2a/{agent_id}/.well-known/agent.json")
        assert card_res.status_code == 200, f"Missing AgentCard for {agent_id}"
        card = card_res.json()
        assert card["id"] == agent_id
        assert card["protocol"].startswith("A2A/1.0")
        print(f"[PASS] A2A AgentCard verified: {card['name']} ({card['id']})")

    # 3. Trigger GKE Incident Simulation -> Log Watcher -> A2A -> Lead Orchestrator
    sim_res = client.post("/api/simulate-incident", json={"scenario_id": "oom_killed"})
    assert sim_res.status_code == 200, f"Simulate incident failed: {sim_res.text}"
    sim_data = sim_res.json()
    incident_id = sim_data["incident_id"]
    incident = sim_data["incident"]
    assert incident["status"] == "AWAITING_HITL_APPROVAL"
    assert "impact_analysis" in incident
    assert incident["impact_analysis"]["recommended_kubectl"].startswith("kubectl")
    print(
        f"[PASS] Watcher reported incident {incident_id} via A2A -> Lead Orchestrator computed Impact & Remedy "
        f"(Engine: {incident['impact_analysis'].get('reasoning_engine')})"
    )

    # 4. Verify Zero-Standing Privilege: GKE Assist rejects unapproved A2A execution without JIT token
    unauth_rpc = {
        "jsonrpc": "2.0",
        "id": "test-unauth-1",
        "method": "tasks/send",
        "params": {
            "sender": "rogue-caller",
            "skill_id": "execute_gke_remediation",
            "message": {
                "role": "agent",
                "parts": [
                    {
                        "type": "data",
                        "data": {
                            "incident_id": incident_id,
                            "jit_token_id": "fake-token",
                            "kubectl_command": "kubectl delete ns prod-payments",
                        },
                    }
                ],
            },
        },
    }
    unauth_res = client.post("/a2a/gke-assist-agent", json=unauth_rpc)
    assert unauth_res.status_code == 200
    assert unauth_res.json()["result"]["status"] == "REJECTED_INVALID_JIT_TOKEN"
    print("[PASS] Zero-Standing Privilege verified: GKE Assist rejected unauthenticated A2A mutation")

    # 5. User Accepts Remedy -> Lead Orchestrator mints JIT token & delegates via A2A to GKE Assist Bot
    approve_res = client.post(
        f"/api/incidents/{incident_id}/approve",
        json={
            "approved_by": "sre-lead@cognizant.com",
            "execution_mode": "dry_run",
        },
    )
    assert approve_res.status_code == 200, f"Approval failed: {approve_res.text}"
    resolved_inc = approve_res.json()["incident"]
    assert resolved_inc["status"] == "RESOLVED"
    assert resolved_inc["jit_token"]["token_id"].startswith("jit-wif-")
    assert resolved_inc["execution_result"]["status"] == "SUCCEEDED"
    assert resolved_inc["verification_result"]["status"] == "VERIFIED_HEALTHY"
    print(
        f"[PASS] HITL Approval -> Lead Orchestrator delegated to GKE Assist Bot via A2A -> "
        f"Executed ({resolved_inc['execution_result']['reconciliation_pr']}) & Watchdog Verified!"
    )

    # 6. Check A2A ledger recorded all handshakes
    state_res = client.get("/api/state")
    assert state_res.status_code == 200
    ledger = state_res.json()["a2a_ledger"]
    assert len(ledger) >= 3
    print(f"[PASS] A2A Protocol Ledger recorded {len(ledger)} JSON-RPC 2.0 handshakes.")


if __name__ == "__main__":
    run_e2e_tests()
