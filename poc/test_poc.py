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

    # 1. Verify Dashboard UI loads with Left Sidebar Navigation Rail, Heartbeat & Telemetry, Specialist Agent Roster (7 specialists), Atlas Holding GCP Cloud icon, 'I accept', Audit Tracker, and without Simulate/Demo controls
    res_ui = client.get("/")
    assert res_ui.status_code == 200, f"Dashboard failed: {res_ui.status_code}"
    assert "AaaS Control Plane" in res_ui.text
    assert "Heartbeat &amp; Telemetry" in res_ui.text
    assert "Specialist Agent Roster" in res_ui.text
    assert "Atlas Holding GCP Cloud" in res_ui.text
    assert "I accept — Dispatch" in res_ui.text
    assert "I'm Convinced" not in res_ui.text
    assert "Audit &amp; Event Tracker" in res_ui.text
    for nav_id in ("nav-command", "nav-roster", "nav-audit", "nav-logs", "view-command", "view-roster", "view-audit", "view-logs"):
        assert nav_id in res_ui.text, f"Missing sidebar/view element {nav_id} in Dashboard UI"
    for specialist_label in (
        "Serverless Agent",
        "Database Agent",
        "Infra Agent",
        "Networking Agent",
        "Data Analytics Agent",
        "Security Agent",
        "Billing Agent",
    ):
        assert specialist_label in res_ui.text, f"Missing {specialist_label} in Dashboard UI"
    assert "Simulate Issue" not in res_ui.text
    assert "scenarioSelect" not in res_ui.text
    print("[PASS] Dashboard UI verified: Left Sidebar Navigation Rail (Command, Roster, Audit, Logs), Atlas Holding GCP Cloud icon, 'I accept' button & 7 Specialists present")

    # 2. Verify all 3 A2A AgentCards (/.well-known/agent.json)
    for agent_id in ("log-watcher-agent", "lead-orchestrator-agent", "gke-assist-agent"):
        card_res = client.get(f"/a2a/{agent_id}/.well-known/agent.json")
        assert card_res.status_code == 200, f"Missing AgentCard for {agent_id}"
        card = card_res.json()
        assert card["id"] == agent_id
        assert card["protocol"].startswith("A2A/1.0")
        skill_ids = [s["id"] for s in card.get("skills", [])]
        assert "scan_and_inject_incident" not in skill_ids
        print(f"[PASS] A2A AgentCard verified: {card['name']} ({card['id']}) -> skills={skill_ids}")

    # 3. Poll Real GCP Cloud Logging -> Log Watcher -> A2A -> Atlas (Lead Orchestrator)
    poll_res = client.post("/api/poll-cloud-logging")
    assert poll_res.status_code == 200, f"Poll live logs failed: {poll_res.text}"
    poll_data = poll_res.json()
    assert poll_data["status"] == "REAL_GCP_INCIDENT_REPORTED_TO_ORCHESTRATOR", f"Unexpected poll status: {poll_data}"
    incident_id = poll_data["incident_id"]
    incident = poll_data["incident"]
    assert incident["status"] == "AWAITING_HITL_APPROVAL"
    assert "impact_analysis" in incident
    assert "specialist_worker" in incident
    assert incident["specialist_worker"]["name"].endswith("Agent")
    assert len(incident.get("chat_messages", [])) >= 1
    assert incident["chat_messages"][0]["sender"] == "Atlas • AaaS Lead"
    assert "Hey Hari" in incident["chat_messages"][0]["text"]
    print(
        f"[PASS] Live GCP Log Poll escalated incident {incident_id} via A2A -> Atlas routed to "
        f"'{incident['specialist_worker']['name']}' (Title: {(poll_data.get('log_entry') or {}).get('title')})"
    )

    # 3b. Verify Audit & Event Tracker recorded issue occurrence timestamp and assigned specialist prior to approval
    audit_res_1 = client.get("/api/audit-events")
    assert audit_res_1.status_code == 200
    audit_events_1 = audit_res_1.json()["audit_events"]
    assert len(audit_events_1) >= 1
    tracked_1 = next(e for e in audit_events_1 if e["incident_id"] == incident_id)
    assert tracked_1["occurred_at"] is not None
    assert tracked_1["detected_at"] is not None
    assert tracked_1["specialist_agent_name"] == incident["specialist_worker"]["name"]
    assert tracked_1["status"] == "AWAITING_HITL_APPROVAL"
    assert tracked_1["approved_by"] is None
    assert tracked_1["approved_at"] is None
    print(
        f"[PASS] Audit Tracker initial record verified: occurred_at={tracked_1['occurred_at']}, "
        f"specialist={tracked_1['specialist_agent_name']}, status={tracked_1['status']}"
    )

    # 3c. Interactive Chat with Atlas • AaaS Lead before approving
    chat_res = client.post(
        f"/api/incidents/{incident_id}/chat",
        json={"message": "Why did this happen and is there any downtime risk if we apply the fix?"},
    )
    assert chat_res.status_code == 200, f"Chat endpoint failed: {chat_res.text}"
    chat_data = chat_res.json()
    assert chat_data["action_taken"] == "ANSWERED_QUESTION"
    assert len(chat_data["incident"]["chat_messages"]) >= 3
    print(f"[PASS] Interactive Chat Q&A verified: Atlas answered Hari's question ({chat_data['reply'][:80]}...)")

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

    # 5a. Test Later / Ignore (Manual Mode) and Reopen
    skip_res = client.post(f"/api/incidents/{incident_id}/skip")
    assert skip_res.status_code == 200
    assert skip_res.json()["incident"]["status"] == "SKIPPED_MANUAL"
    reopen_res = client.post(f"/api/incidents/{incident_id}/reopen")
    assert reopen_res.status_code == 200
    assert reopen_res.json()["incident"]["status"] == "AWAITING_HITL_APPROVAL"
    print("[PASS] Skip / Manual Mode and Reopen verified!")

    # 5b. User accepts via chat ("I accept") -> Atlas mints JIT token & delegates via A2A to Specialist Agent
    approve_res = client.post(
        f"/api/incidents/{incident_id}/chat",
        json={"message": "I accept, please proceed with the fix now."},
    )
    assert approve_res.status_code == 200, f"Chat approval failed: {approve_res.text}"
    assert approve_res.json()["action_taken"] == "APPROVED_AND_EXECUTED"
    resolved_inc = approve_res.json()["incident"]
    assert resolved_inc["status"] == "RESOLVED"
    assert resolved_inc["jit_token"]["token_id"].startswith("jit-wif-")
    assert resolved_inc["execution_result"]["status"] == "SUCCEEDED"
    assert resolved_inc["verification_result"]["status"] == "VERIFIED_HEALTHY"
    print(
        f"[PASS] Conversational Approval -> Atlas • AaaS Lead delegated to Worker Agent via A2A -> "
        f"Executed ({resolved_inc['execution_result']['reconciliation_pr']}) & Watchdog Verified!"
    )

    # 6. Verify Audit & Event Tracker recorded who approved and exact approval timestamp
    state_res = client.get("/api/state")
    assert state_res.status_code == 200
    state_json = state_res.json()
    ledger = state_json["a2a_ledger"]
    assert len(ledger) >= 3
    audit_events_2 = state_json["audit_events"]
    tracked_2 = next(e for e in audit_events_2 if e["incident_id"] == incident_id)
    assert tracked_2["status"] == "RESOLVED"
    assert tracked_2["approved_by"] == "Hari (via Chat)"
    assert tracked_2["approved_at"] is not None
    assert tracked_2["resolved_at"] is not None
    assert tracked_2["jit_token_id"].startswith("jit-wif-")
    print(
        f"[PASS] Audit Tracker approval record verified: approved_by='{tracked_2['approved_by']}', "
        f"approved_at={tracked_2['approved_at']}, jit_token_id={tracked_2['jit_token_id']}"
    )


if __name__ == "__main__":
    run_e2e_tests()



