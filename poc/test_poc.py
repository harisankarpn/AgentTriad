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

    # 1. Verify Dashboard UI loads with Left Sidebar Navigation Rail, AaaS Command Center, User: Hari, Heartbeat & Telemetry, Specialist Agent Roster (7 specialists), Atlas Holding GCP Cloud icon, 'I accept', Audit Tracker, and without Simulate/Demo controls
    res_ui = client.get("/")
    assert res_ui.status_code == 200, f"Dashboard failed: {res_ui.status_code}"
    assert "AaaS Control Plane" in res_ui.text
    assert "AaaS Command Center" in res_ui.text
    assert "Atlas Command Center" not in res_ui.text
    assert "User:" in res_ui.text
    assert "Operator:" not in res_ui.text
    assert "Heartbeat &amp; Telemetry" in res_ui.text
    assert "Specialist Agent Roster" in res_ui.text
    assert "Atlas Holding GCP Cloud" in res_ui.text
    assert "I accept — Dispatch" in res_ui.text
    assert "I'm Convinced" not in res_ui.text
    assert "Audit &amp; Event Tracker" in res_ui.text
    for nav_id in (
        "nav-command",
        "nav-roster",
        "nav-audit",
        "nav-logs",
        "view-command",
        "view-roster",
        "view-audit",
        "view-logs",
        "btnOpenDirectChat",
        "btnPollLiveLogs",
        "themeBtnAuto",
        "themeBtnDark",
        "themeBtnLight",
    ):
        assert nav_id in res_ui.text, f"Missing sidebar/view/theme element {nav_id} in Dashboard UI"
    assert "prefers-color-scheme: dark" in res_ui.text
    for google_token in ("#4285F4", "#EA4335", "#FBBC04", "#34A853", "Google+Sans", "google-brand-bar", "g-card-fourcolor"):
        assert google_token in res_ui.text, f"Missing Google Visual Identity token {google_token} in Dashboard UI"
    for loud_color in ("purple-", "amber-", "violet-", "orange-"):
        assert loud_color not in res_ui.text, f"Loud color class {loud_color} found in Google Visual Identity UI"
    assert "btnSidebarAtlasChat" not in res_ui.text
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
    print("[PASS] Dashboard UI verified: Official Google Visual Identity 4-Color Palette, Google Sans Typography, Auto/Dark/Light Theme Switcher, and 7 Specialists present")

    # 1b. Verify Manual Invocation of Atlas Chatbot across all 4 Customer Scenarios
    # Scenario 4: Simple GCP "How-To" ($0 Sandbox Overhead)
    direct_howto_res = client.post(
        "/api/atlas/chat",
        json={"message": "How do I connect a Cloud Run service to Cloud SQL Postgres safely?"},
    )
    assert direct_howto_res.status_code == 200, f"Direct Atlas How-To chat failed: {direct_howto_res.text}"
    howto_json = direct_howto_res.json()
    assert howto_json["action_taken"] == "DIRECT_ATLAS_CHAT_REPLY"
    assert howto_json["scenario_type"] == "SCENARIO_4_HOW_TO"
    assert howto_json["specialist_worker"]["name"] == "Database Agent"
    assert len(howto_json["messages"]) >= 3
    print(f"[PASS] Scenario 4 (GCP How-To, $0 Sandbox) verified: routed to {howto_json['specialist_worker']['name']}")

    # Scenario 1: Unlogged Troubleshooting with 1-Line CLI Fix
    direct_unlogged_res = client.post(
        "/api/atlas/chat",
        json={"message": "My service has intermittent slow latency and timeouts not captured in Cloud Logging. Give me a 1-line CLI fix."},
    )
    assert direct_unlogged_res.status_code == 200, f"Direct Atlas unlogged troubleshooting failed: {direct_unlogged_res.text}"
    unlogged_json = direct_unlogged_res.json()
    assert unlogged_json["action_taken"] == "DIRECT_ATLAS_CHAT_REPLY"
    assert unlogged_json["scenario_type"] == "SCENARIO_1_CLI_FIX"
    assert unlogged_json["specialist_worker"]["name"] in ("Networking Agent", "Serverless Agent")
    print(f"[PASS] Scenario 1 (1-Line CLI Fix) verified: routed to {unlogged_json['specialist_worker']['name']}")

    # Scenario 2: Coordinated Multi-Service Fix (IAM + VPC Firewall + DB) via Terraform (.tf)
    multi_svc_res = client.post(
        "/api/atlas/chat",
        json={
            "message": (
                "We have a multi-service failure: Cloud Run cannot reach Cloud SQL due to missing IAM roles, "
                "VPC firewall egress rules, and connection pool exhaustion. Generate a coordinated Multi-Service Terraform fix."
            )
        },
    )
    assert multi_svc_res.status_code == 200, f"Scenario 2 Multi-Service chat failed: {multi_svc_res.text}"
    multi_json = multi_svc_res.json()
    assert multi_json["scenario_type"] == "SCENARIO_2_MULTI_SERVICE_TERRAFORM"
    assert len(multi_json.get("coordinated_specialists", [])) >= 2
    assert multi_json.get("terraform_bundle") is not None
    assert multi_json["terraform_bundle"]["dry_run"]["dry_run_status"] == "PASS"
    assert multi_json["terraform_bundle"]["policy_gate"]["opa_verdict"] == "PASS"
    coord_names = [s["name"] for s in multi_json["coordinated_specialists"]]
    print(f"[PASS] Scenario 2 (Multi-Service Terraform Fix) verified: coordinated specialists={coord_names}")

    # Scenario 3: Customer asks Atlas to generate & execute a new Terraform (.tf) deployment script
    tf_gen_res = client.post(
        "/api/atlas/chat",
        json={
            "message": (
                "Generate a production-ready Terraform (.tf) script to deploy a new Cloud Run service "
                "with least-privilege IAM and Cloud SQL connectivity."
            )
        },
    )
    assert tf_gen_res.status_code == 200, f"Scenario 3 Terraform generation failed: {tf_gen_res.text}"
    tf_gen_json = tf_gen_res.json()
    assert tf_gen_json["scenario_type"] == "SCENARIO_3_TERRAFORM_DEPLOYMENT"
    assert tf_gen_json.get("terraform_bundle") is not None
    hcl_code = tf_gen_json["terraform_bundle"]["hcl_code"]
    assert "google_cloud_run_v2_service" in hcl_code

    tf_deploy_res = client.post(
        "/api/atlas/chat/deploy-terraform",
        json={"approved_by": "Hari", "hcl_code": hcl_code},
    )
    assert tf_deploy_res.status_code == 200, f"Scenario 3 Terraform execution failed: {tf_deploy_res.text}"
    tf_deploy_json = tf_deploy_res.json()
    assert tf_deploy_json["status"] == "TERRAFORM_EXECUTED_VIA_HARNESS"
    assert tf_deploy_json["execution_result"]["status"] == "SUCCEEDED"
    print(
        f"[PASS] Scenario 3 (Terraform .tf Generation & Agent Harness Execution) verified: "
        f"deployment_id={tf_deploy_json['deployment_id']}"
    )

    reset_chat_res = client.post("/api/atlas/chat/reset")
    assert reset_chat_res.status_code == 200
    assert len(reset_chat_res.json()["messages"]) == 1
    print("[PASS] Direct Atlas Chat Reset verified!")

    # 1c. Verify Agent Harness Policy Gate blocks mutations to protected teammate resources (testdbconnect & us-west1 Reasoning Engines)
    from services.agent_harness import agent_harness

    blocked_gate = agent_harness.evaluate_policy_gate(
        proposed_command="gcloud run services delete testdbconnect --region=us-west1",
        target_service="testdbconnect",
    )
    assert blocked_gate["allowed"] is False
    assert blocked_gate["opa_verdict"] == "DENY"
    print(f"[PASS] Agent Harness Policy Gate verified: blocked mutation on protected service 'testdbconnect' ({blocked_gate['violations'][0]})")

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

    # 3. Poll Real GCP Cloud Logging -> Log Watcher (SAIF Sanitizer) -> A2A -> Atlas (ADK Lead Orchestrator)
    poll_res = client.post("/api/poll-cloud-logging")
    assert poll_res.status_code == 200, f"Poll live logs failed: {poll_res.text}"
    poll_data = poll_res.json()
    assert poll_data["status"] == "REAL_GCP_INCIDENT_REPORTED_TO_ORCHESTRATOR", f"Unexpected poll status: {poll_data}"
    incident_id = poll_data["incident_id"]
    incident = poll_data["incident"]
    assert incident["status"] == "AWAITING_HITL_APPROVAL"
    assert "impact_analysis" in incident
    assert "agent_harness" in incident
    assert incident["agent_harness"]["state_lock"]["status"] in ("ACQUIRED", "RENEWED")
    assert incident["agent_harness"]["policy_gate"]["opa_verdict"] == "PASS"
    assert "specialist_worker" in incident
    assert incident["specialist_worker"]["name"].endswith("Agent")
    assert len(incident.get("chat_messages", [])) >= 1
    assert incident["chat_messages"][0]["sender"] == "Atlas • AaaS Lead"
    assert "Hey Hari" in incident["chat_messages"][0]["text"]
    print(
        f"[PASS] Live GCP Log Poll escalated incident {incident_id} via A2A -> Atlas routed to "
        f"'{incident['specialist_worker']['name']}' with .tflock={incident['agent_harness']['state_lock']['lock_id']} "
        f"& RAG Playbook={incident['agent_harness']['rag_playbook']['playbook_id']}"
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

    # 3c. Interactive Chat with Atlas • AaaS Lead before approving (including Scenario 2 Multi-Service Terraform upgrade)
    chat_res = client.post(
        f"/api/incidents/{incident_id}/chat",
        json={"message": "Generate a coordinated Multi-Service Terraform (.tf) remediation bundle across IAM, VPC firewall, and database for this incident."},
    )
    assert chat_res.status_code == 200, f"Chat endpoint failed: {chat_res.text}"
    chat_data = chat_res.json()
    assert chat_data["action_taken"] == "ANSWERED_QUESTION"
    assert chat_data.get("terraform_bundle") is not None
    assert len(chat_data["incident"]["chat_messages"]) >= 3
    print(f"[PASS] Interactive Incident Chat + Scenario 2 Terraform Bundle generation verified!")

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

    # 5b. User accepts via chat ("I accept") -> Atlas mints JIT token & delegates via A2A to Deterministic Specialist Harness ($0 extra LLM cost)
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
    assert resolved_inc["execution_result"]["agent_harness_execution"]["specialist_llm_tokens_used"] == 0
    assert resolved_inc["verification_result"]["status"] == "VERIFIED_HEALTHY"
    print(
        f"[PASS] Conversational Approval -> Atlas • AaaS Lead delegated to Deterministic Specialist Harness ($0 LLM tokens) -> "
        f"Executed ({resolved_inc['execution_result']['reconciliation_pr']}) & 45s Watchdog Verified!"
    )

    # 6. Verify Audit & Event Tracker and Agent Harness Status endpoint
    state_res = client.get("/api/state")
    assert state_res.status_code == 200
    state_json = state_res.json()
    assert "agent_harness_status" in state_json
    ledger = state_json["a2a_ledger"]
    assert len(ledger) >= 3
    audit_events_2 = state_json["audit_events"]
    tracked_2 = next(e for e in audit_events_2 if e["incident_id"] == incident_id)
    assert tracked_2["status"] == "RESOLVED"
    assert tracked_2["approved_by"] == "Hari (via Chat)"
    assert tracked_2["approved_at"] is not None
    assert tracked_2["resolved_at"] is not None
    assert tracked_2["jit_token_id"].startswith("jit-wif-")

    harness_res = client.get("/api/harness/status")
    assert harness_res.status_code == 200
    harness_data = harness_res.json()
    assert "testdbconnect" in harness_data["protected_external_resources"]
    print(
        f"[PASS] Audit Tracker & Agent Harness Status verified: approved_by='{tracked_2['approved_by']}', "
        f"jit_token_id={tracked_2['jit_token_id']}, protected_resources={len(harness_data['protected_external_resources'])}"
    )


if __name__ == "__main__":
    run_e2e_tests()




