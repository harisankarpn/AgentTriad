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
        "nav-dispatch",
        "nav-roster",
        "nav-audit",
        "nav-logs",
        "nav-features",
        "view-command",
        "view-dispatch",
        "view-roster",
        "view-audit",
        "view-logs",
        "view-features",
        "sidebarDispatchMini",
        "sidePanelDispatchStage",
        "sidePanelDispatchHistory",
        "platformCloudTabs",
        "platformCloudMatrixGrid",
        "btnOpenDirectChat",
        "btnPollLiveLogs",
        "themeBtnAuto",
        "themeBtnDark",
        "themeBtnLight",
        "userProfileBadge",
        "googleSsoModal",
        "googleSsoForm",
        "btnNewChatSession",
        "btnToggleSessionHistory",
        "btnClearAllSessions",
        "atlasSessionHistoryPanel",
        "targetCloudSwitcher",
        "cloudBtnGcp",
        "cloudBtnAws",
        "cloudBtnAzure",
        "metricCardProviderHealth",
        "logBulkActionBar",
        "logSelectAllCheckbox",
        "logServiceFilter",
        "logTriageFilter",
        "logIgnoreReasonSelect",
        "logIgnoreSimilarCheckbox",
        "btnBulkIgnoreLogs",
        "btnBulkFixLogsViaChat",
        "btnBulkQueueSeparate",
        "multiAlertOptionsRow",
        "btnOpenTicketIntake",
        "btnRecreateScenario1Modal",
        "ticketIntakeModal",
        "liveHealthWatchModal",
    ):
        assert nav_id in res_ui.text, f"Missing sidebar/view/theme/SSO/session/cloud element {nav_id} in Dashboard UI"
    assert "btnQuickRecreateScenario1" not in res_ui.text, "Duplicate header Recreate Fault icon should be removed"
    for p4_ui_token in (
        "renderOutageBlockedCard",
        "renderFailedRemediationCard",
        "recreateScenario1Fault",
        "REMEDIATION_FAILED",
        "renderPhase4IntelligencePanels",
        "recheckIncidentProvider",
        "BLOCKED_PROVIDER_OUTAGE",
        "Zero JIT Token Minted",
        "renderLiveDispatchTrackerCard",
        "renderCompletedDispatchStepper",
        "renderDispatchReceiptCard",
        "startIncidentDispatchTracker",
        "startInlineChatDispatch",
        "selectPlatformCloudTab",
        "launchWorkflowMode",
        "detectDeployedCloudFromUrl",
        "updateCloudHealthCard",
        "renderSidePanelDispatchView",
        "focusActiveCloudIssue",
        "markSelectedLogsSafeToIgnore",
        "fixSelectedLogsViaChat",
        "selectVisibleLogsBySeverity",
        "markSingleLogSafeToIgnore",
        "fixSingleLogViaChat",
        "restoreSingleLog",
        "Mark Safe to Ignore",
        "Fix via AaaS Chat",
        "Queue Separately",
        "Post-Fix Auto-Rollback",
        "Live Health Watch",
        "Provider:",
        "Cloud Outage Safety Brake",
        "Five-Layer Zero-Trust Protection",
        "Bounded AI",
        "renderSecurityIamAuditPanel",
        "submitCustomerTicketIntake",
        "Security_Agent_Tool",
    ):
        assert p4_ui_token in res_ui.text, f"Missing Multi-Cloud / Phase 4 / Dispatch UI token {p4_ui_token} in Dashboard UI"
    assert "pipelineStepsDrawer" not in res_ui.text, "Redundant center-stage pipelineStepsDrawer should be removed"
    assert "capabilitiesBannerGrid" not in res_ui.text, "Redundant center-stage capabilitiesBannerGrid should be removed"
    assert "Sign in to AaaS Command Center" in res_ui.text
    assert "Continue with Google SSO" in res_ui.text
    assert "accounts.google.com/gsi/client" in res_ui.text
    assert "Harisankar P N" not in res_ui.text
    assert "sre-lead@google.com" in res_ui.text
    assert "Firestore (" not in res_ui.text
    assert "fa-gear" in res_ui.text
    assert "prefers-color-scheme: dark" in res_ui.text
    assert res_ui.text.count("Chat with Atlas") == 1, "Expected 'Chat with Atlas' only once in Dashboard UI"
    assert "Gemini 2.5" not in res_ui.text, "Expected 'Gemini 2.5' to be removed from Dashboard UI"
    assert "Gemini latest" in res_ui.text, "Expected 'Gemini latest' in Dashboard UI"
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
    assert "3 Agents Online" in res_ui.text, "ADK Specialists KPI should reflect 3 live agents (Database, Infra, Security)"
    assert "2 Agents Online" not in res_ui.text, "Stale '2 Agents Online' KPI label should be replaced with '3 Agents Online'"
    assert "HSBC_Target Project" in res_ui.text, "Support Ticket modal should show HSBC_Target Project preset"
    assert "HSBC Reference" not in res_ui.text, "Stale 'HSBC Reference' preset label should be replaced with 'HSBC_Target Project'"
    print("[PASS] Dashboard UI verified: Official Google Visual Identity 4-Color Palette, Google SSO Sign-In Modal, Auto/Dark/Light Theme Switcher, 3 ADK Specialists KPI, HSBC_Target Preset, and 7 Specialists present")

    # 1a. Verify Google SSO Authentication Endpoints (/api/auth/me, /api/auth/google, /api/auth/config)
    auth_me_res = client.get("/api/auth/me")
    assert auth_me_res.status_code == 200
    assert auth_me_res.json()["user"]["name"] == "Hari"

    # Verify forged/invalid OAuth tokens are rejected with 401
    forged_jwt_res = client.post(
        "/api/auth/google",
        json={"credential": "forged.jwt.token"},
    )
    assert forged_jwt_res.status_code == 401

    sso_login_res = client.post(
        "/api/auth/google",
        json={"name": "Cloud SRE Lead", "email": "sre-lead@google.com"},
    )
    assert sso_login_res.status_code == 200
    sso_json = sso_login_res.json()
    assert sso_json["status"] == "AUTHENTICATED"
    assert sso_json["user"]["name"] == "Cloud SRE Lead"
    assert sso_json["user"]["email"] == "sre-lead@google.com"
    state_after_sso = client.get("/api/state").json()
    assert state_after_sso["active_user"]["name"] == "Cloud SRE Lead"
    assert "Hey Cloud SRE Lead" in state_after_sso["general_chat_messages"][0]["text"]

    # Switch back to Hari for subsequent baseline assertions
    sso_reset_res = client.post(
        "/api/auth/google",
        json={"name": "Hari", "email": "harisankar@google.com"},
    )
    assert sso_reset_res.status_code == 200
    assert sso_reset_res.json()["user"]["name"] == "Hari"
    print("[PASS] Google SSO Sign-In (/api/auth/me & /api/auth/google), 401 token verification, and dynamic Atlas identity verified!")

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
    assert howto_json.get("dispatch_telemetry") is not None
    assert howto_json["dispatch_telemetry"]["primary_specialist"] == "Database Agent"
    assert howto_json["messages"][-1].get("dispatch_telemetry") is not None
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
    assert tf_deploy_json.get("dispatch_telemetry") is not None
    assert tf_deploy_json["dispatch_telemetry"]["mode"] == "HARNESS_EXECUTED"
    assert tf_deploy_json["dispatch_telemetry"]["jit_token_id"].startswith("jit-wif-")
    print(
        f"[PASS] Scenario 3 (Terraform .tf Generation & Agent Harness Execution) verified: "
        f"deployment_id={tf_deploy_json['deployment_id']}"
    )

    reset_chat_res = client.post("/api/atlas/chat/reset")
    assert reset_chat_res.status_code == 200
    assert len(reset_chat_res.json()["messages"]) == 1
    print("[PASS] Direct Atlas Chat Reset verified!")

    # 1b-ii. Verify Cloud Firestore Multi-Session Chat Manager (New Session, History List, Switch, Delete, Clear All)
    sess_list_1 = client.get("/api/atlas/sessions")
    assert sess_list_1.status_code == 200
    first_session_id = sess_list_1.json()["active_session_id"]

    # Send a message in Session 1 so it gets a custom title
    client.post(
        "/api/atlas/chat",
        json={"message": "How do I configure Cloud Armor rate limiting for Cloud Run?"},
    )

    # Create Session 2
    new_sess_res = client.post("/api/atlas/sessions/new", json={"title": "Database Audit Session"})
    assert new_sess_res.status_code == 200
    second_session_id = new_sess_res.json()["active_session_id"]
    assert second_session_id != first_session_id
    assert len(new_sess_res.json()["messages"]) == 1
    assert len(new_sess_res.json()["sessions"]) >= 2

    # Switch back to Session 1 and verify conversation history was preserved
    select_sess_res = client.post(f"/api/atlas/sessions/{first_session_id}/select")
    assert select_sess_res.status_code == 200
    assert select_sess_res.json()["active_session_id"] == first_session_id
    assert len(select_sess_res.json()["messages"]) >= 3

    # Delete Session 2
    del_sess_res = client.delete(f"/api/atlas/sessions/{second_session_id}")
    assert del_sess_res.status_code == 200
    remaining_ids = [s["session_id"] for s in del_sess_res.json()["sessions"]]
    assert second_session_id not in remaining_ids

    # Clear all chat sessions for current user
    clear_all_res = client.delete("/api/atlas/sessions")
    assert clear_all_res.status_code == 200
    assert clear_all_res.json()["status"] == "ALL_SESSIONS_CLEARED"
    assert len(clear_all_res.json()["sessions"]) == 1
    assert len(clear_all_res.json()["messages"]) == 1
    print(
        f"[PASS] Cloud Firestore Multi-Session Manager verified: create/switch/delete/clear "
        f"(store={sess_list_1.json()['session_store']['status']})"
    )

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

    # 6. Verify Audit & Event Tracker, Dispatch History, and Agent Harness Status endpoint
    state_res = client.get("/api/state")
    assert state_res.status_code == 200
    state_json = state_res.json()
    assert "agent_harness_status" in state_json
    assert "dispatch_history" in state_json and isinstance(state_json["dispatch_history"], list)
    assert len(state_json["dispatch_history"]) >= 1, "Expected persisted dispatch_history entries in /api/state"
    assert state_json["dispatch_history"][0].get("primary_specialist"), state_json["dispatch_history"][0]
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

    # 7. Verify ADK Infra Specialist Agent (`agents/infra_agent/`) live tools & AgentCard
    import importlib.util

    infra_dir = Path(__file__).resolve().parent.parent / "agents" / "infra_agent"
    if str(infra_dir) not in sys.path:
        sys.path.insert(0, str(infra_dir))
    spec_agent = importlib.util.spec_from_file_location("infra_agent_mod", str(infra_dir / "agent.py"))
    assert spec_agent and spec_agent.loader
    infra_agent_mod = importlib.util.module_from_spec(spec_agent)
    spec_agent.loader.exec_module(infra_agent_mod)

    spec_srv = importlib.util.spec_from_file_location("infra_srv_mod", str(infra_dir / "server.py"))
    assert spec_srv and spec_srv.loader
    infra_srv_mod = importlib.util.module_from_spec(spec_srv)
    spec_srv.loader.exec_module(infra_srv_mod)

    infra_client = TestClient(infra_srv_mod.app)
    infra_health = infra_client.get("/healthz")
    assert infra_health.status_code == 200
    infra_card = infra_client.get("/.well-known/agent.json")
    assert infra_card.status_code == 200
    assert infra_card.json()["id"] == "infra-agent"

    live_vms = infra_agent_mod.inspect_compute_instances("2397540675679890849")
    assert live_vms["status"] == "LIVE_GCP_COMPUTE_API"
    assert len(live_vms["discovered_instances"]) >= 1
    assert live_vms["lifecycle_note"] is not None

    live_perf = infra_agent_mod.get_compute_performance_metrics("testinstance1")
    assert live_perf["status"] == "LIVE_GCP_CLOUD_MONITORING"

    live_logs = infra_agent_mod.analyze_infra_logs("Error watching metadata: context canceled", "2397540675679890849")
    assert live_logs["status"] == "LIVE_GCP_CLOUD_LOGGING"
    assert "customer_what_happened" in live_logs

    live_ident = infra_agent_mod.inspect_infra_agent_runtime_identity()
    assert live_ident["active_service_account"] == "aaas-infra-agent-sa@agent-triad.iam.gserviceaccount.com"

    live_prop = infra_agent_mod.generate_infra_remediation_proposal(live_logs["finding"], "2397540675679890849")
    assert "gcloud compute" in live_prop["recommended_cli"]
    assert live_prop.get("gitops_pr_payload") is not None
    assert live_prop["gitops_pr_payload"]["reconciliation_mode"] == "BIDIRECTIONAL_GITOPS_PR"
    print(
        f"[PASS] ADK Infra Specialist Agent verified: discovered_vms={[v['instance_name'] for v in live_vms['discovered_instances']]}, "
        f"service_account={live_ident['active_service_account']}"
    )

    # 8. Phase 4 Unit Test: Cloud Provider Status Check Pre-Flight Gate (GCP / AWS / Azure)
    from app import watcher_agent as app_watcher_agent
    from services.cloud_status_service import cloud_status_service

    watcher_card = client.get("/a2a/log-watcher-agent/.well-known/agent.json").json()
    watcher_skills = [s["id"] for s in watcher_card.get("skills", [])]
    assert "check_cloud_provider_status" in watcher_skills

    # Nominal pre-flight check (offline-safe assertion: status is HEALTHY or STATUS_FEED_UNREACHABLE, mutations_allowed=True)
    nominal_preflight = client.get("/api/preflight/cloud-status", params={"cloud": "gcp", "region": "us-central1-c"})
    assert nominal_preflight.status_code == 200
    assert nominal_preflight.json()["region"] == "us-central1"
    assert nominal_preflight.json()["mutations_allowed"] is True

    try:
        # Inject active GCP regional outage in us-central1 (via zone string us-central1-c)
        cloud_status_service.inject_simulated_outage(
            cloud_provider="gcp",
            region="us-central1-c",
            title="Elevated Compute Engine & Cloud Run API error rates in us-central1",
            service="Cloud Run / Compute Engine",
        )

        # Verify Watcher A2A check_cloud_provider_status detects active outage
        outage_rpc = {
            "jsonrpc": "2.0",
            "id": "preflight-outage-1",
            "method": "tasks/send",
            "params": {
                "sender": "lead-orchestrator-agent",
                "skill_id": "check_cloud_provider_status",
                "message": {
                    "role": "agent",
                    "parts": [{"type": "data", "data": {"cloud_provider": "gcp", "region": "us-central1-c"}}],
                },
            },
        }
        outage_rpc_res = client.post("/a2a/log-watcher-agent", json=outage_rpc)
        assert outage_rpc_res.status_code == 200
        assert outage_rpc_res.json()["result"]["status"] == "ACTIVE_OUTAGE_DETECTED"
        assert outage_rpc_res.json()["result"]["mutations_allowed"] is False

        # Report a serverless incident in us-central1-c and verify approval is BLOCKED while provider outage is active
        outage_log = {
            "log_id": "p4-outage-test-inc-1",
            "timestamp": "2026-11-13T16:15:00+00:00",
            "severity": "ERROR",
            "source": "cloud_run_revision",
            "cluster": "us-central1-c",
            "namespace": "default",
            "workload": "service/payments-api",
            "pod": "payments-api-00042",
            "error_code": "HTTP_503_REGIONAL",
            "title": "Cloud Run 503 Upstream Timeout",
            "message": "Upstream service unavailable in us-central1-c",
            "is_anomaly": True,
            "cloud_provider": "gcp",
        }
        asyncio.run(app_watcher_agent.detect_and_report_anomaly(outage_log))

        blocked_approve = client.post(
            "/api/incidents/p4-outage-test-inc-1/approve",
            json={"approved_by": "Hari", "execution_mode": "sandbox"},
        )
        assert blocked_approve.status_code == 200
        blocked_payload = blocked_approve.json()
        assert blocked_payload["status"] == "BLOCKED_PROVIDER_OUTAGE", blocked_payload
        assert blocked_payload["incident"]["status"] == "BLOCKED_PROVIDER_OUTAGE"
        assert blocked_payload["incident"]["jit_token"] is None, "JIT token must NOT be minted during active provider outage"
        assert blocked_payload["incident"]["execution_result"]["mutations_allowed"] is False

        # Verify AWS & Azure outage gating too
        cloud_status_service.inject_simulated_outage("aws", "us-east-1a", title="AWS EC2 Control Plane Degradation")
        cloud_status_service.inject_simulated_outage("azure", "East US", title="Azure Compute Regional Outage")
        aws_st = cloud_status_service.check_region_status("aws", "us-east-1b")
        az_st = cloud_status_service.check_region_status("azure", "eastus")
        assert aws_st["region"] == "us-east-1" and aws_st["mutations_allowed"] is False
        assert az_st["region"] == "eastus" and az_st["mutations_allowed"] is False
    finally:
        cloud_status_service.clear_simulated_outages()

    # Once outage clears, approving the same incident succeeds cleanly
    recovered_approve = client.post(
        "/api/incidents/p4-outage-test-inc-1/approve",
        json={"approved_by": "Hari", "execution_mode": "sandbox"},
    )
    assert recovered_approve.status_code == 200
    assert recovered_approve.json()["status"] == "REMEDIATION_COMPLETED_AND_VERIFIED"
    assert recovered_approve.json()["incident"]["status"] == "RESOLVED"
    assert recovered_approve.json()["incident"]["jit_token"]["token_id"].startswith("jit-wif-")
    assert recovered_approve.json()["incident"]["execution_result"]["gitops_pr_payload"]["reconciliation_mode"] == "BIDIRECTIONAL_GITOPS_PR"
    print("[PASS] Phase 4 Cloud Provider Status Check Pre-Flight verified: blocked mutations during active GCP/AWS/Azure outages and resumed cleanly on recovery")

    # 9. Phase 4 Unit Test: GitOps / Recent Deployment Correlator & Bidirectional GitOps PR Payload
    from services.gitops_correlator import gitops_correlator

    sample_commits = [
        {
            "event_type": "git_commit",
            "commit_sha": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
            "short_sha": "a1b2c3d4",
            "author": "release-bot",
            "committed_at": "2026-11-13T16:07:00+00:00",
            "subject": "Bump payments-api Cloud Run concurrency & Terraform VPC connector",
            "changed_files": ["terraform/payments-api/main.tf", "poc/app.py"],
        },
        {
            "event_type": "git_commit",
            "commit_sha": "9999999999999999999999999999999999999999",
            "short_sha": "99999999",
            "author": "old-dev",
            "committed_at": "2026-11-13T10:00:00+00:00",
            "subject": "Unrelated docs tweak",
            "changed_files": ["README.md"],
        },
    ]
    corr = gitops_correlator.correlate_recent_deployments(
        incident_timestamp="2026-11-13T16:15:00+00:00",
        workload="service/payments-api",
        window_minutes=180,
        git_commits=sample_commits,
    )
    assert corr["status"] == "CORRELATED_RECENT_DEPLOYMENT", corr
    top = corr["highest_confidence_match"]
    assert top is not None
    assert top["commit_sha"] == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    assert top["delta_minutes_before_incident"] == 8.0
    assert top["confidence"] == "HIGH"
    assert top["suggested_action"] == "REVERT_COMMIT_VIA_GITOPS_PR"

    pr_payload = gitops_correlator.build_gitops_reconciliation_pr_payload(
        incident_id="p4-gitops-inc-1",
        workload="service/payments-api",
        target_cloud="gcp",
        recommended_cli="gcloud run services update payments-api --concurrency=40 --region=us-central1",
        correlation_report=corr,
        reason="Revert bad concurrency config causing 503 timeouts",
    )
    assert pr_payload["reconciliation_mode"] == "BIDIRECTIONAL_GITOPS_PR"
    assert pr_payload["base_branch"] == "main"
    assert pr_payload["head_branch"].startswith("aaas/gitops-reconcile-payments-api-")
    assert pr_payload["correlated_suspect_commit"] == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    assert pr_payload["revert_recommended"] is True
    assert pr_payload["revert_command"].startswith("git revert --no-edit a1b2c3d4")
    assert len(pr_payload["files"]) == 2
    assert any(f["path"].endswith("reconciliation-metadata.json") for f in pr_payload["files"])

    # Verify Infra Agent exposes GitOps correlation tool & AgentCard capabilities
    assert "gitops-deployment-correlation" in infra_card.json()["capabilities"]
    assert "bidirectional-gitops-pr-reconciliation" in infra_card.json()["capabilities"]
    infra_gitops_res = infra_agent_mod.correlate_gitops_deployments(
        workload="gce_instance/testinstance1",
        target_cloud="gcp",
        recommended_cli="gcloud compute instances add-metadata testinstance1 --zone=us-west1-b",
    )
    assert infra_gitops_res["gitops_pr_payload"]["reconciliation_mode"] == "BIDIRECTIONAL_GITOPS_PR"
    assert recovered_approve.json()["incident"].get("gitops_correlation") is not None
    assert recovered_approve.json()["incident"].get("gitops_pr_payload") is not None
    print(
        f"[PASS] Phase 4 GitOps Deployment Correlator & Bidirectional PR verified: "
        f"suspect={top['short_sha']} ({top['delta_minutes_before_incident']}m prior, {top['confidence']}), "
        f"branch={pr_payload['head_branch']}, files={len(pr_payload['files'])}"
    )

    # 10. Phase 4 Unit Test: Database Agent Read-Only pg_stat_activity & Slow-Query Introspection
    db_dir = Path(__file__).resolve().parent.parent / "agents" / "database_agent"
    prev_agent_mod = sys.modules.pop("agent", None)
    try:
        sys.path.insert(0, str(db_dir))
        spec_db_agent = importlib.util.spec_from_file_location("agent", str(db_dir / "agent.py"))
        assert spec_db_agent and spec_db_agent.loader
        db_agent_mod = importlib.util.module_from_spec(spec_db_agent)
        sys.modules["agent"] = db_agent_mod
        spec_db_agent.loader.exec_module(db_agent_mod)

        spec_db_srv = importlib.util.spec_from_file_location("db_srv_mod", str(db_dir / "server.py"))
        assert spec_db_srv and spec_db_srv.loader
        db_srv_mod = importlib.util.module_from_spec(spec_db_srv)
        sys.modules["db_srv_mod"] = db_srv_mod
        spec_db_srv.loader.exec_module(db_srv_mod)
    finally:
        if str(db_dir) in sys.path:
            sys.path.remove(str(db_dir))
        if prev_agent_mod is not None:
            sys.modules["agent"] = prev_agent_mod

    db_client = TestClient(db_srv_mod.app)
    db_card = db_client.get("/.well-known/agent.json")
    assert db_card.status_code == 200
    assert "pg-stat-activity-readonly-introspection" in db_card.json()["capabilities"]
    assert "slow-query-analysis" in db_card.json()["capabilities"]

    # Verify strict read-only SQL guard rejects mutations / termination calls
    assert db_agent_mod.is_strictly_readonly_introspection_sql("SELECT pid, state FROM pg_stat_activity") is True
    assert db_agent_mod.is_strictly_readonly_introspection_sql("DELETE FROM orders WHERE id = 1") is False
    assert db_agent_mod.is_strictly_readonly_introspection_sql("SELECT pg_terminate_backend(4201)") is False
    assert db_agent_mod.is_strictly_readonly_introspection_sql("SELECT 1; DROP TABLE users") is False

    # Mock DB-API 2.0 read-only connection returning pg_stat_activity & pg_stat_statements rows
    executed_sqls: list[str] = []

    class _MockReadOnlyCursor:
        def __init__(self) -> None:
            self._rows: list[tuple] = []
            self.description: list[tuple] = []

        def __enter__(self) -> "_MockReadOnlyCursor":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def execute(self, sql: str) -> None:
            executed_sqls.append(sql.strip())
            if "FROM pg_stat_activity" in sql:
                self.description = [
                    ("pid",), ("usename",), ("application_name",), ("client_addr",),
                    ("state",), ("wait_event_type",), ("wait_event",), ("duration_ms",),
                    ("xact_duration_ms",), ("blocked_by_pids",), ("query",),
                ]
                self._rows = [
                    (
                        4102, "checkout_svc", "payments-api", "10.0.1.15",
                        "idle in transaction", "Client", "ClientRead", 45200.0,
                        45200.0, [], "UPDATE orders SET status = 'PENDING' WHERE id = 9981",
                    ),
                    (
                        4188, "checkout_svc", "payments-api", "10.0.1.18",
                        "active", "Lock", "transactionid", 18450.5,
                        18450.5, [4102], "SELECT * FROM orders WHERE customer_id = 42 FOR UPDATE",
                    ),
                ]
            elif "FROM pg_stat_statements" in sql:
                self.description = [
                    ("queryid",), ("calls",), ("total_exec_time_ms",), ("mean_exec_time_ms",),
                    ("rows",), ("shared_blks_read",), ("shared_blks_hit",), ("query",),
                ]
                self._rows = [
                    ("8819201", 1420, 4820000.0, 3394.37, 142000, 95000, 12000, "SELECT * FROM orders WHERE customer_id = 'secret'"),
                ]

        def fetchall(self) -> list[tuple]:
            return self._rows

    class _MockReadOnlyConn:
        def cursor(self) -> _MockReadOnlyCursor:
            return _MockReadOnlyCursor()

    pg_res = db_agent_mod.introspect_db_query_activity_detailed(
        instance_name="testdbinstance1",
        slow_query_threshold_ms=500.0,
        target_cloud="gcp",
        db_connection=_MockReadOnlyConn(),
    )
    assert pg_res["status"] == "LIVE_PG_STAT_ACTIVITY", pg_res
    assert pg_res["read_only_enforced"] is True
    assert any("SET TRANSACTION READ ONLY" in s for s in executed_sqls)
    assert pg_res["summary"]["total_active_sessions"] == 2
    assert pg_res["summary"]["long_running_count"] == 1
    assert pg_res["summary"]["idle_in_transaction_count"] == 1
    assert pg_res["summary"]["blocked_session_count"] == 1
    assert pg_res["blocking_chains"][0]["blocked_pid"] == 4188
    assert pg_res["blocking_chains"][0]["blocker_pid"] == 4102
    assert all(rec["requires_hitl_approval"] is True for rec in pg_res["dba_recommendations"])

    # Also verify out-of-band slow-query log analysis mode (Zero-Standing-Privilege default)
    slow_log_res = db_agent_mod.introspect_db_query_activity_detailed(
        instance_name="prod-rds-1",
        slow_query_threshold_ms=500.0,
        target_cloud="aws",
        log_lines=[
            "[2026-11-13T16:14:00Z] LOG:  duration: 2450.32 ms  statement: SELECT * FROM orders WHERE customer_id = 42 AND status = 'OPEN'",
            "[2026-11-13T16:14:02Z] ERROR:  deadlock detected while waiting for ShareLock on transaction 1234",
        ],
    )
    assert slow_log_res["status"] == "CONTROL_PLANE_SLOW_QUERY_ANALYSIS", slow_log_res
    assert slow_log_res["read_only_enforced"] is True
    assert slow_log_res["summary"]["slow_query_count"] == 1
    assert slow_log_res["top_slow_queries"][0]["table_hint"] == "orders"
    assert "42" not in slow_log_res["top_slow_queries"][0]["query_fingerprint"]
    assert len(slow_log_res["lock_warnings_in_logs"]) == 1
    print(
        f"[PASS] Phase 4 Database Agent Read-Only Query Introspection verified: "
        f"pg_stat_activity blocking_chain={pg_res['blocking_chains'][0]['blocked_pid']}->{pg_res['blocking_chains'][0]['blocker_pid']}, "
        f"slow_log_max_ms={slow_log_res['summary']['max_query_duration_ms']}ms, read_only_enforced=True"
    )

    # 11. Phase 5: Portable Deployment (/healthz, docker-compose.yml, Helm chart for EKS/AKS/GKE/OpenShift, intact Terraform)
    import re as _re
    import yaml as _yaml
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parent.parent

    # 11a. Control-plane /healthz endpoint
    hz = client.get("/healthz")
    assert hz.status_code == 200, hz.text
    hz_body = hz.json()
    assert hz_body["status"] == "ok", hz_body
    assert hz_body["service"] == "agent-triad-control-plane", hz_body
    for key in ("state_backend", "lock_backend", "telemetry_provider", "llm_provider"):
        assert key in hz_body and hz_body[key], hz_body

    # 11b. Local / Any-VM docker-compose.yml validation
    compose_path = repo_root / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml missing"
    compose_doc = _yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose_doc.get("services") or {}
    expected_services = {"control-plane", "db-agent", "infra-agent", "postgres", "redis"}
    assert expected_services.issubset(set(services.keys())), f"Missing services: {expected_services - set(services.keys())}"
    for svc_name in expected_services:
        assert "healthcheck" in services[svc_name], f"Missing healthcheck for {svc_name}"
    cp_env = services["control-plane"].get("environment") or {}
    assert cp_env.get("DATABASE_AGENT_URL") == "http://db-agent:8080", cp_env
    assert cp_env.get("INFRA_AGENT_URL") == "http://infra-agent:8080", cp_env
    assert "AAAS_POSTGRES_DSN" in cp_env and "AAAS_REDIS_URL" in cp_env, cp_env

    # 11c. Portable Kubernetes Helm Chart (EKS, AKS, GKE, OpenShift)
    helm_dir = repo_root / "deploy" / "helm" / "agent-triad"
    chart_doc = _yaml.safe_load((helm_dir / "Chart.yaml").read_text(encoding="utf-8"))
    values_doc = _yaml.safe_load((helm_dir / "values.yaml").read_text(encoding="utf-8"))
    assert chart_doc.get("apiVersion") == "v2" and chart_doc.get("name") == "agent-triad", chart_doc
    for k in ("global", "openshift", "serviceAccount", "llm", "state", "telemetry", "auth", "controlPlane", "dbAgent", "infraAgent", "postgres", "redis", "ingress", "openshiftRoute", "networkPolicy"):
        assert k in values_doc, f"Missing values.yaml section: {k}"
    sa_vals = values_doc["serviceAccount"]
    assert all(k in sa_vals for k in ("eksRoleArn", "aksClientId", "gkeServiceAccount")), sa_vals

    templates_dir = helm_dir / "templates"
    required_templates = [
        "_helpers.tpl",
        "serviceaccount.yaml",
        "configmap.yaml",
        "secret.yaml",
        "control-plane-deployment.yaml",
        "control-plane-service.yaml",
        "db-agent-deployment.yaml",
        "db-agent-service.yaml",
        "infra-agent-deployment.yaml",
        "infra-agent-service.yaml",
        "postgres.yaml",
        "redis.yaml",
        "ingress.yaml",
        "openshift-route.yaml",
        "hpa.yaml",
        "networkpolicy.yaml",
        "NOTES.txt",
    ]
    for tpl_name in required_templates:
        tpl_file = templates_dir / tpl_name
        assert tpl_file.exists(), f"Missing Helm template: {tpl_name}"
        tpl_text = tpl_file.read_text(encoding="utf-8")
        assert tpl_text.count("{{") == tpl_text.count("}}"), f"Unbalanced template braces in {tpl_name}"
        # Validate Go template block open/close balance (`if`/`with`/`range`/`define` vs `end`)
        actions = _re.findall(r"\{\{-?\s*(.*?)\s*-?\}\}", tpl_text, flags=_re.DOTALL)
        depth = 0
        for act in actions:
            stripped = act.strip()
            if stripped.startswith("/*"):
                continue
            head = stripped.split()[0] if stripped.split() else ""
            if head in ("if", "with", "range", "define"):
                depth += 1
            elif head == "end":
                depth -= 1
                assert depth >= 0, f"Unexpected 'end' in {tpl_name}"
        assert depth == 0, f"Unclosed template block (depth={depth}) in {tpl_name}"

    # 11d. Verify original GCP Cloud Run terraform/main.tf remains intact
    tf_main = (repo_root / "terraform" / "main.tf").read_text(encoding="utf-8")
    assert 'resource "google_cloud_run_v2_service"' in tf_main, "terraform/main.tf Cloud Run resources altered!"

    print(
        f"[PASS] Phase 5 Portable Deployment verified: /healthz=200, "
        f"docker-compose={len(expected_services)} services, "
        f"helm-chart={len(required_templates)} validated templates (EKS/AKS/GKE/OpenShift), terraform/main.tf intact"
    )

    # 12. Multi-Cloud UI & Backend Control Plane Integration (platform_runtime, target-cloud switcher, fault attribution, query_introspection, recheck-provider)
    st_rt = client.get("/api/state").json()
    pr = st_rt.get("platform_runtime")
    assert pr is not None, "Missing platform_runtime in /api/state"
    assert pr["cloud_provider"] == "gcp", pr
    for rt_key in (
        "default_cloud_provider",
        "region",
        "llm_provider",
        "llm_model",
        "telemetry_provider",
        "state_backend",
        "lock_backend",
        "auth_provider",
        "cloud_provider_status",
    ):
        assert rt_key in pr and pr[rt_key], f"Missing platform_runtime.{rt_key}: {pr}"
    assert pr["cloud_provider_status"]["mutations_allowed"] is True

    # Target Cloud Switcher API (gcp -> aws -> azure -> invalid 400 -> gcp)
    for target_c, expected_region in (("aws", "us-east-1"), ("azure", "eastus")):
        sw_res = client.post("/api/platform/target-cloud", json={"target_cloud": target_c})
        assert sw_res.status_code == 200, sw_res.text
        sw_body = sw_res.json()
        assert sw_body["status"] == "TARGET_CLOUD_UPDATED"
        assert sw_body["target_cloud"] == target_c
        assert sw_body["platform_runtime"]["cloud_provider"] == target_c
        assert sw_body["platform_runtime"]["region"] == expected_region

    bad_sw = client.post("/api/platform/target-cloud", json={"target_cloud": "oracle-cloud"})
    assert bad_sw.status_code == 400

    # Reset back to GCP and verify explicit target_cloud override on /api/atlas/chat
    reset_sw = client.post("/api/platform/target-cloud", json={"target_cloud": "gcp"})
    assert reset_sw.status_code == 200 and reset_sw.json()["target_cloud"] == "gcp"

    aws_chat = client.post(
        "/api/atlas/chat",
        json={
            "message": "How do I configure AWS STS AssumeRoleWithWebIdentity for 15-minute JIT tokens?",
            "target_cloud": "aws",
        },
    )
    assert aws_chat.status_code == 200, aws_chat.text
    assert aws_chat.json()["target_cloud"] == "aws"

    # Fault Attribution (External App/DB Fault) + Read-Only Query Introspection lifting on incident
    ext_db_log = {
        "log_id": "p4-ext-db-test-1",
        "timestamp": "2026-11-15T16:10:00+00:00",
        "severity": "ERROR",
        "source": "cloudsql_database",
        "cluster": "us-central1",
        "namespace": "production",
        "workload": "cloudsql/testdbinstance1",
        "pod": "agent-triad:testdbinstance1",
        "error_code": "SQL_CONNECTION_DROP",
        "title": "Cloud SQL Connection Drop & Slow Query Lock",
        "message": (
            "FATAL: remaining connection slots are reserved; "
            "duration: 3120.45 ms  statement: SELECT * FROM orders WHERE account_id = 8812 FOR UPDATE"
        ),
        "is_anomaly": True,
        "cloud_provider": "gcp",
    }
    asyncio.run(app_watcher_agent.detect_and_report_anomaly(ext_db_log))
    ext_state = client.get("/api/state").json()
    ext_inc = next((i for i in ext_state["incidents"] if i["incident_id"] == "p4-ext-db-test-1"), None)
    assert ext_inc is not None, "Expected p4-ext-db-test-1 in incidents"
    assert ext_inc["fault_attribution"]["origin"] == "EXTERNAL_APP_WORKLOAD", ext_inc["fault_attribution"]
    assert ext_inc["fault_attribution"]["mutations_allowed"] is True
    assert ext_inc["query_introspection"] is not None
    assert ext_inc["query_introspection"]["read_only_enforced"] is True
    assert ext_inc["query_introspection"]["summary"]["slow_query_count"] >= 1

    # Internal Provider Outage -> BLOCKED_PROVIDER_OUTAGE -> /recheck-provider (still blocked -> clears -> AWAITING_HITL_APPROVAL)
    try:
        cloud_status_service.inject_simulated_outage(
            cloud_provider="gcp",
            region="us-central1",
            service="Google Cloud SQL",
            title="Simulated GCP Cloud SQL Control Plane Disruption",
            severity="HIGH",
        )
        int_outage_log = {
            "log_id": "p4-recheck-test-1",
            "timestamp": "2026-11-15T16:12:00+00:00",
            "severity": "CRITICAL",
            "source": "cloud_run_revision",
            "cluster": "us-central1",
            "namespace": "production",
            "workload": "service/checkout-api",
            "pod": "checkout-api-00012",
            "error_code": "GCP_REGION_503",
            "title": "Regional Service Disruption in us-central1",
            "message": "503 Service Unavailable during active regional control plane disruption.",
            "is_anomaly": True,
            "cloud_provider": "gcp",
        }
        asyncio.run(app_watcher_agent.detect_and_report_anomaly(int_outage_log))
        outage_inc = next(i for i in client.get("/api/state").json()["incidents"] if i["incident_id"] == "p4-recheck-test-1")
        assert outage_inc["fault_attribution"]["origin"] == "INTERNAL_CLOUD_PROVIDER_OUTAGE"

        blk_res = client.post(
            "/api/incidents/p4-recheck-test-1/approve",
            json={"approved_by": "Hari", "execution_mode": "sandbox"},
        )
        assert blk_res.status_code == 200 and blk_res.json()["status"] == "BLOCKED_PROVIDER_OUTAGE"
        assert blk_res.json()["incident"]["jit_token"] is None

        still_blk = client.post("/api/incidents/p4-recheck-test-1/recheck-provider")
        assert still_blk.status_code == 200
        assert still_blk.json()["status"] == "BLOCKED_PROVIDER_OUTAGE"
        assert still_blk.json()["cloud_provider_status"]["mutations_allowed"] is False
    finally:
        cloud_status_service.clear_simulated_outages()

    cleared_recheck = client.post("/api/incidents/p4-recheck-test-1/recheck-provider")
    assert cleared_recheck.status_code == 200, cleared_recheck.text
    cleared_body = cleared_recheck.json()
    assert cleared_body["status"] == "AWAITING_HITL_APPROVAL", cleared_body
    assert cleared_body["incident"]["status"] == "AWAITING_HITL_APPROVAL"
    assert cleared_body["cloud_provider_status"]["mutations_allowed"] is True
    assert cleared_body["fault_attribution"]["origin"] == "EXTERNAL_APP_WORKLOAD"
    print(
        "[PASS] Multi-Cloud Control Plane & Phase 4 UI/Backend Wiring verified: "
        "platform_runtime, target-cloud switcher (GCP/AWS/Azure), fault_attribution (External vs Internal), "
        "read-only query_introspection, and /recheck-provider outage recovery!"
    )

    # 13. Live Log Alert Triage: Mark Safe to Ignore, Restore, and Fix via AaaS Chat (single & batch)
    from app import logging_service as app_logging_service

    triage_log_1 = {
        "log_id": "triage-test-log-1",
        "timestamp": "2026-11-16T05:15:00+00:00",
        "severity": "ERROR",
        "source": "gcp:cloud_run_revision",
        "cluster": "us-central1",
        "namespace": "cloud-run",
        "workload": "service/orders-api",
        "pod": "orders-api-00011",
        "error_code": "CLOUD_RUN_RUNTIME_ERROR",
        "title": "Cloud Run (orders-api): Upstream connection reset by peer",
        "message": "Upstream connection reset by peer while calling inventory-svc",
        "is_anomaly": True,
        "cloud_provider": "gcp",
    }
    triage_log_2 = {
        "log_id": "triage-test-log-2",
        "signature_key": "cloudsql:testdbinstance1:SQL_SLOW_QUERY",
        "timestamp": "2026-11-16T05:16:00+00:00",
        "severity": "WARNING",
        "source": "gcp:cloudsql_database",
        "cluster": "us-central1",
        "namespace": "cloud-sql",
        "workload": "cloudsql/testdbinstance1",
        "pod": "agent-triad:testdbinstance1",
        "error_code": "SQL_SLOW_QUERY",
        "title": "Cloud SQL (testdbinstance1): Slow query lock wait detected",
        "message": "duration: 1850.00 ms  statement: SELECT * FROM orders WHERE status = 'PENDING'",
        "is_anomaly": True,
        "cloud_provider": "gcp",
    }
    triage_log_2_dup = {
        "log_id": "triage-test-log-2-dup",
        "signature_key": "cloudsql:testdbinstance1:SQL_SLOW_QUERY",
        "timestamp": "2026-11-16T05:16:30+00:00",
        "severity": "WARNING",
        "source": "gcp:cloudsql_database",
        "cluster": "us-central1",
        "namespace": "cloud-sql",
        "workload": "cloudsql/testdbinstance1",
        "pod": "agent-triad:testdbinstance1",
        "error_code": "SQL_SLOW_QUERY",
        "title": "Cloud SQL (testdbinstance1): Slow query lock wait detected (sibling)",
        "message": "duration: 1920.00 ms  statement: SELECT * FROM orders WHERE status = 'PENDING'",
        "is_anomaly": True,
        "cloud_provider": "gcp",
    }
    app_logging_service._local_logs.insert(0, triage_log_2_dup)
    app_logging_service._local_logs.insert(0, triage_log_2)
    app_logging_service._local_logs.insert(0, triage_log_1)

    # 13a. Mark single log as Safe to Ignore -> reflected in /api/state
    ign_res = client.post(
        "/api/logs/ignore",
        json={"log_ids": ["triage-test-log-1"], "reason": "Expected / Benign Noise"},
    )
    assert ign_res.status_code == 200, ign_res.text
    assert ign_res.json()["status"] == "LOGS_MARKED_SAFE_TO_IGNORE"
    assert "triage-test-log-1" in ign_res.json()["ignored_ids"]

    state_ign = client.get("/api/state").json()
    assert "triage-test-log-1" in state_ign.get("ignored_log_ids", [])
    ign_entry = next(l for l in state_ign["logs"] if l["log_id"] == "triage-test-log-1")
    assert ign_entry["ignored"] is True
    assert ign_entry["triage_status"] == "IGNORED"
    assert ign_entry["ignored_reason"] == "Expected / Benign Noise"

    # 13a-ii. Storm suppression: ignore_similar_signatures=True also suppresses matching sibling alerts
    sim_ign_res = client.post(
        "/api/logs/ignore",
        json={
            "log_ids": ["triage-test-log-2"],
            "reason": "Duplicate of Active Alert",
            "ignore_similar_signatures": True,
        },
    )
    assert sim_ign_res.status_code == 200, sim_ign_res.text
    assert sim_ign_res.json()["similar_expanded_count"] >= 1
    assert "triage-test-log-2-dup" in sim_ign_res.json()["ignored_ids"]

    # 13b. Restore ignored logs back to active alerts
    unign_res = client.post(
        "/api/logs/unignore",
        json={"log_ids": ["triage-test-log-1", "triage-test-log-2", "triage-test-log-2-dup"]},
    )
    assert unign_res.status_code == 200, unign_res.text
    assert "triage-test-log-1" in unign_res.json()["restored_ids"]
    state_unign = client.get("/api/state").json()
    unign_entry = next(l for l in state_unign["logs"] if l["log_id"] == "triage-test-log-1")
    assert unign_entry["ignored"] is False
    assert unign_entry["triage_status"] == "OPEN"

    # 13c. Single log -> Fix via AaaS Chat (escalates to dedicated Incident Remediation Chat)
    fix_single_res = client.post("/api/logs/fix-via-chat", json={"log_ids": ["triage-test-log-1"]})
    assert fix_single_res.status_code == 200, fix_single_res.text
    fix_single_body = fix_single_res.json()
    assert fix_single_body["status"] == "ESCALATED_TO_AAAS_CHAT"
    assert fix_single_body["mode"] == "incident"
    assert fix_single_body["incident_id"] == "triage-test-log-1"
    assert fix_single_body["incident"]["status"] == "AWAITING_HITL_APPROVAL"

    # 13d. Multiple logs -> Fix All Together in AaaS Chat (unified Direct Atlas Chat diagnosis)
    fix_batch_res = client.post(
        "/api/logs/fix-via-chat",
        json={"log_ids": ["triage-test-log-1", "triage-test-log-2"], "strategy": "auto"},
    )
    assert fix_batch_res.status_code == 200, fix_batch_res.text
    fix_batch_body = fix_batch_res.json()
    assert fix_batch_body["status"] == "SENT_TO_AAAS_CHAT"
    assert fix_batch_body["mode"] == "direct_chat"
    assert fix_batch_body["log_count"] == 2
    assert fix_batch_body["chat_result"]["action_taken"] == "DIRECT_ATLAS_CHAT_REPLY"

    # 13e. Multiple logs -> Queue Separately (parallel HITL incident cards in Command Center)
    queue_sep_res = client.post(
        "/api/logs/fix-via-chat",
        json={"log_ids": ["triage-test-log-1", "triage-test-log-2"], "strategy": "separate_incidents"},
    )
    assert queue_sep_res.status_code == 200, queue_sep_res.text
    queue_sep_body = queue_sep_res.json()
    assert queue_sep_body["status"] == "QUEUED_SEPARATE_INCIDENTS"
    assert queue_sep_body["mode"] == "separate_incidents"
    assert queue_sep_body["queued_count"] == 2
    assert set(queue_sep_body["incident_ids"]) == {"triage-test-log-1", "triage-test-log-2"}
    print(
        "[PASS] Graceful Multi-Alert Live Log Triage verified: /api/logs/ignore (+similar storm suppression), "
        "/api/logs/unignore, single-alert incident handoff, unified multi-alert AaaS Chat, and separate-incident queuing!"
    )

    # 14. Scenario 1 Live GCP Role-Play: External IaC / IAM Drift (Datastream Private Connectivity to Cloud SQL)
    import datetime as _dt
    from types import SimpleNamespace as _SimpleNamespace
    from providers.gcp.cloud_logging_adapter import GCPCloudLoggingAdapter

    # 14a. Verify real Datastream Cloud Audit Log normalization (`audited_resource` / `datastream.googleapis.com`, gRPC code 9)
    ds_adapter = GCPCloudLoggingAdapter(project_id="agent-triad", initial_poll=False)
    sample_ds_entry = _SimpleNamespace(
        severity="ERROR",
        resource=_SimpleNamespace(
            type="audited_resource",
            labels={
                "service": "datastream.googleapis.com",
                "method": "google.cloud.datastream.v1.Datastream.CreatePrivateConnection",
                "project_id": "agent-triad",
            },
        ),
        log_name="projects/agent-triad/logs/cloudaudit.googleapis.com%2Factivity",
        timestamp=_dt.datetime(2026, 11, 16, 11, 45, 0, tzinfo=_dt.timezone.utc),
        insert_id="t636n0d8nfp",
        trace=None,
        span_id=None,
        payload={
            "serviceName": "datastream.googleapis.com",
            "methodName": "google.cloud.datastream.v1.Datastream.CreatePrivateConnection",
            "resourceName": "projects/agent-triad/locations/europe-west2/privateConnections/ds-priv-conn-iam-check",
            "resourceLocation": {"currentLocations": ["europe-west2"]},
            "status": {
                "code": 9,
                "message": (
                    "com.google.cloud.datastream.clh.handlers.CreatePrivateConnectionHandler$ValidationErrorException: "
                    "<eye3 title='FAILED_PRECONDITION'/> generic::FAILED_PRECONDITION: "
                    "Missing permissions to validate that the provided IP range is available. "
                    "Please check that Datastream SA has the required permissions."
                ),
            },
        },
    )
    norm_ds = ds_adapter._normalize_gcp_entry(sample_ds_entry)
    assert norm_ds is not None, "Expected Datastream audit error entry to normalize"
    assert norm_ds["log_id"] == "gcp-ds-t636n0d8nfp", norm_ds
    assert norm_ds["scenario_id"] == "datastream_iam_drift", norm_ds
    assert norm_ds["cluster"] == "europe-west2", norm_ds
    assert norm_ds["workload"] == "datastream/ds-priv-conn-iam-check", norm_ds
    assert (
        'gcloud projects add-iam-policy-binding agent-triad '
        '--member="serviceAccount:service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com" '
        '--role="roles/compute.networkAdmin"'
    ) == norm_ds["recommended_kubectl"], norm_ds["recommended_kubectl"]

    # 14b. Live `agent-triad` Support Ticket Intake -> Phase 1-4 verification (Zero Autonomous Writes)
    live_tkt_res = client.post(
        "/api/tickets/ingest",
        json={
            "customer_name": "HSBC Global Services (UK) Limited",
            "project_id": "projects/agent-triad",
            "region": "europe-west2",
            "business_impact": "Non-Production System impaired",
            "service_agent_email": "service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com",
        },
    )
    assert live_tkt_res.status_code == 200, live_tkt_res.text
    live_tkt_body = live_tkt_res.json()
    assert live_tkt_body["status"] == "TICKET_INGESTED_AWAITING_HITL", live_tkt_body
    live_inc = live_tkt_body["incident"]
    live_inc_id = live_tkt_body["incident_id"]

    # Phase 1: Green regional health -> Safety Brake disengaged
    assert live_inc["cloud_provider_status"]["status"] in ("HEALTHY", "OPERATIONAL"), live_inc["cloud_provider_status"]
    assert live_inc["cloud_provider_status"]["mutations_allowed"] is True
    assert live_inc["cloud_provider_status"]["region"] == "europe-west2"
    assert live_inc["fault_attribution"]["origin"] == "EXTERNAL_APP_WORKLOAD"

    # Phase 2: Parallel Security Agent + Infra Agent findings (via live Cloud Run ADK A2A or fallback)
    assert live_inc["specialist_worker"]["id"] == "security-agent", live_inc["specialist_worker"]
    coord_ids = [s["id"] for s in live_inc["coordinated_specialists"]]
    assert "security-agent" in coord_ids and "infra-agent" in coord_ids, coord_ids
    assert live_inc["iam_audit"]["tool_name"] == "Security_Agent_Tool"
    assert isinstance(live_inc["iam_audit"]["binding_present"], bool), live_inc["iam_audit"]
    assert live_inc["iam_audit"]["status"] in ("MISSING_REQUIRED_IAM_BINDING", "IAM_BINDING_PRESENT"), live_inc["iam_audit"]
    assert live_inc["iam_audit"]["required_role"] == "roles/compute.networkAdmin"
    assert live_inc["log_entry"]["severity"] == "ERROR"
    assert live_inc["gitops_correlation"] is not None
    assert live_inc["impact_analysis"].get("live_security_agent_diagnosis") is not None, "Expected Security Agent ADK diagnosis"
    assert live_inc["impact_analysis"].get("live_infra_agent_diagnosis") is not None, "Expected Infra Agent ADK diagnosis"
    chat_senders = [m.get("sender", "") for m in live_inc["chat_messages"]]
    assert any("agent-triad-security-agent" in s for s in chat_senders), chat_senders
    assert any("agent-triad-infra-agent" in s for s in chat_senders), chat_senders

    # Phase 3: Blameless RCA + exact live CLI + exact HITL prompt
    expected_live_cli = (
        'gcloud projects add-iam-policy-binding agent-triad '
        '--member="serviceAccount:service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com" '
        '--role="roles/compute.networkAdmin"'
    )
    assert live_inc["impact_analysis"]["recommended_kubectl"] == expected_live_cli
    greeting_text = live_inc["chat_messages"][0]["text"]
    assert "OPERATIONAL" in greeting_text
    assert "Security_Agent_Tool" in greeting_text
    assert "GitOps_Correlator_Tool" in greeting_text
    assert "Do NOT remove" in greeting_text
    assert expected_live_cli in greeting_text
    assert "Click 'I Accept' to mint a 15-minute JIT token and execute this GitOps synchronization." in greeting_text

    # Phase 4: Strict Zero Autonomous Execution before human approval
    assert live_inc["status"] == "AWAITING_HITL_APPROVAL"
    assert live_inc["jit_token"] is None
    assert live_inc["execution_result"] is None

    # 14c. Stage 2 HITL Approval in `sandbox` mode (preserves live armed GCP demo state!)
    ds_appr_res = client.post(
        f"/api/incidents/{live_inc_id}/approve",
        json={"approved_by": "Hari", "execution_mode": "sandbox"},
    )
    assert ds_appr_res.status_code == 200, ds_appr_res.text
    ds_appr_inc = ds_appr_res.json()["incident"]
    assert ds_appr_inc["status"] == "RESOLVED"
    assert ds_appr_inc["jit_token"] is not None
    assert ds_appr_inc["execution_result"]["iam_execution_result"]["status"] == "SANDBOX_VALIDATED"
    assert ds_appr_inc["execution_result"]["reconciliation_pr"] is not None
    assert ds_appr_inc["verification_result"]["status"] == "VERIFIED_HEALTHY"

    # 14d. External HSBC reference ticket with 12-minute-prior Terraform drift deployment
    twelve_min_ago = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=12)).isoformat()
    hsbc_res = client.post(
        "/api/tickets/ingest",
        json={
            "customer_name": "HSBC Global Services (UK) Limited",
            "project_id": "projects/hsbc-10534429-fdreu-dev",
            "region": "europe-west2",
            "business_impact": "Non-Production System impaired",
            "service_agent_email": "service-ORG@gcp-sa-datastream.iam.gserviceaccount.com",
            "mock_deployments": [
                {
                    "event_type": "terraform_pipeline",
                    "commit_sha": "tf-drift-90210",
                    "revision": "tf-apply-441",
                    "author": "hsbc-gitops-runner",
                    "deployed_at": twelve_min_ago,
                    "summary": "Terraform state drift removed Datastream service account roles/compute.networkAdmin binding",
                    "changed_files": ["terraform/shared-vpc/iam.tf"],
                    "service": "datastream/private-connectivity-ew2",
                }
            ],
        },
    )
    assert hsbc_res.status_code == 200, hsbc_res.text
    hsbc_inc = hsbc_res.json()["incident"]
    expected_hsbc_cli = (
        'gcloud projects add-iam-policy-binding hsbc-10534429-fdreu-dev '
        '--member="serviceAccount:service-ORG@gcp-sa-datastream.iam.gserviceaccount.com" '
        '--role="roles/compute.networkAdmin"'
    )
    assert hsbc_inc["impact_analysis"]["recommended_kubectl"] == expected_hsbc_cli
    assert hsbc_inc["gitops_correlation"]["status"] == "CORRELATED_RECENT_DEPLOYMENT"
    assert hsbc_inc["gitops_correlation"]["highest_confidence_match"]["short_sha"] == "tf-drift"
    assert hsbc_inc["status"] == "AWAITING_HITL_APPROVAL"
    assert hsbc_inc["jit_token"] is None

    # 14e. Direct Atlas Chat with pasted Datastream FAILED_PRECONDITION ticket -> 4-phase reply, zero writes
    ds_chat_res = client.post(
        "/api/atlas/chat",
        json={
            "message": (
                "Customer: HSBC Global Services (UK) Limited. Project ID: projects/agent-triad. Region: europe-west2. "
                "Error: generic::FAILED_PRECONDITION: Missing permissions to validate that the provided IP range is available. "
                "Please check that Datastream SA has the required permissions. We cannot create private connectivity to CloudSQL."
            ),
            "target_cloud": "gcp",
        },
    )
    assert ds_chat_res.status_code == 200, ds_chat_res.text
    ds_chat_body = ds_chat_res.json()
    assert ds_chat_body["specialist_worker"]["id"] == "security-agent"
    assert expected_live_cli in ds_chat_body["reply"]
    assert "Click 'I Accept' to mint a 15-minute JIT token and execute this GitOps synchronization." in ds_chat_body["reply"]
    assert ds_chat_body["terraform_bundle"] is not None
    assert "prevent_destroy = true" in ds_chat_body["terraform_bundle"]["hcl_code"]

    # 14f. Verify standalone Security Agent & Infra Agent A2A servers + UI Live ADK badge
    ui_html = (Path(__file__).resolve().parent / "static" / "index.html").read_text(encoding="utf-8")
    assert "agent-triad-security-agent" in ui_html, "Expected agent-triad-security-agent Live ADK badge in UI"
    sec_dir = str(Path(__file__).resolve().parents[1] / "agents" / "security_agent")
    assert (Path(sec_dir) / "server.py").exists() and (Path(sec_dir) / "agent.py").exists()
    import importlib.util as _ilu
    _sec_spec = _ilu.spec_from_file_location("aaas_sec_srv_test", str(Path(sec_dir) / "server.py"))
    assert _sec_spec and _sec_spec.loader
    if sec_dir not in sys.path:
        sys.path.insert(0, sec_dir)
    _sec_srv = _ilu.module_from_spec(_sec_spec)
    sys.modules[_sec_spec.name] = _sec_srv
    _sec_spec.loader.exec_module(_sec_srv)
    sec_client = TestClient(_sec_srv.app)
    sec_card = sec_client.get("/.well-known/agent.json")
    assert sec_card.status_code == 200 and sec_card.json()["id"] == "security-agent"
    assert sec_card.json()["ZeroStandingPrivilege"] is True
    sec_reject = sec_client.post(
        "/a2a",
        json={
            "jsonrpc": "2.0",
            "id": "sec-test-nojit",
            "method": "tasks/send",
            "params": {"skill_id": "execute_approved_security_remediation", "data": {"project_id": "agent-triad"}},
        },
    )
    assert sec_reject.status_code == 200
    assert sec_reject.json()["result"]["status"] == "REJECTED_INVALID_JIT_TOKEN"

    # 14g. Honest Failure Handling: 403 / LIVE_IAM_EXECUTION_ERROR MUST mark REMEDIATION_FAILED (never RESOLVED) & log ERROR
    from services.security_iam_service import security_iam_service as _live_iam_svc
    from app import logging_service as _app_log_svc

    fail_ticket_res = client.post(
        "/api/tickets/ingest",
        json={
            "customer_name": "HSBC Global Services (UK) Limited",
            "project_id": "projects/agent-triad",
            "region": "europe-west2",
            "service_agent_email": "service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com",
        },
    )
    assert fail_ticket_res.status_code == 200
    fail_inc_id = fail_ticket_res.json()["incident_id"]

    _orig_apply = _live_iam_svc.apply_iam_policy_binding_live

    def _mock_403_apply(*args, **kwargs):
        return {
            "status": "LIVE_IAM_EXECUTION_ERROR",
            "live_executed": False,
            "project_id": "agent-triad",
            "member": "serviceAccount:service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com",
            "role": "roles/compute.networkAdmin",
            "command": expected_live_cli,
            "jit_token_id": kwargs.get("jit_token_id", ""),
            "jit_impersonation_mode": "LIVE_GCP_ADMIN_FALLBACK_TOKEN",
            "impersonation_error": "HTTP 403 simulated impersonation denial",
            "verified_after_apply": False,
            "error": "HTTPStatusError: Client error '403 Forbidden' for url 'https://cloudresourcemanager.googleapis.com/v1/projects/agent-triad:setIamPolicy'",
            "summary": "[Security Agent • GCP IAM API] Live setIamPolicy error: HTTPStatusError: Client error '403 Forbidden'",
        }

    try:
        _live_iam_svc.apply_iam_policy_binding_live = _mock_403_apply
        approve_fail_res = client.post(
            f"/api/incidents/{fail_inc_id}/approve",
            json={"approved_by": "Hari", "execution_mode": "live"},
        )
    finally:
        _live_iam_svc.apply_iam_policy_binding_live = _orig_apply

    assert approve_fail_res.status_code == 200, approve_fail_res.text
    fail_body = approve_fail_res.json()
    assert fail_body["status"] == "REMEDIATION_FAILED", f"Expected REMEDIATION_FAILED, got {fail_body['status']}"
    fail_inc = fail_body["incident"]
    assert fail_inc["status"] == "REMEDIATION_FAILED", f"Must NOT claim RESOLVED on 403! Got {fail_inc['status']}"
    assert fail_inc.get("resolved_at") is None
    assert fail_inc["execution_result"]["status"] == "FAILED"
    assert fail_inc["execution_result"].get("reconciliation_pr") is None
    assert fail_inc["iam_audit"]["binding_present"] is False
    assert any(
        (lg.get("severity") == "ERROR" and "403 Forbidden" in str(lg.get("message", "")) and lg.get("error_code") == "REMEDIATION_ERROR")
        for lg in _app_log_svc._local_logs[:10]
    ), "Expected ERROR log entry in Cloud Logging / View Logs stream on live IAM 403 failure"

    # Reopen failed incident cleanly back to AWAITING_HITL_APPROVAL
    reopen_fail_res = client.post(f"/api/incidents/{fail_inc_id}/reopen")
    assert reopen_fail_res.status_code == 200
    assert reopen_fail_res.json()["incident"]["status"] == "AWAITING_HITL_APPROVAL"

    # 14h. One-Click Scenario 1 Fault Re-Creator endpoint + strict sandbox guardrail
    recreate_ok = client.post(
        "/api/scenarios/datastream-iam-drift/recreate",
        json={"execute_live": False},
    )
    assert recreate_ok.status_code == 200, recreate_ok.text
    assert recreate_ok.json()["status"] == "FAULT_RECREATED_SANDBOX_DRY_RUN"
    assert recreate_ok.json()["verified_stripped"] is True

    recreate_blocked = client.post(
        "/api/scenarios/datastream-iam-drift/recreate",
        json={"project_id": "projects/HSBC_Target", "execute_live": False},
    )
    assert recreate_blocked.status_code == 400, f"External project reset must be blocked, got {recreate_blocked.status_code}"

    print(
        "[PASS] Scenario 1 Live Datastream IAM Drift Role-Play verified: real GCP audit log normalizer, "
        "live Security Agent + Infra Agent Cloud Run ADK A2A parallel delegation, Phase 1-4 Blameless RCA, "
        "exact live CLI, HSBC reference ticket, Direct Atlas Chat, honest 403 REMEDIATION_FAILED + Cloud Logging ERROR, "
        "1-click Scenario 1 fault re-creator (+sandbox guardrail), and strict Stage 2 HITL zero-autonomy!"
    )

    # -----------------------------------------------------------------------
    # 15. Colleague Feedback Safeguards:
    #     (a) Support Ticket ERROR Cloud Logging Persistence
    #     (b) Tier-2 Critical Irreversible HITL Confirmation Gate
    #     (c) Pre-Execution Snapshot & 1-Click 'Revert to Stable Snapshot'
    #     (d) 45s Watchdog Cross-Service Cascading Failure Auto-Rollback + 7-Day Poison-Pill
    # -----------------------------------------------------------------------
    import datetime
    from services.agent_harness import agent_harness as _harness_singleton
    from providers.base_telemetry import normalize_otel_anomaly as _norm_otel
    from app import lead_orchestrator as _app_orch

    # 15a. Support Ticket ERROR Cloud Logging Persistence (sandbox vs external project guardrail)
    recorded_ticket_anomalies = []
    _orig_rec_anom = _app_log_svc.record_anomaly_log

    def _spy_record_anomaly(entry):
        recorded_ticket_anomalies.append(dict(entry))
        return True

    try:
        _app_log_svc.record_anomaly_log = _spy_record_anomaly
        tkt_sandbox = client.post(
            "/api/tickets/ingest",
            json={
                "customer_name": "Sandbox Cloud Logging Persistence Check",
                "project_id": "projects/agent-triad",
                "region": "europe-west2",
            },
        )
        assert tkt_sandbox.status_code == 200
        assert len(recorded_ticket_anomalies) == 1
        assert recorded_ticket_anomalies[0]["severity"] == "ERROR"
        assert recorded_ticket_anomalies[0]["error_code"] == "DATASTREAM_FAILED_PRECONDITION_IAM"
        assert recorded_ticket_anomalies[0]["project_id"] == "agent-triad"

        tkt_external = client.post(
            "/api/tickets/ingest",
            json={
                "customer_name": "External Reference Guardrail Check",
                "project_id": "projects/HSBC_Target",
                "region": "europe-west2",
            },
        )
        assert tkt_external.status_code == 200
        assert len(recorded_ticket_anomalies) == 1, "External project tickets must NOT write to sandbox Cloud Logging"
    finally:
        _app_log_svc.record_anomaly_log = _orig_rec_anom

    crit_inc_id = tkt_external.json()["incident_id"]
    rev_inc_id = tkt_sandbox.json()["incident_id"]

    # 15b. Tier-2 Critical Irreversible HITL Gate: blocks blind 'I accept' without explicit confirmation
    irrev_cmd = "gcloud sql instances restart testdbinstance1 --project=agent-triad"
    risk_eval = _harness_singleton.classify_change_risk(
        workload="cloudsql/testdbinstance1",
        command=irrev_cmd,
    )
    assert risk_eval["risk_tier"] == "TIER_2_CRITICAL_IRREVERSIBLE"
    assert risk_eval["reversible"] is False
    assert risk_eval["requires_critical_confirmation"] is True

    blind_accept_res = client.post(
        f"/api/incidents/{crit_inc_id}/approve",
        json={
            "approved_by": "Hari",
            "execution_mode": "sandbox",
            "custom_kubectl": irrev_cmd,
            "critical_change_confirmed": False,
        },
    )
    assert blind_accept_res.status_code == 200, blind_accept_res.text
    blind_body = blind_accept_res.json()
    assert blind_body["status"] == "CRITICAL_CONFIRMATION_REQUIRED"
    assert blind_body["requires_critical_confirmation"] is True
    assert blind_body["incident"]["status"] == "AWAITING_HITL_APPROVAL"
    assert blind_body["incident"].get("jit_token") is None, "Zero JIT tokens may be minted when critical confirmation is missing"

    # Unlock Tier-2 gate once operator explicitly confirms irreversible impact
    confirmed_accept_res = client.post(
        f"/api/incidents/{crit_inc_id}/approve",
        json={
            "approved_by": "Hari",
            "execution_mode": "sandbox",
            "custom_kubectl": irrev_cmd,
            "critical_change_confirmed": True,
        },
    )
    assert confirmed_accept_res.status_code == 200, confirmed_accept_res.text
    confirmed_body = confirmed_accept_res.json()
    assert confirmed_body["status"] == "REMEDIATION_COMPLETED_AND_VERIFIED"
    assert confirmed_body["incident"]["status"] == "RESOLVED"
    assert confirmed_body["incident"]["last_approval_gate"] == "CRITICAL_IRREVERSIBLE_CONFIRMED"
    assert "[Irreversible Impact Confirmed]" in confirmed_body["incident"]["approved_by"]

    # 15c. Pre-Execution Stable Snapshot & 1-Click 'Revert to Stable Snapshot' + 7-Day Poison-Pill Quarantine
    rev_ok_res = client.post(
        f"/api/incidents/{rev_inc_id}/approve",
        json={"approved_by": "Hari", "execution_mode": "sandbox"},
    )
    assert rev_ok_res.status_code == 200
    rev_inc = rev_ok_res.json()["incident"]
    assert rev_inc["status"] == "RESOLVED"
    snap = rev_inc.get("rollback_snapshot") or rev_inc["execution_result"].get("rollback_snapshot")
    assert isinstance(snap, dict) and snap.get("snapshot_id", "").startswith("snap-")
    assert "remove-iam-policy-binding" in snap.get("revert_command", "")
    assert snap.get("reversible") is True

    manual_rb_res = client.post(
        f"/api/incidents/{rev_inc_id}/rollback",
        json={
            "requested_by": "Hari",
            "reason": "Downstream analytics pipeline reported connection errors after fix",
            "execution_mode": "sandbox",
            "quarantine_signature": True,
        },
    )
    assert manual_rb_res.status_code == 200, manual_rb_res.text
    rb_body = manual_rb_res.json()
    assert rb_body["status"] == "REMEDIATION_ROLLED_BACK"
    assert rb_body["incident"]["status"] == "ROLLED_BACK"
    assert rb_body["rollback_result"]["status"] == "ROLLED_BACK_TO_SNAPSHOT"
    q_info = rb_body["rollback_result"].get("poison_pill_quarantine") or {}
    q_sig = q_info.get("signature_hash")
    assert q_sig and q_sig in _harness_singleton.poison_pill_quarantine
    try:
        gate_after_q = _harness_singleton.evaluate_policy_gate(
            workload=rev_inc["workload"],
            command=rev_inc["execution_result"]["command"],
        )
        assert gate_after_q["passed"] is False
        assert any("Poison-Pill Quarantine" in v for v in gate_after_q["violations"])
    finally:
        if q_sig:
            _harness_singleton.clear_poison_pill(q_sig)

    # 15d. 45s Watchdog Cross-Service Cascading Failure Auto-Rollback
    try:
        _app_log_svc.record_anomaly_log = _spy_record_anomaly
        cas_tkt = client.post(
            "/api/tickets/ingest",
            json={
                "customer_name": "Cascading Failure Watchdog Test",
                "project_id": "projects/HSBC_Target",
                "region": "europe-west2",
                "workload": "datastream/private-connectivity-cascade-test",
            },
        )
    finally:
        _app_log_svc.record_anomaly_log = _orig_rec_anom
    assert cas_tkt.status_code == 200
    cas_inc_id = cas_tkt.json()["incident_id"]

    collateral_log_id = "col-err-checkout-billing-01"
    future_ts = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=15)).isoformat()
    collateral_entry = _norm_otel(
        log_id=collateral_log_id,
        signature_key="cloudrun:checkout-billing-api:503_UPSTREAM_RESET",
        timestamp=future_ts,
        severity="ERROR",
        scenario_id="cloud_run_5xx",
        title="Cloud Run checkout-billing-api: 503 Upstream Peer Connection Reset",
        source="gcp:run.googleapis.com",
        project_id="HSBC_Target",
        cluster="europe-west2",
        namespace="payments",
        workload="service/checkout-billing-api",
        pod="checkout-billing-api-00014",
        container="billing-api",
        error_code="HTTP_503_CASCADING_PEER_FAILURE",
        message="503 Service Unavailable: VPC peering route flap broke checkout-billing-api DB pool",
        metrics_snapshot={"http_5xx_rate": 24.5},
        recommended_kubectl="gcloud run services update-traffic checkout-billing-api --region=europe-west2 --to-latest",
        recommended_action_type="cloud_run_revision_rollback",
        is_anomaly=True,
        persisted_to_gcp=False,
        cloud_provider="gcp",
    )
    _app_log_svc._local_logs.insert(0, collateral_entry)
    auto_q_sig = None
    try:
        cas_approve = client.post(
            f"/api/incidents/{cas_inc_id}/approve",
            json={"approved_by": "Hari", "execution_mode": "sandbox"},
        )
        assert cas_approve.status_code == 200, cas_approve.text
        cas_body = cas_approve.json()
        assert cas_body["status"] == "REMEDIATION_ROLLED_BACK", f"Expected auto-rollback, got {cas_body['status']}"
        cas_inc = cas_body["incident"]
        assert cas_inc["status"] == "ROLLED_BACK"
        assert cas_inc["rollback_auto_triggered"] is True
        assert cas_inc["verification_result"]["status"] == "CASCADING_FAILURE_DETECTED"
        assert "service/checkout-billing-api" in cas_inc["verification_result"]["affected_collateral_services"]
        assert collateral_log_id in (cas_inc.get("collateral_incident_ids") or [])
        assert _app_orch.incidents[collateral_log_id]["status"] == "AWAITING_HITL_APPROVAL"
        auto_q_sig = (cas_inc.get("poison_pill_quarantine") or {}).get("signature_hash")
        assert auto_q_sig and auto_q_sig in _harness_singleton.poison_pill_quarantine
    finally:
        _app_log_svc._local_logs[:] = [
            e for e in _app_log_svc._local_logs if e.get("log_id") != collateral_log_id
        ]
        _app_orch.incidents.pop(collateral_log_id, None)
        _app_orch.audit_events.pop(collateral_log_id, None)
        if auto_q_sig:
            _harness_singleton.clear_poison_pill(auto_q_sig)

    # 15e. Post-Fix Verification on Service Health ('Live Health Watch' Blink & Click Check)
    plat_health_res = client.post("/api/platform/verify-health")
    assert plat_health_res.status_code == 200, plat_health_res.text
    plat_health = plat_health_res.json()
    assert plat_health["report"]["incident_status"] == "PLATFORM_WATCH"
    assert len(plat_health["report"]["checks"]) == 4

    resolved_health_res = client.post(f"/api/incidents/{crit_inc_id}/verify-health")
    assert resolved_health_res.status_code == 200, resolved_health_res.text
    resolved_health = resolved_health_res.json()
    assert resolved_health["status"] == "VERIFIED_HEALTHY", resolved_health
    assert resolved_health["report"]["overall_health"] == "VERIFIED_HEALTHY", resolved_health
    assert resolved_health["report"]["healthy"] is True
    assert len(resolved_health["report"]["checks"]) == 4
    assert resolved_health["incident"]["post_fix_health_report"]["overall_health"] == "VERIFIED_HEALTHY"

    rolled_health_res = client.post(f"/api/incidents/{rev_inc_id}/verify-health")
    assert rolled_health_res.status_code == 200, rolled_health_res.text
    rolled_health = rolled_health_res.json()
    assert rolled_health["status"] == "ROLLED_BACK_STABLE", rolled_health
    assert rolled_health["report"]["overall_health"] == "ROLLED_BACK_STABLE", rolled_health
    assert rolled_health["report"]["healthy"] is True
    assert len(rolled_health["report"]["checks"]) == 4

    missing_health_res = client.post("/api/incidents/nonexistent-inc-999/verify-health")
    assert missing_health_res.status_code == 404

    # 15f. Dashboard HTML markers for Irreversibility Gate, Snapshot Rollback & Live Health Watch UI
    ui_html = client.get("/").text
    assert "btnQuickRecreateScenario1" not in ui_html, "Duplicate header Recreate Fault icon should be removed"
    for marker in (
        "criticalGatePanel-",
        "evaluateClientChangeRisk",
        "renderRolledBackCard",
        "btnRollbackSnapshotCard",
        "rollbackIncident(",
        "liveHealthWatchModal",
        "openLiveHealthWatchModal",
        "updateLiveHealthWatchCard",
        "runPostFixHealthVerification",
        "health-blink-green",
        "health-blink-yellow",
        "Post-Fix Verification on Service Health",
        "platformFaqSection",
        "PLATFORM_FAQS",
        "togglePlatformFaq",
        "Gemini Cloud Assist",
        "7-Day Poison-Pill Quarantine",
        "Execution Honesty Invariant",
    ):
        assert marker in ui_html, f"Missing Phase 2/3/HealthWatch/FAQ UI marker `{marker}` in index.html"

    print(
        "[PASS] Colleague Feedback Safeguards & Live Health Watch verified: Support Ticket ERROR Cloud Logging persistence, "
        "Tier-2 Critical Irreversible HITL confirmation gate (0 JIT tokens on blind accept), "
        "pre-execution stable snapshot + 1-click 'Revert to Stable Snapshot', 45s Watchdog "
        "cross-service cascading failure auto-rollback + 7-Day Poison-Pill Quarantine, "
        "single Recreate Fault button inside Support Ticket modal, and blinking Live Health Watch post-fix verification!"
    )

    # 16. PostgreSQL Table Permission Denied (`audit_logs_test`), Prioritized Issue Picker (P1..P4) & Permanent Safe-to-Ignore Suppression
    import io as _io
    import json as _json
    import urllib.request as _urlreq
    import app as _app_module
    from providers.gcp.cloud_adapters import GCPDatabaseCloudAdapter
    from services.session_store_service import session_store_service as _sess_store

    class _FakeGcpEntry:
        def __init__(self, payload, resource_type: str, labels: dict, severity: str, insert_id: str, ts_iso: str):
            import datetime as _dt

            self.payload = payload
            self.resource = type("Res", (), {"type": resource_type, "labels": labels})()
            self.severity = severity
            self.insert_id = insert_id
            self.log_name = "projects/agent-triad/logs/cloudsql.googleapis.com%2Fpostgres.log"
            self.timestamp = _dt.datetime.fromisoformat(ts_iso)

    # 16a. Normalize exact user PostgreSQL permission denied log & external port probe false positive
    exact_pg_perm_msg = (
        "2026-11-18 07:39:41.915 UTC [2377783]: [1-1] "
        "db=postgres,user=sa-test-db-auth-obj-access@agent-triad.iam,host=[local] "
        "ERROR: permission denied for table audit_logs_test"
    )
    norm_pg_perm = _app_log_svc.adapter._normalize_gcp_entry(
        _FakeGcpEntry(
            payload=exact_pg_perm_msg,
            resource_type="cloudsql_database",
            labels={"database_id": "agent-triad:testdbinstance1", "region": "us-central1"},
            severity="ERROR",
            insert_id="test16-pg-perm-1",
            ts_iso="2026-11-18T07:39:41.915000+00:00",
        )
    )
    assert norm_pg_perm is not None
    assert norm_pg_perm["scenario_id"] == "cloudsql_pg_permission_denied", norm_pg_perm
    assert norm_pg_perm["error_code"] == "CLOUDSQL_PG_OBJECT_PERMISSION_DENIED", norm_pg_perm
    assert norm_pg_perm["metrics_snapshot"]["db_object_name"] == "audit_logs_test"
    assert norm_pg_perm["metrics_snapshot"]["db_user"] == "sa-test-db-auth-obj-access@agent-triad.iam"
    assert norm_pg_perm["metrics_snapshot"]["db_name"] == "postgres"
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.audit_logs_test" in norm_pg_perm["recommended_kubectl"]

    norm_probe = _app_log_svc.adapter._normalize_gcp_entry(
        _FakeGcpEntry(
            payload="2026-11-18 08:10:12.000 UTC [2379001]: [1-1] db=[unknown],user=[unknown],host=203.0.113.42 FATAL: unsupported frontend protocol 1234.5679: server supports 2.0 to 3.0",
            resource_type="cloudsql_database",
            labels={"database_id": "agent-triad:testdbinstance1", "region": "us-central1"},
            severity="ALERT",
            insert_id="test16-probe-1",
            ts_iso="2026-11-18T08:10:12+00:00",
        )
    )
    assert norm_probe is not None
    assert norm_probe["scenario_id"] == "cloudsql_conn_probe", norm_probe
    assert norm_probe["error_code"] == "CLOUDSQL_EXTERNAL_CONN_REJECTED", norm_probe
    assert norm_probe["signature_key"] == "cloudsql:agent-triad:testdbinstance1:EXTERNAL_CONN_PROBE"

    # Verify Database Agent DDL & privilege correlation (`DROP TABLE` + `CREATE TABLE` wiping PostgreSQL grants)
    sql_adapter = GCPDatabaseCloudAdapter(project_id="agent-triad", token_provider=lambda: "fake-token")
    orig_urlopen = _urlreq.urlopen

    class _FakeHttpResp:
        def __init__(self, body_dict: dict):
            self._raw = _io.BytesIO(_json.dumps(body_dict).encode("utf-8"))

        def read(self) -> bytes:
            return self._raw.read()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    try:
        _urlreq.urlopen = lambda req, timeout=12: _FakeHttpResp(
            {
                "entries": [
                    {
                        "timestamp": "2026-11-18T07:39:41.915000+00:00",
                        "severity": "ERROR",
                        "textPayload": exact_pg_perm_msg,
                    },
                    {
                        "timestamp": "2026-11-18T07:38:10.100000+00:00",
                        "severity": "INFO",
                        "textPayload": "2026-11-18 07:38:10.100 UTC [2377500]: [2-1] db=postgres,user=postgres,host=[local] LOG:  statement: CREATE TABLE public.audit_logs_test (id serial PRIMARY KEY, payload jsonb);",
                    },
                    {
                        "timestamp": "2026-11-18T07:38:09.900000+00:00",
                        "severity": "INFO",
                        "textPayload": "2026-11-18 07:38:09.900 UTC [2377500]: [1-1] db=postgres,user=postgres,host=[local] LOG:  statement: DROP TABLE IF EXISTS public.audit_logs_test;",
                    },
                ]
            }
        )
        ddl_corr = sql_adapter.inspect_table_ddl_and_privilege_logs(
            table_or_object="audit_logs_test",
            db_user="sa-test-db-auth-obj-access@agent-triad.iam",
            instance_name="testdbinstance1",
            account_or_project_id="agent-triad",
        )
    finally:
        _urlreq.urlopen = orig_urlopen

    assert ddl_corr["status"] == "LIVE_CLOUDSQL_DDL_ACL_CORRELATION", ddl_corr
    assert ddl_corr["ddl_recreation_detected"] is True, ddl_corr
    assert len(ddl_corr["ddl_events"]) == 2
    assert (
        ddl_corr["recommended_grant_sql"]
        == 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.audit_logs_test TO "sa-test-db-auth-obj-access@agent-triad.iam";'
    )
    assert "ALTER DEFAULT PRIVILEGES" in ddl_corr["recommended_default_privileges_sql"]

    # 16b & 16c. Prioritized Issue Picker (P1 first over newer P3/P4) + Permanent Safe-to-Ignore across Atlas & Firestore
    p1_id = "test16-p1-pg-perm-audit-logs"
    p3_id = "test16-p3-mon-api-warn"
    p4_id = "test16-p4-conn-probe-fp"
    p4_recur_id = "test16-p4-conn-probe-recurring"

    saved_local_logs = list(_app_log_svc._local_logs)
    saved_incidents = dict(_app_orch.incidents)
    saved_ignored_ids = dict(_app_module._ignored_log_ids)
    saved_ignored_sigs = dict(_app_module._ignored_signatures)
    saved_orch_ign_ids = set(_app_orch.ignored_log_ids)
    saved_orch_ign_sigs = set(_app_orch.ignored_signatures)
    saved_seen = set(_app_module._seen_anomaly_ids)
    orig_fetch_fn = _app_log_svc.fetch_recent_logs

    p1_entry = {
        **norm_pg_perm,
        "log_id": p1_id,
        "timestamp": "2026-11-18T07:39:41.915000+00:00",  # Older than P3 & P4!
    }
    p3_entry = {
        "log_id": p3_id,
        "timestamp": "2026-11-18T08:05:00+00:00",
        "severity": "WARNING",
        "source": "gcp-cloud-logging-live",
        "cluster": "gcp-project/agent-triad",
        "namespace": "us-central1",
        "workload": "gce-vm/demo-instance-1",
        "pod": "demo-instance-1",
        "error_code": "MonApiPermissionErr",
        "signature_key": "gce:demo-instance-1:MonApiPermissionErr",
        "scenario_id": "real_gcp_anomaly",
        "title": "VM Monitoring agent MonApiPermissionErr warning",
        "message": "MonApiPermissionErr: monitoring.timeSeries.create permission warning",
        "is_anomaly": True,
    }
    p4_entry = {
        **norm_probe,
        "log_id": p4_id,
        "timestamp": "2026-11-18T08:15:00+00:00",  # Newest timestamp, but P4 false positive!
    }
    p4_recurring_entry = {
        **norm_probe,
        "log_id": p4_recur_id,
        "timestamp": "2026-11-18T08:25:00+00:00",  # Brand-new log_id with the exact same P4 signature_key!
    }

    try:
        _app_orch.incidents.clear()
        _app_module._ignored_log_ids.clear()
        _app_module._ignored_signatures.clear()
        _app_module._sync_orchestrator_ignore_sets()
        _app_module._seen_anomaly_ids.clear()
        _app_log_svc._local_logs[:] = [p4_entry, p3_entry, p1_entry]
        _app_log_svc.fetch_recent_logs = lambda limit=25, poll_gcp=True, force=False: list(
            _app_log_svc._local_logs[:limit]
        )

        # Verify GET /api/state ranks P1 (`audit_logs_test`) FIRST ahead of newer P3 and P4
        st16 = client.get("/api/state").json()
        prio_queue = st16["prioritized_open_issues"]
        assert len(prio_queue) == 3, prio_queue
        assert [item["log_id"] for item in prio_queue] == [p1_id, p3_id, p4_id], prio_queue
        assert prio_queue[0]["priority_tier"] == "P1" and prio_queue[0]["priority_score"] == 95
        assert prio_queue[1]["priority_tier"] == "P3"
        assert prio_queue[2]["priority_tier"] == "P4" and prio_queue[2]["priority_score"] == 20

        # Escalate P4 false positive first (simulating when user saw the DB port access false positive)
        esc_p4 = client.post("/api/logs/fix-via-chat", json={"log_ids": [p4_id], "strategy": "auto"})
        assert esc_p4.status_code == 200, esc_p4.text

        # Poll Live Logs MUST pick P1 (`audit_logs_test`) FIRST even though P3 is newer!
        poll_p1 = client.post("/api/poll-cloud-logging", json={"strategy": "prioritized"})
        assert poll_p1.status_code == 200, poll_p1.text
        poll_p1_body = poll_p1.json()
        assert poll_p1_body["status"] == "REAL_GCP_INCIDENT_REPORTED_TO_ORCHESTRATOR", poll_p1_body
        assert poll_p1_body["priority"]["priority_tier"] == "P1"
        assert poll_p1_body["incident_id"] == p1_id
        assert poll_p1_body["log_entry"]["log_id"] == p1_id

        # Verify `/api/state["incidents"]` orders P1 incident ahead of P4 incident
        st_incs = client.get("/api/state").json()["incidents"]
        assert [i["incident_id"] for i in st_incs[:2]] == [p1_id, p4_id], [i["incident_id"] for i in st_incs]
        p1_inc = st_incs[0]
        assert p1_inc["specialist_worker"]["name"] == "Database Agent"
        assert p1_inc["agent_harness"]["rag_playbook"]["playbook_id"] == "PB-SQL-425"

        # Verify Incident Chat on `audit_logs_test` answers DDL/root-cause questions accurately with PostgreSQL GRANT
        chat_ddl = client.post(
            f"/api/incidents/{p1_id}/chat",
            json={
                "message": "Why did permission denied for table audit_logs_test happen? Do you see any DROP or CREATE TABLE DDL in the logs?",
                "user_name": "Hari",
            },
        )
        assert chat_ddl.status_code == 200, chat_ddl.text
        reply_ddl = chat_ddl.json()["reply"]
        assert "audit_logs_test" in reply_ddl
        assert "GRANT SELECT" in reply_ddl
        assert "sa-test-db-auth-obj-access@agent-triad.iam" in reply_ddl
        assert "testdbconnect" not in reply_ddl.lower()

        # Verify Direct Atlas Chat recognizes the exact pasted `audit_logs_test` log as PostgreSQL table ACL
        direct_pg = client.post(
            "/api/atlas/chat",
            json={
                "message": f'Please diagnose this Cloud SQL log: "{exact_pg_perm_msg}"',
                "user_name": "Hari",
            },
        )
        assert direct_pg.status_code == 200, direct_pg.text
        direct_reply = direct_pg.json()["reply"]
        assert "audit_logs_test" in direct_reply
        assert "GRANT" in direct_reply
        assert direct_pg.json()["specialist_worker"]["name"] == "Database Agent"

        # Click "Safe to Ignore" directly on the P4 incident card in Atlas (`POST /api/incidents/{p4_id}/ignore`)
        ign_p4 = client.post(
            f"/api/incidents/{p4_id}/ignore",
            json={"reason": "False positive external port scanner", "user_name": "Hari", "ignore_similar_signatures": True},
        )
        assert ign_p4.status_code == 200, ign_p4.text
        ign_p4_body = ign_p4.json()
        assert ign_p4_body["status"] == "INCIDENT_MARKED_SAFE_TO_IGNORE"
        assert ign_p4_body["next_incident_id"] == p1_id
        assert norm_probe["signature_key"] in ign_p4_body["ignored_signatures"]

        # Also mark P3 warning Safe to Ignore via `/api/logs/ignore` (`ignore_similar_signatures=True`)
        ign_p3 = client.post(
            "/api/logs/ignore",
            json={"log_ids": [p3_id], "reason": "Benign VM agent warning", "user_name": "Hari", "ignore_similar_signatures": True},
        )
        assert ign_p3.status_code == 200, ign_p3.text

        # Verify neither P4 nor P3 appears in `/api/state["incidents"]` or `prioritized_open_issues`
        st_after_ign = client.get("/api/state").json()
        assert [i["incident_id"] for i in st_after_ign["incidents"]] == [p1_id], st_after_ign["incidents"]
        assert [x["log_id"] for x in st_after_ign["prioritized_open_issues"]] == [p1_id], st_after_ign["prioritized_open_issues"]

        # Verify durable persistence in `session_store_service` (`__global_triage__` in Cloud Firestore) across restart!
        persisted_triage = _sess_store.get_global_triage_state(sync_from_firestore=True)
        assert p4_id in persisted_triage["ignored_logs"]
        assert norm_probe["signature_key"] in persisted_triage["ignored_signatures"]

        # Simulate container cold start: wipe in-memory ignore dicts and reload from Firestore
        _app_module._ignored_log_ids.clear()
        _app_module._ignored_signatures.clear()
        _app_module._load_persisted_triage_state(sync_from_firestore=True)
        assert p4_id in _app_module._ignored_log_ids
        assert norm_probe["signature_key"] in _app_module._ignored_signatures

        # Inject brand-new recurring P4 log (`p4_recur_id`) with same signature -> MUST stay suppressed & NEVER re-appear in Atlas!
        _app_orch.incidents.pop(p1_id, None)
        _app_log_svc._local_logs[:] = [p4_recurring_entry, p3_entry]
        st_recur = client.get("/api/state").json()
        assert st_recur["incidents"] == [], st_recur["incidents"]
        assert st_recur["prioritized_open_issues"] == [], st_recur["prioritized_open_issues"]
        recur_row = next(l for l in st_recur["logs"] if l["log_id"] == p4_recur_id)
        assert recur_row["ignored"] is True and recur_row["triage_status"] == "IGNORED"

        poll_after_ign = client.post("/api/poll-cloud-logging")
        assert poll_after_ign.status_code == 200
        assert poll_after_ign.json()["status"] == "NO_UNIGNORED_ANOMALIES", poll_after_ign.json()

        # 16d. Verify Dashboard UI markers for Prioritized Issue Picker & Permanent Safe-to-Ignore buttons
        ui_html_16 = client.get("/").text
        for marker16 in (
            "btnPickPrioritizedIssue",
            "pickTopPrioritizedIssue",
            "getPrioritizedOpenIssueQueue",
            "btnIgnoreIncidentMain",
            "ignoreIncidentPermanently",
            "cloudsql_pg_permission_denied",
            "cloudsql_conn_probe",
            "Sort: Priority (P1 First)",
        ):
            assert marker16 in ui_html_16, f"Missing Section 16 UI marker `{marker16}` in index.html"
    finally:
        _app_log_svc.fetch_recent_logs = orig_fetch_fn
        _app_log_svc._local_logs[:] = saved_local_logs
        _app_orch.incidents.clear()
        _app_orch.incidents.update(saved_incidents)
        _app_module._ignored_log_ids.clear()
        _app_module._ignored_log_ids.update(saved_ignored_ids)
        _app_module._ignored_signatures.clear()
        _app_module._ignored_signatures.update(saved_ignored_sigs)
        _app_orch.ignored_log_ids.clear()
        _app_orch.ignored_log_ids.update(saved_orch_ign_ids)
        _app_orch.ignored_signatures.clear()
        _app_orch.ignored_signatures.update(saved_orch_ign_sigs)
        _app_module._seen_anomaly_ids.clear()
        _app_module._seen_anomaly_ids.update(saved_seen)
        _app_module._persist_triage_state()

    print(
        "[PASS] PostgreSQL Table Permission Denied (`audit_logs_test` -> Database Agent PB-SQL-425 + DDL log correlation), "
        "Prioritized Issue Picker (P1 first over P3/P4), and Permanent 'Safe to Ignore' Firestore signature suppression verified!"
    )


if __name__ == "__main__":
    run_e2e_tests()




