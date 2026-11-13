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
        "userProfileBadge",
        "googleSsoModal",
        "googleSsoForm",
        "btnNewChatSession",
        "btnToggleSessionHistory",
        "btnClearAllSessions",
        "atlasSessionHistoryPanel",
    ):
        assert nav_id in res_ui.text, f"Missing sidebar/view/theme/SSO/session element {nav_id} in Dashboard UI"
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
    print("[PASS] Dashboard UI verified: Official Google Visual Identity 4-Color Palette, Google SSO Sign-In Modal, Auto/Dark/Light Theme Switcher, and 7 Specialists present")

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


if __name__ == "__main__":
    run_e2e_tests()




