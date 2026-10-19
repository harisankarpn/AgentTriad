output "database_agent_url" {
  description = "Base HTTPS URL of the deployed ADK Database Specialist Agent on Cloud Run"
  value       = google_cloud_run_v2_service.database_agent.uri
}

output "agent_card_url" {
  description = "A2A 1.0 AgentCard discovery endpoint (/.well-known/agent.json)"
  value       = "${google_cloud_run_v2_service.database_agent.uri}/.well-known/agent.json"
}

output "diagnose_endpoint" {
  description = "Direct HTTP POST endpoint to invoke ADK Database Agent diagnosis"
  value       = "${google_cloud_run_v2_service.database_agent.uri}/diagnose"
}

output "a2a_endpoint" {
  description = "JSON-RPC 2.0 A2A endpoint for Atlas Lead Orchestrator"
  value       = "${google_cloud_run_v2_service.database_agent.uri}/a2a"
}

output "service_account_email" {
  description = "Dedicated Zero-Standing Privilege Service Account for the ADK Database Agent"
  value       = google_service_account.database_agent_sa.email
}

output "aaas_command_center_url" {
  description = "Live Cloud Run AaaS Command Center Dashboard URL (Atlas connected to Database Agent)"
  value       = "https://agent-triad-control-plane-${data.google_project.current.number}.${var.region}.run.app"
}

