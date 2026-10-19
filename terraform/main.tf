locals {
  container_image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.artifact_repo}/${var.service_name}:${var.image_tag}"

  # Strictly Read-Only + Vertex AI Reasoning IAM roles (Zero-Standing Privilege)
  database_agent_roles = toset([
    "roles/cloudsql.viewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer",
    "roles/aiplatform.user",
  ])
}

# ---------------------------------------------------------------------------
# 1. Enable Required GCP APIs (Non-destructive: disable_on_destroy = false)
# ---------------------------------------------------------------------------
resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "aiplatform.googleapis.com",
    "logging.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------
# 2. Dedicated Least-Privilege Service Account for the ADK Database Agent
# ---------------------------------------------------------------------------
resource "google_service_account" "database_agent_sa" {
  account_id   = "aaas-database-agent-sa"
  display_name = "AaaS ADK Database Specialist Agent (Zero-Standing Privilege)"
  description  = "Read-only Cloud SQL diagnostic identity + Vertex AI Gemini reasoning for the ADK Database Agent."
  project      = var.project_id

  depends_on = [google_project_service.required_apis]
}

resource "google_project_iam_member" "database_agent_readonly_roles" {
  for_each = local.database_agent_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.database_agent_sa.email}"
}

# ---------------------------------------------------------------------------
# 3. 1-Click Container Build & Push via Cloud Build (Triggered by source hash)
# ---------------------------------------------------------------------------
resource "terraform_data" "build_database_agent_image" {
  count = var.auto_build_image ? 1 : 0

  triggers_replace = [
    filesha256("${path.module}/../agents/database_agent/agent.py"),
    filesha256("${path.module}/../agents/database_agent/server.py"),
    filesha256("${path.module}/../agents/database_agent/requirements.txt"),
    filesha256("${path.module}/../agents/database_agent/Dockerfile"),
  ]

  provisioner "local-exec" {
    command = "gcloud builds submit ${path.module}/../agents/database_agent --tag ${local.container_image} --project=${var.project_id}"
  }

  depends_on = [google_project_service.required_apis]
}

# ---------------------------------------------------------------------------
# 4. Cloud Run v2 Service: ADK Database Specialist Agent (Scale-to-Zero)
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "database_agent" {
  name     = var.service_name
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.database_agent_sa.email

    # Scale-to-Zero ($0 idle cost) + FinOps ceiling (max 3 instances)
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = local.container_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle = true
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_REGION"
        value = var.region
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }
      env {
        name  = "ADK_MODEL"
        value = var.adk_model
      }
      env {
        name  = "AGENT_SOURCE_HASH"
        value = filesha256("${path.module}/../agents/database_agent/agent.py")
      }
    }
  }

  depends_on = [
    google_project_iam_member.database_agent_readonly_roles,
    terraform_data.build_database_agent_image,
  ]
}

data "google_project" "current" {
  project_id = var.project_id
}

# Allow Zero-Trust A2A invocation from Atlas Control Plane Service Account
# (Complies with GCP Organization Policy `iam.allowedPolicyMemberDomains` which blocks `allUsers`)
resource "google_cloud_run_v2_service_iam_member" "control_plane_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.database_agent.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${data.google_project.current.number}-compute@developer.gserviceaccount.com"
}

# ---------------------------------------------------------------------------
# 5. Wire Atlas Control Plane (`agent-triad-control-plane`) to Live DB Agent
# ---------------------------------------------------------------------------
resource "terraform_data" "sync_control_plane_with_db_agent" {
  count = var.auto_build_image ? 1 : 0

  triggers_replace = [
    google_cloud_run_v2_service.database_agent.uri,
    filesha256("${path.module}/../poc/agents/lead_orchestrator.py"),
    filesha256("${path.module}/../poc/services/cloud_logging_service.py"),
    filesha256("${path.module}/../poc/static/index.html"),
    filesha256("${path.module}/../poc/app.py"),
  ]

  provisioner "local-exec" {
    command = <<-EOT
      gcloud builds submit ${path.module}/../poc \
        --tag ${var.region}-docker.pkg.dev/${var.project_id}/${var.artifact_repo}/agent-triad-poc:latest \
        --project=${var.project_id} && \
      gcloud run deploy agent-triad-control-plane \
        --image=${var.region}-docker.pkg.dev/${var.project_id}/${var.artifact_repo}/agent-triad-poc:latest \
        --region=${var.region} \
        --project=${var.project_id} \
        --set-env-vars="GCP_PROJECT_ID=${var.project_id},GCP_LOCATION=${var.region},DATABASE_AGENT_URL=${google_cloud_run_v2_service.database_agent.uri}" \
        --quiet
    EOT
  }

  depends_on = [
    google_cloud_run_v2_service.database_agent,
    google_cloud_run_v2_service_iam_member.control_plane_invoker,
  ]
}

