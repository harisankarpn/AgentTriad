variable "project_id" {
  description = "Target Google Cloud Project ID"
  type        = string
  default     = "agent-triad"
}

variable "region" {
  description = "Primary GCP region for Cloud Run and Artifact Registry"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name for the ADK Database Specialist Agent"
  type        = string
  default     = "agent-triad-db-agent"
}

variable "artifact_repo" {
  description = "Existing Artifact Registry repository name in us-central1"
  type        = string
  default     = "agent-triad-repo"
}

variable "image_tag" {
  description = "Container image tag for the ADK Database Agent"
  type        = string
  default     = "latest"
}

variable "adk_model" {
  description = "Vertex AI Gemini model used by the ADK Database Agent for read-only DBA reasoning"
  type        = string
  default     = "gemini-2.5-flash"
}

variable "auto_build_image" {
  description = "Whether Terraform should automatically build & push the ADK Database Agent container image via Cloud Build before deploying Cloud Run"
  type        = bool
  default     = true
}
