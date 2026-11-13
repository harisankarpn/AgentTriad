# AgentTriad (AaaS) Portable Kubernetes Helm Chart

One-click deployment for the complete **AgentTriad** stack (`control-plane`, `db-agent`, `infra-agent`, optional in-cluster `postgres` + `redis`) across **AWS EKS**, **Azure AKS**, **Google GKE**, and **Red Hat OpenShift**.

> GCP Cloud Run users can continue using the original `terraform/main.tf` deployment without changes.

---

## Quick Start (One-Click Install Examples)

### 1. AWS EKS (IRSA + Bedrock Claude + ALB Ingress)
```bash
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set global.cloudProvider=aws \
  --set global.awsRegion=us-east-1 \
  --set serviceAccount.eksRoleArn=arn:aws:iam::123456789012:role/agent-triad-irsa \
  --set llm.provider=bedrock \
  --set llm.model=anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --set ingress.enabled=true \
  --set ingress.className=alb \
  --set ingress.hosts[0].host=agent-triad.aws.example.com
```

### 2. Azure AKS (Workload Identity + Azure OpenAI + NGINX/AGIC Ingress)
```bash
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set global.cloudProvider=azure \
  --set global.azureSubscriptionId=<subscription-id> \
  --set global.azureResourceGroup=<resource-group> \
  --set serviceAccount.aksClientId=<managed-identity-client-id> \
  --set llm.provider=azure_openai \
  --set llm.azureOpenaiEndpoint=https://<resource>.openai.azure.com \
  --set llm.azureOpenaiDeployment=gpt-4o \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=agent-triad.azure.example.com
```

### 3. Google GKE (Workload Identity + Vertex AI Gemini + GCE Ingress)
```bash
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set global.cloudProvider=gcp \
  --set global.gcpProjectId=<gcp-project-id> \
  --set serviceAccount.gkeServiceAccount=aaas-orchestrator@<gcp-project-id>.iam.gserviceaccount.com \
  --set llm.provider=vertex \
  --set llm.model=gemini-2.5-flash \
  --set llm.googleGenaiUseVertexai=TRUE \
  --set ingress.enabled=true \
  --set ingress.className=gce \
  --set ingress.hosts[0].host=agent-triad.gcp.example.com
```

### 4. Red Hat OpenShift (`restricted-v2` SCC + TLS Route)
```bash
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set openshift.enabled=true \
  --set postgres.enabled=false \
  --set postgres.externalDsn="postgresql://aaas:<password>@<managed-or-operator-pg>:5432/agent_triad" \
  --set llm.provider=litellm \
  --set llm.model=openai/gpt-4o-mini \
  --set llm.apiKey=<api-key>
```
> Setting `--set openshift.enabled=true` automatically omits fixed `runAsUser`/`runAsGroup`/`fsGroup` values for OpenShift `restricted-v2` SCC compliance and creates an edge-terminated `route.openshift.io/v1` `Route`. For PostgreSQL on OpenShift, use your managed PostgreSQL / Crunchy Postgres / CloudNativePG operator DSN via `postgres.externalDsn` (or `existingSecret`).

---

## Production Managed Databases & External Secrets

Disable in-cluster PostgreSQL/Redis and point to managed services (AWS RDS + ElastiCache, Azure PostgreSQL + Redis, Cloud SQL + Memorystore) or an External Secrets Operator `Secret`:

```bash
helm upgrade --install agent-triad ./deploy/helm/agent-triad \
  --namespace agent-triad --create-namespace \
  --set postgres.enabled=false \
  --set redis.enabled=false \
  --set existingSecret=agent-triad-prod-secrets \
  --set controlPlane.autoscaling.enabled=true \
  --set networkPolicy.enabled=true
```
