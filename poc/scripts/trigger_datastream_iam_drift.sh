#!/usr/bin/env bash
# Reproducible Live GCP Fault Trigger — Scenario 1 (Datastream Private Connectivity IAM Drift)
#
# Executes 100% REAL Google Cloud actions in project `agent-triad` (`1041190629307`) at $0 ongoing cost:
#   1. Strips IAM bindings from the real Datastream Service Agent
#      `service-1041190629307@gcp-sa-datastream.iam.gserviceaccount.com`
#      (generating a real `SetIamPolicy` REMOVE Cloud Audit Log simulating Terraform state drift).
#   2. Waits for IAM cache propagation.
#   3. Attempts a real `gcloud datastream private-connections create` in `europe-west2` on `repro-vpc`.
#      Google Cloud Datastream rejects it pre-flight with:
#        generic::FAILED_PRECONDITION: Missing permissions to validate that the provided IP range
#        is available. Please check that Datastream SA has the required permissions.
#      and records the real ERROR entry in Cloud Logging (`cloudaudit.googleapis.com/activity`).
#
# Usage:
#   ./poc/scripts/trigger_datastream_iam_drift.sh [--no-wait]

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-agent-triad}"
PROJECT_NUMBER="${GCP_PROJECT_NUMBER:-1041190629307}"
REGION="${DATASTREAM_REGION:-europe-west2}"
VPC_NAME="${DATASTREAM_VPC:-repro-vpc}"
SUBNET_CIDR="${DATASTREAM_SUBNET:-10.200.0.40/29}"
DS_SA="service-${PROJECT_NUMBER}@gcp-sa-datastream.iam.gserviceaccount.com"
CONN_ID="ds-priv-conn-cloudsql-$(date +%H%M%S)"
WAIT_SECONDS=75

if [[ "${1:-}" == "--no-wait" ]]; then
  WAIT_SECONDS=5
fi

echo "=================================================================="
echo " AgentTriad Live GCP Fault Trigger — Datastream IAM State Drift"
echo " Project : ${PROJECT_ID} (${PROJECT_NUMBER})"
echo " Region  : ${REGION} | VPC: ${VPC_NAME} | CIDR: ${SUBNET_CIDR}"
echo " SA      : ${DS_SA}"
echo "=================================================================="

echo "[1/4] Checking current IAM bindings for ${DS_SA}..."
CURRENT_ROLES="$(gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${DS_SA}" \
  --format="value(bindings.role)" || true)"

if [[ -n "${CURRENT_ROLES}" ]]; then
  while IFS= read -r role; do
    [[ -z "${role}" ]] && continue
    echo "  -> Removing role ${role} (simulating Terraform state drift, writing SetIamPolicy audit log)..."
    gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${DS_SA}" \
      --role="${role}" \
      --condition=None --quiet >/dev/null
  done <<< "${CURRENT_ROLES}"
  echo "[2/4] Waiting ${WAIT_SECONDS}s for GCP IAM policy revocation to propagate..."
  sleep "${WAIT_SECONDS}"
else
  echo "  -> ${DS_SA} already has 0 IAM roles on ${PROJECT_ID}."
  echo "[2/4] Skipping propagation wait (IAM already stripped)."
fi

echo "[3/4] Triggering real Datastream private-connections create (${CONN_ID})..."
set +e
ERR_OUT="$(gcloud datastream private-connections create "${CONN_ID}" \
  --location="${REGION}" \
  --display-name="Private Connectivity to Cloud SQL (${REGION})" \
  --vpc="projects/${PROJECT_ID}/global/networks/${VPC_NAME}" \
  --subnet="${SUBNET_CIDR}" \
  --project="${PROJECT_ID}" 2>&1)"
RC=$?
set -e
echo "${ERR_OUT}"

if [[ ${RC} -eq 0 ]]; then
  echo "WARNING: IAM cache had not finished revoking; cleaning up ${CONN_ID} and retrying in 30s..."
  gcloud datastream private-connections delete "${CONN_ID}" \
    --location="${REGION}" --project="${PROJECT_ID}" --force --quiet >/dev/null 2>&1 || true
  sleep 30
  CONN_ID="${CONN_ID}-r"
  gcloud datastream private-connections create "${CONN_ID}" \
    --location="${REGION}" \
    --display-name="Private Connectivity to Cloud SQL (${REGION})" \
    --vpc="projects/${PROJECT_ID}/global/networks/${VPC_NAME}" \
    --subnet="${SUBNET_CIDR}" \
    --project="${PROJECT_ID}" 2>&1 || true
fi

echo "[4/4] Verifying real ERROR Cloud Audit Log landed in Cloud Logging..."
sleep 4
gcloud logging read 'protoPayload.serviceName="datastream.googleapis.com" AND severity>=ERROR' \
  --project="${PROJECT_ID}" \
  --limit=1 \
  --format="table(timestamp,severity,protoPayload.methodName,protoPayload.status.message)"

echo ""
echo "Done! Click 'Poll Live Logs' in AgentTriad Command Center to watch Atlas run Phases 1-4."
