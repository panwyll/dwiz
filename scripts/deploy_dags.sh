#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-${ENV:-}}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: deploy_dags.sh <dev|prod>"
  exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Deploying DAGs to ${ENVIRONMENT} environment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Get the S3 bucket name from Terraform output
if ! DAGS_BUCKET=$(terraform -chdir=terraform/envs/${ENVIRONMENT} output -raw dags_bucket 2>&1); then
  echo "═══════════════════════════════════════════════════════════════════"
  echo "❌ DAG deployment failed"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "   Error: Failed to get DAGs bucket from Terraform output"
  echo "   Make sure Terraform has been successfully applied for: ${ENVIRONMENT}"
  echo ""
  echo "   To apply Terraform configuration:"
  echo "     make tf-apply ENV=${ENVIRONMENT}"
  echo "   Or:"
  echo "     dwiz up ${ENVIRONMENT}"
  echo ""
  exit 1
fi

echo "   Target bucket: ${DAGS_BUCKET}"
echo ""

# Sync DAGs to S3
if aws s3 sync dags "s3://${DAGS_BUCKET}/dags" --delete; then
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  echo "✅ DAG deployment completed successfully"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "   Environment: ${ENVIRONMENT}"
  echo "   Bucket: s3://${DAGS_BUCKET}/dags"
  echo ""
  exit 0
else
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  echo "❌ DAG deployment failed"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "   Error: Failed to sync DAGs to S3 bucket: ${DAGS_BUCKET}"
  echo "   Check your AWS credentials and permissions"
  echo ""
  exit 1
fi
