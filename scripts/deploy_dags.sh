#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-${ENV:-}}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: deploy_dags.sh <dev|prod>"
  exit 1
fi

echo "🚀 Deploying DAGs to ${ENVIRONMENT} environment..."

# Get the S3 bucket name from Terraform output
if ! DAGS_BUCKET=$(terraform -chdir=terraform/envs/${ENVIRONMENT} output -raw dags_bucket 2>&1); then
  echo "❌ Error: Failed to get DAGs bucket from Terraform output"
  echo "   Make sure Terraform has been initialized and applied for environment: ${ENVIRONMENT}"
  echo "   Error details: ${DAGS_BUCKET}"
  exit 1
fi

echo "📦 Target bucket: ${DAGS_BUCKET}"

# Sync DAGs to S3
if aws s3 sync dags "s3://${DAGS_BUCKET}/dags" --delete; then
  echo "✅ Successfully deployed DAGs to ${ENVIRONMENT} environment"
  echo "   Bucket: s3://${DAGS_BUCKET}/dags"
  exit 0
else
  echo "❌ Error: Failed to sync DAGs to S3 bucket: ${DAGS_BUCKET}"
  echo "   Check your AWS credentials and permissions"
  exit 1
fi
