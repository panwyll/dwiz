#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-${ENV:-}}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: deploy_dags.sh <dev|prod>"
  exit 1
fi

DAGS_BUCKET=$(terraform -chdir=terraform/envs/${ENVIRONMENT} output -raw dags_bucket)
aws s3 sync dags "s3://${DAGS_BUCKET}/dags" --delete
