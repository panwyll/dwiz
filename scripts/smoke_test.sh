#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: smoke_test.sh <dev|prod>"
  exit 1
fi

DAGS_BUCKET=$(terraform -chdir=terraform/envs/${ENVIRONMENT} output -raw dags_bucket)
aws s3 ls "s3://${DAGS_BUCKET}/dags" >/dev/null
python scripts/validate_dags.py
