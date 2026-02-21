#!/usr/bin/env bash
set -euo pipefail

# This script ensures the Terraform S3 backend and DynamoDB lock table exist
# before running terraform init. It extracts configuration from backend.tf
# and creates resources if they don't exist.

ENVIRONMENT=${1:-${ENV:-}}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: ensure_backend.sh <dev|prod>"
  exit 1
fi

BACKEND_FILE="terraform/envs/${ENVIRONMENT}/backend.tf"

if [[ ! -f "${BACKEND_FILE}" ]]; then
  echo "Error: Backend configuration not found at ${BACKEND_FILE}"
  exit 1
fi

# Extract bucket, table, and region from backend.tf
BUCKET=$(grep -oP 'bucket\s*=\s*"\K[^"]+' "${BACKEND_FILE}" || echo "")
TABLE=$(grep -oP 'dynamodb_table\s*=\s*"\K[^"]+' "${BACKEND_FILE}" || echo "")
REGION=$(grep -oP 'region\s*=\s*"\K[^"]+' "${BACKEND_FILE}" || echo "us-east-1")

if [[ -z "${BUCKET}" ]]; then
  echo "Error: Could not extract bucket name from ${BACKEND_FILE}"
  exit 1
fi

if [[ -z "${TABLE}" ]]; then
  echo "Error: Could not extract DynamoDB table name from ${BACKEND_FILE}"
  exit 1
fi

echo "Checking Terraform backend resources..."
echo "  Bucket: ${BUCKET}"
echo "  Table: ${TABLE}"
echo "  Region: ${REGION}"
echo ""

# Check if bucket exists
if aws s3api head-bucket --bucket "${BUCKET}" --region "${REGION}" 2>/dev/null; then
  echo "✓ S3 bucket exists: ${BUCKET}"
else
  echo "Creating S3 bucket: ${BUCKET}"
  if [[ "${REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}"
  else
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}" \
      --create-bucket-configuration LocationConstraint="${REGION}"
  fi
  
  echo "Enabling versioning on bucket: ${BUCKET}"
  aws s3api put-bucket-versioning --bucket "${BUCKET}" --region "${REGION}" \
    --versioning-configuration Status=Enabled
  
  echo "✓ Created S3 bucket: ${BUCKET}"
fi

# Check if DynamoDB table exists
if aws dynamodb describe-table --table-name "${TABLE}" --region "${REGION}" &>/dev/null; then
  echo "✓ DynamoDB table exists: ${TABLE}"
else
  echo "Creating DynamoDB table: ${TABLE}"
  aws dynamodb create-table \
    --table-name "${TABLE}" \
    --region "${REGION}" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --no-cli-pager \
    > /dev/null
  
  echo "✓ Created DynamoDB table: ${TABLE}"
fi

echo ""
echo "✓ Backend resources ready for Terraform"
