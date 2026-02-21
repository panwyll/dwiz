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
# Using sed for better cross-platform compatibility
BUCKET=$(sed -n 's/^[[:space:]]*bucket[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
TABLE=$(sed -n 's/^[[:space:]]*dynamodb_table[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
REGION=$(sed -n 's/^[[:space:]]*region[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
REGION=${REGION:-us-east-1}

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
bucket_exists=false
bucket_check_error=""
if aws s3api head-bucket --bucket "${BUCKET}" --region "${REGION}" 2>/dev/null; then
  bucket_exists=true
else
  # head-bucket returns non-zero for both 404 (not exists) and 403 (forbidden)
  # Try to list objects to distinguish between the two
  if ls_output=$(aws s3 ls "s3://${BUCKET}" --region "${REGION}" 2>&1); then
    bucket_exists=true
  else
    # Check if it's an access denied error
    if echo "${ls_output}" | grep -q "AccessDenied\|Forbidden"; then
      bucket_check_error="access_denied"
    fi
  fi
fi

if ${bucket_exists}; then
  echo "✓ S3 bucket exists: ${BUCKET}"
elif [[ "${bucket_check_error}" == "access_denied" ]]; then
  echo "Error: S3 bucket '${BUCKET}' exists but you don't have access to it."
  echo "Please ensure you have the necessary permissions or use a different bucket name."
  exit 1
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
  
  echo "Enabling default encryption on bucket: ${BUCKET}"
  aws s3api put-bucket-encryption --bucket "${BUCKET}" --region "${REGION}" \
    --server-side-encryption-configuration '{
      "Rules": [{
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        },
        "BucketKeyEnabled": true
      }]
    }'
  
  echo "Blocking public access on bucket: ${BUCKET}"
  aws s3api put-public-access-block --bucket "${BUCKET}" --region "${REGION}" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  
  echo "✓ Created S3 bucket: ${BUCKET}"
fi

# Check if DynamoDB table exists
if aws dynamodb describe-table --table-name "${TABLE}" --region "${REGION}" &>/dev/null; then
  echo "✓ DynamoDB table exists: ${TABLE}"
else
  echo "Creating DynamoDB table: ${TABLE}"
  # Note: SSEType=KMS uses AWS-managed key (alias/aws/dynamodb) by default
  # For customer-managed keys, add: --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-id>
  aws dynamodb create-table \
    --table-name "${TABLE}" \
    --region "${REGION}" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --sse-specification Enabled=true,SSEType=KMS \
    --no-cli-pager \
    > /dev/null
  
  echo "Waiting for DynamoDB table to be ready..."
  aws dynamodb wait table-exists --table-name "${TABLE}" --region "${REGION}"
  
  echo "✓ Created DynamoDB table: ${TABLE}"
fi

echo ""
echo "✓ Backend resources ready for Terraform"
