#!/usr/bin/env bash
set -euo pipefail

# This script checks for existing Terraform state locks and waits/retries if locked
# It provides a safer alternative to force-unlock by waiting for locks to clear

ENVIRONMENT=${1:-${ENV:-}}
MAX_RETRIES=${2:-5}
RETRY_DELAY=${3:-30}

if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: check_state_lock.sh <dev|prod|test> [max_retries] [retry_delay_seconds]"
  exit 1
fi

BACKEND_FILE="terraform/envs/${ENVIRONMENT}/backend.tf"

if [[ ! -f "${BACKEND_FILE}" ]]; then
  echo "Error: Backend configuration not found at ${BACKEND_FILE}"
  exit 1
fi

# Extract configuration from backend.tf
BUCKET=$(sed -n 's/^[[:space:]]*bucket[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
TABLE=$(sed -n 's/^[[:space:]]*dynamodb_table[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
KEY=$(sed -n 's/^[[:space:]]*key[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
REGION=$(sed -n 's/^[[:space:]]*region[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
REGION=${REGION:-us-east-1}

if [[ -z "${BUCKET}" ]] || [[ -z "${TABLE}" ]] || [[ -z "${KEY}" ]]; then
  echo "Error: Could not extract backend configuration from ${BACKEND_FILE}"
  exit 1
fi

# Construct the lock ID used by Terraform
# Terraform uses: md5(bucket/key)
LOCK_KEY="${BUCKET}/${KEY}"

echo "Checking Terraform state lock status..."
echo "  Bucket: ${BUCKET}"
echo "  Key: ${KEY}"
echo "  Table: ${TABLE}"
echo "  Region: ${REGION}"
echo ""

# Function to check if lock exists
check_lock() {
  # Query DynamoDB for lock entry
  local lock_info
  if lock_info=$(aws dynamodb get-item \
    --table-name "${TABLE}" \
    --key "{\"LockID\": {\"S\": \"${LOCK_KEY}\"}}" \
    --region "${REGION}" \
    --output json 2>/dev/null); then

    if echo "${lock_info}" | grep -q '"Item"'; then
      # Lock exists, extract info if possible
      echo "${lock_info}"
      return 0
    else
      # No lock found
      return 1
    fi
  else
    # Error querying DynamoDB (might not exist yet)
    return 1
  fi
}

# Check for lock with retries
attempt=1
while [ ${attempt} -le ${MAX_RETRIES} ]; do
  echo "Attempt ${attempt}/${MAX_RETRIES}: Checking for state lock..."

  if lock_info=$(check_lock); then
    echo ""
    echo "⚠️  State lock detected:"
    echo "${lock_info}" | grep -E '"(ID|Who|Created|Operation)"' | sed 's/^/  /' || echo "  (Unable to parse lock details)"
    echo ""

    if [ ${attempt} -lt ${MAX_RETRIES} ]; then
      echo "Waiting ${RETRY_DELAY} seconds before retry..."
      sleep ${RETRY_DELAY}
      attempt=$((attempt + 1))
    else
      echo "❌ State lock still present after ${MAX_RETRIES} attempts"
      echo ""
      echo "This likely means:"
      echo "  1. Another Terraform operation is currently running"
      echo "  2. A previous operation was interrupted and left a stale lock"
      echo ""
      echo "To resolve:"
      echo "  • Wait for the other operation to complete"
      echo "  • If you're sure no operations are running, force unlock with:"
      echo "    make tf-unlock ENV=${ENVIRONMENT} LOCK_ID=<lock-id-from-error>"
      echo ""
      exit 1
    fi
  else
    echo "✓ No state lock found - safe to proceed"
    exit 0
  fi
done

echo "❌ Failed to acquire state lock after ${MAX_RETRIES} attempts"
exit 1
