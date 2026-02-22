#!/usr/bin/env bash
set -euo pipefail

# This script forces an unlock of a Terraform state lock.
# Use this when a previous Terraform operation was interrupted and left a stale lock.

ENVIRONMENT=${1:-${ENV:-}}
LOCK_ID=${2:-}

if [[ -z "${ENVIRONMENT}" ]]; then
  echo "Usage: tf_force_unlock.sh <dev|prod|test> [lock_id]"
  echo ""
  echo "Examples:"
  echo "  tf_force_unlock.sh dev bbfc73fb-7f79-0d42-2239-0f2ba22ec62d"
  echo "  ENV=dev make tf-unlock LOCK_ID=bbfc73fb-7f79-0d42-2239-0f2ba22ec62d"
  echo ""
  echo "If lock_id is not provided, you will be prompted to enter it."
  exit 1
fi

BACKEND_FILE="terraform/envs/${ENVIRONMENT}/backend.tf"

if [[ ! -f "${BACKEND_FILE}" ]]; then
  echo "Error: Backend configuration not found at ${BACKEND_FILE}"
  exit 1
fi

# Extract region from backend.tf
REGION=$(sed -n 's/^[[:space:]]*region[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${BACKEND_FILE}" | head -1)
REGION=${REGION:-us-east-1}

echo "═══════════════════════════════════════════════════════════════════"
echo "  Terraform State Force Unlock - ${ENVIRONMENT} environment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "⚠️  WARNING: Only use this if you are sure no Terraform operations"
echo "   are currently running. Force unlocking while another process is"
echo "   running can lead to state corruption!"
echo ""

# If LOCK_ID is not provided, prompt for it or try to get it from error output
if [[ -z "${LOCK_ID}" ]]; then
  echo "To find the Lock ID, look at the error message from 'make tf-plan' or 'make tf-apply'."
  echo "The Lock ID is shown in the error output, for example:"
  echo "  Lock Info:"
  echo "    ID:        bbfc73fb-7f79-0d42-2239-0f2ba22ec62d"
  echo ""
  read -p "Enter Lock ID: " LOCK_ID
  
  if [[ -z "${LOCK_ID}" ]]; then
    echo "Error: Lock ID is required"
    exit 1
  fi
fi

echo "Lock ID: ${LOCK_ID}"
echo "Region: ${REGION}"
echo ""

# Confirm before unlocking
read -p "Are you sure you want to force unlock? (yes/no): " CONFIRM

if [[ "${CONFIRM}" != "yes" ]]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "Force unlocking Terraform state..."

# Run terraform force-unlock
terraform -chdir=terraform/envs/${ENVIRONMENT} force-unlock -force "${LOCK_ID}"

UNLOCK_EXIT_CODE=$?

echo ""
echo "═══════════════════════════════════════════════════════════════════"

if [ $UNLOCK_EXIT_CODE -eq 0 ]; then
  echo "✅ Successfully unlocked Terraform state"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "You can now run:"
  echo "  make tf-plan ENV=${ENVIRONMENT}"
  echo "  make tf-apply ENV=${ENVIRONMENT}"
  exit 0
else
  echo "❌ Failed to unlock Terraform state (exit code: ${UNLOCK_EXIT_CODE})"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "If the unlock failed, the lock may have already been released."
  echo "Try running 'make tf-plan ENV=${ENVIRONMENT}' to verify."
  exit $UNLOCK_EXIT_CODE
fi
