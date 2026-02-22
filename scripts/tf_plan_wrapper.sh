#!/usr/bin/env bash
set -eo pipefail

ENVIRONMENT=${1:-${ENV:-}}
MAX_RETRIES=${2:-3}
RETRY_DELAY=${3:-10}

if [[ -z "${ENVIRONMENT}" ]]; then
  echo "❌ Error: Environment not specified"
  echo "Usage: tf_plan_wrapper.sh <dev|prod|test> [max_retries] [retry_delay_seconds]"
  exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  Running Terraform plan for ${ENVIRONMENT} environment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Check for state lock before attempting plan
echo "Checking for existing state locks..."
if ./scripts/check_state_lock.sh "${ENVIRONMENT}" 3 15; then
  echo "✓ State lock check passed"
  echo ""
else
  echo "⚠️  State lock detected - this may cause plan to fail"
  echo ""
fi

# Run terraform plan with retry logic for transient network errors
attempt=1
TERRAFORM_EXIT_CODE=1

while [ "${attempt}" -le "${MAX_RETRIES}" ] && [ "${TERRAFORM_EXIT_CODE}" -ne 0 ]; do
  if [ "${attempt}" -gt 1 ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  Retry attempt ${attempt}/${MAX_RETRIES} after ${RETRY_DELAY} seconds"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    sleep "${RETRY_DELAY}"
  fi

  # Run terraform plan and capture the exit code
  set +e
  terraform -chdir="terraform/envs/${ENVIRONMENT}" plan
  TERRAFORM_EXIT_CODE=$?
  set -e

  # Check if error was transient (network, state lock, etc.)
  if [ "${TERRAFORM_EXIT_CODE}" -ne 0 ]; then
    if [ "${attempt}" -lt "${MAX_RETRIES}" ]; then
      echo "⚠️  Terraform plan failed (exit code: ${TERRAFORM_EXIT_CODE})"
      echo "This may be due to transient network or state lock issues. Retrying..."
      attempt=$((attempt + 1))
      # Exponential backoff
      RETRY_DELAY=$((RETRY_DELAY * 2))
    else
      break
    fi
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════════"

if [ $TERRAFORM_EXIT_CODE -eq 0 ]; then
  echo "✅ Terraform plan completed successfully"
  echo "═══════════════════════════════════════════════════════════════════"
  exit 0
else
  echo "❌ Terraform plan failed after ${attempt} attempts"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "Common causes and solutions:"
  echo ""
  echo "  • Network errors (DNS resolution, connection timeouts)"
  echo "    → This script automatically retries ${MAX_RETRIES} times with exponential backoff"
  echo "    → If the error persists, check your network connectivity"
  echo "    → Ensure you can reach AWS endpoints: aws sts get-caller-identity"
  echo ""
  echo "  • State lock conflict (ConditionalCheckFailed)"
  echo "    → Another Terraform operation may be running"
  echo "    → Check lock status: make tf-check-lock ENV=${ENVIRONMENT}"
  echo "    → Force unlock (if safe): make tf-unlock ENV=${ENVIRONMENT} LOCK_ID=<id>"
  echo ""
  echo "  • Configuration errors"
  echo "    → Review the error messages above"
  echo "    → Check syntax: terraform fmt -check -recursive"
  echo "    → Validate config: terraform -chdir=terraform/envs/${ENVIRONMENT} validate"
  echo ""
  echo "  • Permission errors (403 AccessDenied)"
  echo "    → Check your AWS credentials: aws sts get-caller-identity"
  echo "    → Verify IAM permissions for your user/role"
  echo ""
  exit $TERRAFORM_EXIT_CODE
fi
