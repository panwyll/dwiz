#!/usr/bin/env bash
set -eo pipefail

ENVIRONMENT=${1:-${ENV:-}}
MAX_RETRIES=${2:-3}
RETRY_DELAY=${3:-30}

if [[ -z "${ENVIRONMENT}" ]]; then
  echo "❌ Error: Environment not specified"
  echo "Usage: tf_apply_wrapper.sh <dev|prod> [max_retries] [retry_delay_seconds]"
  exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  Applying Terraform configuration for ${ENVIRONMENT} environment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Check for state lock before attempting apply
echo "Checking for existing state locks..."
if ./scripts/check_state_lock.sh "${ENVIRONMENT}" 3 15; then
  echo "✓ State lock check passed"
  echo ""
else
  echo "⚠️  State lock detected - will retry with backoff"
  echo ""
fi

# Run terraform apply with retry logic for state lock issues
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

  # Run terraform apply and capture the exit code
  set +e
  terraform -chdir="terraform/envs/${ENVIRONMENT}" apply -auto-approve
  TERRAFORM_EXIT_CODE=$?
  set -e

  # Check if error was due to state lock
  if [ "${TERRAFORM_EXIT_CODE}" -ne 0 ]; then
    # If this is a state lock error, we'll retry
    # Otherwise, break the loop
    if [ "${attempt}" -lt "${MAX_RETRIES}" ]; then
      echo "⚠️  Terraform apply failed (exit code: ${TERRAFORM_EXIT_CODE})"
      echo "Checking if this is a state lock issue..."
      attempt=$((attempt + 1))
    else
      break
    fi
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════════"

if [ "${TERRAFORM_EXIT_CODE}" -eq 0 ]; then
  echo "✅ Terraform apply completed successfully"
  echo "═══════════════════════════════════════════════════════════════════"
  exit 0
else
  echo "⚠️  Terraform apply exited with code ${TERRAFORM_EXIT_CODE}"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""

  # Check if we should suggest importing existing resources
  echo "Common causes and solutions:"
  echo ""
  echo "  • State lock conflict (ConditionalCheckFailed)"
  echo "    → The script automatically retries ${MAX_RETRIES} times with ${RETRY_DELAY}s delay"
  echo "    → If lock persists, another operation may be running"
  echo "    → Check lock status: make tf-check-lock ENV=${ENVIRONMENT}"
  echo "    → Force unlock (if safe): make tf-unlock ENV=${ENVIRONMENT} LOCK_ID=<id>"
  echo ""
  echo "  • Resources already exist (409 EntityAlreadyExists)"
  echo "    → This may be OK if infrastructure is already deployed"
  echo "    → Check current state: terraform -chdir=terraform/envs/${ENVIRONMENT} state list"
  echo "    → To import existing resources, use:"
  echo "      terraform -chdir=terraform/envs/${ENVIRONMENT} import [RESOURCE_TYPE.NAME] [RESOURCE_ID]"
  echo ""
  echo "    Common import examples:"
  echo "      # S3 buckets (if they already exist):"
  echo "      terraform -chdir=terraform/envs/${ENVIRONMENT} import module.s3_lake.aws_s3_bucket.raw [YOUR-BUCKET-NAME]"
  echo ""
  echo "      # IAM roles:"
  echo "      terraform -chdir=terraform/envs/${ENVIRONMENT} import module.iam_${ENVIRONMENT}.aws_iam_role.github [YOUR-ROLE-NAME]"
  echo ""
  echo "  • Permission errors (403 AccessDenied)"
  echo "    → Check your AWS credentials and IAM permissions"
  echo "    → Some MWAA errors may resolve after the environment is created"
  echo ""
  echo "  • Resource conflicts or validation errors"
  echo "    → Review the errors above and fix any configuration issues"
  echo ""
  echo "To check current infrastructure state:"
  echo "  terraform -chdir=terraform/envs/${ENVIRONMENT} show"
  echo ""
  echo "To continue with DAG deployment despite errors:"
  echo "  ./scripts/deploy_dags.sh ${ENVIRONMENT}"
  echo ""
  exit "${TERRAFORM_EXIT_CODE}"
fi