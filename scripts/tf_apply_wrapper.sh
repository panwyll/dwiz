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

# Check MWAA environment status to avoid operations during transitional states
echo "Checking MWAA environment status..."
MWAA_ENV_NAME="dwiz-mwaa-${ENVIRONMENT}"
MWAA_WAIT_ATTEMPTS=0
MWAA_MAX_WAIT_ATTEMPTS=5
MWAA_WAIT_DELAY=60

while [ "${MWAA_WAIT_ATTEMPTS}" -lt "${MWAA_MAX_WAIT_ATTEMPTS}" ]; do
  if ./scripts/check_mwaa_status.sh "${MWAA_ENV_NAME}" 2>/dev/null; then
    echo ""
    break
  else
    MWAA_STATUS_EXIT_CODE=$?
    if [ "${MWAA_STATUS_EXIT_CODE}" -eq 1 ]; then
      # MWAA is in transitional state
      MWAA_WAIT_ATTEMPTS=$((MWAA_WAIT_ATTEMPTS + 1))
      if [ "${MWAA_WAIT_ATTEMPTS}" -lt "${MWAA_MAX_WAIT_ATTEMPTS}" ]; then
        echo "⚠️  MWAA environment is in transitional state"
        echo "    Waiting ${MWAA_WAIT_DELAY} seconds before checking again (attempt ${MWAA_WAIT_ATTEMPTS}/${MWAA_MAX_WAIT_ATTEMPTS})..."
        sleep "${MWAA_WAIT_DELAY}"
      else
        echo "⚠️  MWAA environment is still in transitional state after ${MWAA_MAX_WAIT_ATTEMPTS} attempts"
        echo "    Proceeding with terraform, but operations may fail if MWAA state hasn't stabilized"
        echo ""
        break
      fi
    else
      # MWAA doesn't exist or is in a different state
      echo ""
      break
    fi
  fi
done

# Run terraform apply with retry logic for state lock issues
attempt=1
TERRAFORM_EXIT_CODE=1
TERRAFORM_OUTPUT_FILE=$(mktemp)

# Ensure temporary file is cleaned up on exit
trap 'rm -f "${TERRAFORM_OUTPUT_FILE}"' EXIT

while [ "${attempt}" -le "${MAX_RETRIES}" ] && [ "${TERRAFORM_EXIT_CODE}" -ne 0 ]; do
  # Run terraform apply and capture both output and exit code
  set +e
  terraform -chdir="terraform/envs/${ENVIRONMENT}" apply -auto-approve 2>&1 | tee "${TERRAFORM_OUTPUT_FILE}"
  TERRAFORM_EXIT_CODE=$?
  set -e

  # Check if error was due to specific retryable conditions
  if [ "${TERRAFORM_EXIT_CODE}" -ne 0 ]; then
    # Check for MWAA transitional state errors
    if grep -q "Environments with CREATING status must complete previous operation" "${TERRAFORM_OUTPUT_FILE}" || \
       grep -q "Environments with UPDATING status must complete previous operation" "${TERRAFORM_OUTPUT_FILE}" || \
       grep -q "Environments with DELETING status must complete previous operation" "${TERRAFORM_OUTPUT_FILE}"; then
      if [ "${attempt}" -lt "${MAX_RETRIES}" ]; then
        echo ""
        echo "⚠️  MWAA environment is in transitional state - will retry after environment stabilizes"
        # Use exponential backoff for MWAA operations as they can take several minutes
        MWAA_RETRY_DELAY=$((RETRY_DELAY * 2 * attempt))
        echo "    Retry attempt $((attempt + 1))/${MAX_RETRIES} after ${MWAA_RETRY_DELAY} seconds"
        sleep "${MWAA_RETRY_DELAY}"
        attempt=$((attempt + 1))
        continue
      fi
    fi

    # Check for resource already exists errors (should not auto-retry these)
    if grep -q "EntityAlreadyExists" "${TERRAFORM_OUTPUT_FILE}"; then
      echo ""
      echo "⚠️  Resource already exists - attempting to provide import guidance"
      echo ""
      
      # Try to extract resource information from error message
      if grep -q "Role with name.*already exists" "${TERRAFORM_OUTPUT_FILE}"; then
        # Use sed for portable extraction - IAM role names cannot contain spaces per AWS restrictions
        # Pattern matches: "Role with name <role-name> already exists"
        ROLE_NAME=$(grep "Role with name" "${TERRAFORM_OUTPUT_FILE}" | sed -n 's/.*Role with name \([^[:space:]]*\) already exists.*/\1/p' | head -1)
        if [[ -n "${ROLE_NAME}" ]]; then
          echo "📋 Detected IAM Role already exists: ${ROLE_NAME}"
          echo ""
          echo "To resolve this, import the existing role into Terraform state:"
          echo ""
          
          # Derive IAM module name from ENVIRONMENT variable
          IAM_MODULE_NAME="iam_${ENVIRONMENT}"
          echo "  terraform -chdir=terraform/envs/${ENVIRONMENT} import module.${IAM_MODULE_NAME}.aws_iam_role.github ${ROLE_NAME}"
          echo ""
          echo "Then retry the apply operation."
        fi
      fi
      break
    fi

    # Generic retry logic for other errors
    if [ "${attempt}" -lt "${MAX_RETRIES}" ]; then
      echo ""
      echo "⚠️  Terraform apply failed (exit code: ${TERRAFORM_EXIT_CODE})"
      echo "Checking if this is a retryable issue..."
      echo "    Retry attempt $((attempt + 1))/${MAX_RETRIES} after ${RETRY_DELAY} seconds"
      sleep "${RETRY_DELAY}"
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
  echo "  • MWAA Environment in transitional state (CREATING, UPDATING, DELETING)"
  echo "    → The script automatically waits and retries for MWAA state changes"
  echo "    → MWAA operations can take 20-45 minutes to complete"
  echo "    → Wait for the environment to reach AVAILABLE or failed state"
  echo "    → Check status: aws mwaa get-environment --name <env-name> --query 'Environment.Status'"
  echo "    → NOTE: If destroying infrastructure, wait for MWAA deletion to complete before recreating"
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