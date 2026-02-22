#!/usr/bin/env bash
set -eo pipefail

# Check if MWAA environment exists and its status
# Usage: check_mwaa_status.sh <environment-name>

ENVIRONMENT_NAME=${1:-}

if [[ -z "${ENVIRONMENT_NAME}" ]]; then
  echo "❌ Error: Environment name not specified"
  echo "Usage: check_mwaa_status.sh <environment-name>"
  exit 1
fi

echo "Checking MWAA environment status: ${ENVIRONMENT_NAME}"

# Check if environment exists
set +e
MWAA_STATUS=$(aws mwaa get-environment --name "${ENVIRONMENT_NAME}" --query 'Environment.Status' --output text 2>/dev/null)
MWAA_CHECK_EXIT_CODE=$?
set -e

if [ "${MWAA_CHECK_EXIT_CODE}" -ne 0 ]; then
  echo "✓ MWAA environment does not exist or is not accessible"
  exit 0
fi

echo "MWAA environment status: ${MWAA_STATUS}"

# Check if environment is in a transitional state
case "${MWAA_STATUS}" in
  CREATING|UPDATING|DELETING)
    echo "⚠️  MWAA environment is in transitional state: ${MWAA_STATUS}"
    echo "    Operations on this environment will fail until it reaches a stable state"
    echo "    This can take 20-45 minutes"
    exit 1
    ;;
  AVAILABLE)
    echo "✓ MWAA environment is in stable state: ${MWAA_STATUS}"
    exit 0
    ;;
  CREATE_FAILED|UPDATE_FAILED|DELETE_FAILED)
    echo "⚠️  MWAA environment is in failed state: ${MWAA_STATUS}"
    echo "    Manual intervention may be required"
    exit 2
    ;;
  *)
    echo "⚠️  MWAA environment is in unknown state: ${MWAA_STATUS}"
    exit 3
    ;;
esac
