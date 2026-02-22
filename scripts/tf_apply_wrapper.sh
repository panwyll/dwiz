#!/usr/bin/env bash
set -eo pipefail

ENVIRONMENT=${1:-${ENV:-}}
if [[ -z "${ENVIRONMENT}" ]]; then
  echo "❌ Error: Environment not specified"
  echo "Usage: tf_apply_wrapper.sh <dev|prod>"
  exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  Applying Terraform configuration for ${ENVIRONMENT} environment"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Run terraform apply and capture the exit code
set +e
terraform -chdir=terraform/envs/${ENVIRONMENT} apply -auto-approve
TERRAFORM_EXIT_CODE=$?
set -e

echo ""
echo "═══════════════════════════════════════════════════════════════════"

if [ $TERRAFORM_EXIT_CODE -eq 0 ]; then
  echo "✅ Terraform apply completed successfully"
  echo "═══════════════════════════════════════════════════════════════════"
  exit 0
else
  echo "⚠️  Terraform apply exited with code ${TERRAFORM_EXIT_CODE}"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "Common causes:"
  echo "  • Resources already exist (409 EntityAlreadyExists)"
  echo "    → This may be OK if infrastructure is already deployed"
  echo "    → Try running: terraform -chdir=terraform/envs/${ENVIRONMENT} import <resource>"
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
  exit $TERRAFORM_EXIT_CODE
fi