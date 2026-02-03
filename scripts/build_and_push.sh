#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG=${IMAGE_TAG:-latest}
ACCOUNT_ID=${ACCOUNT_ID:-}
REGION=${REGION:-us-east-1}

if [[ -z "${ACCOUNT_ID}" ]]; then
  echo "ACCOUNT_ID is required"
  exit 1
fi

ECR_REPO="genie-jobs"
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPO}" --region "${REGION}"

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

docker build -t "${ECR_REPO}:${IMAGE_TAG}" jobs

docker tag "${ECR_REPO}:${IMAGE_TAG}" "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

docker push "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"
