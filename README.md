# Data Platform Genie v1

Data Platform Genie provides a minimal, Terraform-first AWS data platform with Airflow (MWAA), S3 data lake, optional ECS jobs, and streaming ingest via Kinesis Firehose. This repository ships with example DAGs and a CLI to manage deployments.

## Prerequisites

- AWS account with permissions to create IAM roles, VPC, S3, MWAA, ECS, CloudWatch, and Kinesis Firehose resources.
- Terraform >= 1.6
- Python 3.11
- AWS CLI (for local credentials) and Docker (for building job images)

## Bootstrap remote state

Create an S3 bucket and DynamoDB table for state locking (one-time). Example:

```bash
aws s3 mb s3://<org>-genie-tf-state
aws dynamodb create-table \
  --table-name <org>-genie-tf-lock \
  --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH
```

Update `terraform/envs/dev/backend.tf` and `terraform/envs/prod/backend.tf` with your bucket and table names.

## GitHub Actions OIDC roles

The `terraform/modules/iam` module creates two roles. Provide `account_id` in env vars or `terraform.tfvars`.

- `github-deploy-dev` trusts `refs/heads/main`
- `github-deploy-prod` trusts `refs/tags/v*`

The trust policy is scoped to this repo and specific ref. Policies are scoped to environment resources via tags.

## Deploy dev

```bash
./cli/genie.py init
./cli/genie.py up dev
./cli/genie.py deploy dev
```

## Promote to prod

```bash
./cli/genie.py up prod
./cli/genie.py deploy prod
```

For GitHub Actions, push a tag `v*` to run the prod workflow.

## Adding pipelines

- `dags/templates/stream_compaction.py` and `dags/templates/batch_api_ingest.py` show recommended structure.
- Add sources in `pipelines/sources` and streams in `pipelines/streams`.
- Use `./cli/genie.py new-source <name>` and `./cli/genie.py add-stream <name>` to scaffold files.

All DAGs must set `owner`, `tags`, `schedule_interval`, `catchup`, and `max_active_runs`.

## Monitoring

- MWAA logs and metrics are sent to CloudWatch.
- DAGs should use `libs/python_common/metrics.py` for task-level metrics and `logging.getLogger` for structured logs.

## Minimal runbook

- Check MWAA health in AWS Console if DAGs are not scheduling.
- Use `scripts/smoke_test.sh` to confirm the environment is reachable and DAGs can be parsed.
- Review CloudWatch Logs for task failures.

## Development

```bash
make lint
make test
make dag-validate
```
