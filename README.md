# Data Platform Genie v1

Data Platform Genie provides a minimal, Terraform-first AWS data platform with Airflow (MWAA), S3 data lake, optional ECS jobs, and streaming ingest via Kinesis Firehose. This repository ships with example DAGs and a CLI to manage deployments.

## Prerequisites

- AWS account with permissions to create IAM roles, VPC, S3, MWAA, ECS, CloudWatch, and Kinesis Firehose resources.
- Terraform >= 1.6
- Python 3.11
- AWS CLI (for local credentials) and Docker (for building job images)

## Install

```bash
make install
```

This installs the `genie` CLI so you can run `genie <command>` from anywhere in the repo.

## Bootstrap remote state

Create the S3 bucket and DynamoDB table for Terraform state with a single command (one-time):

```bash
genie bootstrap --bucket YOUR_ORG-genie-tf-state --table YOUR_ORG-genie-tf-lock
```

Then update `terraform/envs/dev/backend.tf` and `terraform/envs/prod/backend.tf` with the printed values.

## GitHub Actions OIDC roles

The `terraform/modules/iam` module creates two roles. Provide `account_id` in env vars or `terraform.tfvars`.

- `github-deploy-dev` trusts `refs/heads/main`
- `github-deploy-prod` trusts `refs/tags/v*`

The trust policy is scoped to this repo and specific ref. Policies are scoped to environment resources via tags.

## Deploy dev

```bash
genie init
genie up dev
genie deploy dev
```

## Promote to prod

```bash
genie up prod
genie deploy prod
```

For GitHub Actions, push a tag `v*` to run the prod workflow.

## Adding pipelines

- `dags/templates/stream_compaction.py` and `dags/templates/batch_api_ingest.py` show recommended structure.
- Add sources in `pipelines/sources` and streams in `pipelines/streams`.
- Use `genie new-source <name>` and `genie add-stream <name>` to scaffold files.

All DAGs must set `owner`, `tags`, `schedule_interval`, `catchup`, and `max_active_runs`.

## Secrets Management

Secure storage of API keys, database credentials, and other secrets via AWS Secrets Manager:

- Automatically provisioned KMS keys and secret storage per environment
- Python library at `libs/python_common/secrets.py` for easy retrieval
- See `docs/SECRETS_MANAGEMENT.md` for complete usage guide

```python
from libs.python_common.secrets import get_secret_value

api_key = get_secret_value("genie-dev/api-keys", "external_api")
```

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
