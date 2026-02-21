# Data Platform Wizard v1

Data Platform Wizard provides a minimal, Terraform-first AWS data platform with Airflow (MWAA), S3 data lake, optional ECS jobs, and streaming ingest via Kinesis Firehose. This repository ships with example DAGs and a CLI to manage deployments.

## Prerequisites

- AWS account with permissions to create IAM roles, VPC, S3, MWAA, ECS, CloudWatch, and Kinesis Firehose resources.
- Terraform >= 1.5
- Python 3.11
- AWS CLI (for local credentials) and Docker (for building job images)

## Install

```bash
make install
```

This installs the `wizard` CLI so you can run `wizard <command>` from anywhere in the repo.

## Bootstrap remote state

Create the S3 bucket and DynamoDB table for Terraform state with a single command (one-time):

```bash
wizard bootstrap --bucket YOUR_ORG-wizard-tf-state --table YOUR_ORG-wizard-tf-lock
```

Then update `terraform/envs/dev/backend.tf` and `terraform/envs/prod/backend.tf` with the printed values.

## GitHub Actions OIDC roles

The `terraform/modules/iam` module creates two roles. Provide `account_id` in env vars or `terraform.tfvars`.

- `github-deploy-dev` trusts `refs/heads/main`
- `github-deploy-prod` trusts `refs/tags/v*`

The trust policy is scoped to this repo and specific ref. Policies are scoped to environment resources via tags.

## Deploy dev

```bash
wizard init
wizard up dev
wizard deploy dev
```

## Promote to prod

```bash
wizard up prod
wizard deploy prod
```

For GitHub Actions, push a tag `v*` to run the prod workflow.

## Adding pipelines

- `dags/templates/stream_compaction.py` and `dags/templates/batch_api_ingest.py` show recommended structure.
- Add sources in `pipelines/sources` and streams in `pipelines/streams`.
- Use `wizard new-source <name>` and `wizard add-stream <name>` to scaffold files.

All DAGs must set `owner`, `tags`, `schedule_interval`, `catchup`, and `max_active_runs`.

## Secrets Management

Secure storage of API keys, database credentials, and other secrets via AWS Secrets Manager:

- Automatically provisioned KMS keys and secret storage per environment
- Python library at `libs/python_common/secrets.py` for easy retrieval
- See `docs/SECRETS_MANAGEMENT.md` for complete usage guide

```python
from libs.python_common.secrets import get_secret_value

api_key = get_secret_value("wizard-dev/api-keys", "external_api")
```

## Monitoring

The platform includes a comprehensive CloudWatch dashboard for usage and billing monitoring:

- **Usage Metrics**: MWAA task/DAG execution, ECS resource utilization, Kinesis Firehose throughput, S3 storage
- **Billing Metrics**: Estimated AWS charges by service for cost optimization
- **Error Analysis**: Log insights for error trends and failed task identification
- Automatically deployed per environment (dev/prod)
- Access URL provided as Terraform output: `terraform -chdir=terraform/envs/dev output dashboard_url`

See `docs/MONITORING_DASHBOARD.md` for complete usage guide and customization options.

Additionally:
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
