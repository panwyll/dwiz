# Quick Start: Secrets Management

This guide will help you get started with secure secrets management in just a few minutes.

## Step 1: Deploy Infrastructure

After deploying your environment (dev or prod), the secrets infrastructure is automatically created:

```bash
genie up dev
```

This creates:
- KMS key for encryption
- Secret placeholders for API keys, database credentials, and streaming config

## Step 2: Add Your First Secret

Use AWS CLI to store a secret:

```bash
# Store API keys
aws secretsmanager put-secret-value \
  --secret-id genie-dev/api-keys \
  --secret-string '{"github_token":"ghp_xxxxx","slack_webhook":"https://hooks.slack.com/xxxxx"}'
```

Or use the AWS Console:
1. Go to AWS Secrets Manager
2. Find secret: `genie-dev/api-keys`
3. Click "Retrieve secret value" → "Edit"
4. Add key-value pairs
5. Save

## Step 3: Use Secrets in Your DAG

```python
from airflow import DAG
from airflow.operators.python import PythonOperator
from libs.python_common.secrets import get_secret_value

def my_task():
    # Retrieve secret securely
    api_key = get_secret_value("genie-dev/api-keys", "github_token")
    
    # Use the API key
    # headers = {"Authorization": f"token {api_key}"}
    # response = requests.get(url, headers=headers)
    pass

with DAG(dag_id="my_dag", ...) as dag:
    task = PythonOperator(task_id="task", python_callable=my_task)
```

## Step 4: Test Locally

Verify you can retrieve secrets (requires AWS credentials):

```python
from libs.python_common.secrets import get_secret

# Test retrieval
secret = get_secret("genie-dev/api-keys")
print(secret.keys())  # Shows available keys
```

## Common Secrets to Store

### API Keys
```json
{
  "github_token": "ghp_xxxxx",
  "slack_webhook": "https://hooks.slack.com/xxxxx",
  "external_api_key": "xxxxx"
}
```

### Database Credentials
```json
{
  "host": "db.example.com",
  "port": "5432",
  "database": "analytics",
  "username": "app_user",
  "password": "xxxxx"
}
```

### Streaming Credentials
```json
{
  "api_key": "xxxxx",
  "endpoint": "https://stream.example.com",
  "consumer_group": "airflow-group"
}
```

## Next Steps

- Read the full guide: [docs/SECRETS_MANAGEMENT.md](./SECRETS_MANAGEMENT.md)
- Set up secret rotation (optional)
- Enable CloudTrail logging for audit trail

## Troubleshooting

**Can't retrieve secret in DAG?**
- Verify secret name matches exactly (case-sensitive)
- Check secret exists: `aws secretsmanager get-secret-value --secret-id <name>`
- Ensure Terraform has been applied

**Access denied error?**
- Run `genie up dev` to update IAM permissions
- Verify secret name follows pattern: `genie-<env>/*`

For more help, see the full [Secrets Management Guide](./SECRETS_MANAGEMENT.md).
