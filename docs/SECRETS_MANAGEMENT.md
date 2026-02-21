# Secrets Management

This document describes how to securely manage secrets (API keys, database credentials, etc.) in the Data Platform Genie.

## Overview

The platform uses **AWS Secrets Manager** for secure storage and retrieval of secrets. This provides:

- **Encryption at rest** using AWS KMS with automatic key rotation
- **Fine-grained access control** via IAM policies
- **Audit logging** through CloudTrail
- **Automatic secret rotation** (optional)
- **Versioning** for secret values

## Architecture

### Components

1. **AWS Secrets Manager**: Stores encrypted secrets
2. **AWS KMS**: Encrypts/decrypts secrets with customer-managed keys
3. **IAM Policies**: Grant MWAA execution role access to secrets
4. **Python Library**: `libs/python_common/secrets.py` provides simple API for retrieving secrets

### Secret Naming Convention

Secrets are organized by environment with the following pattern:

```
<project>-<environment>/<category>
```

Examples:
- `genie-dev/api-keys` - API keys for external services (dev)
- `genie-dev/database` - Database credentials (dev)
- `genie-dev/streaming` - Streaming service credentials (dev)
- `genie-prod/api-keys` - API keys for external services (prod)

## Usage in DAGs

### Basic Usage

```python
from libs.python_common.secrets import get_secret, get_secret_value

# Get a single value from a secret
api_key = get_secret_value("genie-dev/api-keys", "github_token")

# Get entire secret as dictionary
api_keys = get_secret("genie-dev/api-keys")
github_token = api_keys["github_token"]
slack_webhook = api_keys["slack_webhook"]
```

### Example DAG

```python
from datetime import datetime
from airflow import DAG
from airflow.operators.python import PythonOperator
from libs.python_common.secrets import get_secret_value

def fetch_data():
    # Retrieve API key securely
    api_key = get_secret_value("genie-dev/api-keys", "external_api")
    
    # Use api_key to authenticate
    # response = requests.get(url, headers={"Authorization": f"Bearer {api_key}"})
    pass

with DAG(
    dag_id="secure_api_ingest",
    start_date=datetime(2024, 1, 1),
    schedule_interval="@daily",
) as dag:
    fetch = PythonOperator(task_id="fetch", python_callable=fetch_data)
```

## Managing Secrets

### Creating/Updating Secrets via AWS CLI

```bash
# Create or update a secret with JSON value
aws secretsmanager put-secret-value \
  --secret-id genie-dev/api-keys \
  --secret-string '{"github_token":"ghp_xxx","slack_webhook":"https://hooks.slack.com/xxx"}'

# Create or update database credentials
aws secretsmanager put-secret-value \
  --secret-id genie-dev/database \
  --secret-string '{"host":"db.example.com","username":"app_user","password":"xxx"}'

# Create or update streaming credentials
aws secretsmanager put-secret-value \
  --secret-id genie-dev/streaming \
  --secret-string '{"api_key":"xxx","endpoint":"https://stream.example.com"}'
```

### Creating/Updating Secrets via AWS Console

1. Navigate to AWS Secrets Manager in the AWS Console
2. Click "Store a new secret"
3. Select "Other type of secret"
4. Enter key-value pairs:
   - Key: `github_token`, Value: `ghp_xxx`
   - Key: `slack_webhook`, Value: `https://hooks.slack.com/xxx`
5. Choose the KMS key: `alias/<project>-<env>-secrets`
6. Name the secret: `<project>-<env>/api-keys`
7. Click "Store"

### Retrieving Secrets for Local Development

```bash
# View secret value
aws secretsmanager get-secret-value \
  --secret-id genie-dev/api-keys \
  --query SecretString \
  --output text | jq .

# Get specific key from secret
aws secretsmanager get-secret-value \
  --secret-id genie-dev/api-keys \
  --query SecretString \
  --output text | jq -r '.github_token'
```

## Security Best Practices

### DO

✅ **Store all sensitive data in AWS Secrets Manager**
- API keys, tokens, passwords, certificates

✅ **Use descriptive key names**
- `github_token` not `key1`

✅ **Rotate secrets regularly**
- Configure automatic rotation when possible
- Update secrets manually at least quarterly

✅ **Use environment-specific secrets**
- Separate dev and prod secrets completely

✅ **Minimize secret scope**
- Create separate secrets for different services
- Don't store all credentials in one secret

✅ **Monitor secret access**
- Enable CloudTrail logging
- Review access logs periodically

### DON'T

❌ **Never commit secrets to source control**
- Not in code, comments, or configuration files
- Use `.gitignore` to exclude credential files

❌ **Never log secret values**
- Don't print or log API keys, passwords, tokens
- Redact sensitive data in error messages

❌ **Never hardcode secrets**
- Always retrieve from Secrets Manager at runtime

❌ **Don't share secrets across environments**
- Dev and prod should have completely separate secrets

❌ **Don't use overly broad IAM permissions**
- Grant access only to specific secrets needed

## Terraform Configuration

The secrets infrastructure is automatically provisioned by Terraform:

### Modules

- `terraform/modules/secrets_manager/` - Creates KMS keys and secret placeholders
- `terraform/modules/mwaa/` - Grants MWAA permissions to access secrets

### Deployed Resources

For each environment (dev/prod):

1. **KMS Key**: `<project>-<env>-secrets-key`
   - Customer-managed key with automatic rotation
   - Used to encrypt all secrets

2. **Secret Placeholders**:
   - `<project>-<env>/api-keys` - API keys
   - `<project>-<env>/database` - Database credentials
   - `<project>-<env>/streaming` - Streaming service credentials

3. **IAM Permissions**: MWAA execution role can:
   - `secretsmanager:GetSecretValue` on all environment secrets
   - `secretsmanager:DescribeSecret` on all environment secrets
   - `kms:Decrypt` using the environment KMS key

## Caching

The secrets library caches retrieved secrets in memory for the lifetime of the Python process. This:

- Reduces API calls to AWS Secrets Manager
- Improves DAG performance
- Reduces AWS costs

To clear the cache (mainly for testing):

```python
from libs.python_common.secrets import clear_cache

clear_cache()
```

## Troubleshooting

### Error: "Secret not found"

**Cause**: The secret doesn't exist in AWS Secrets Manager.

**Solution**: Create the secret using AWS CLI or Console (see "Managing Secrets" above).

### Error: "Access denied to secret"

**Cause**: MWAA execution role lacks permission to read the secret.

**Solution**: 
1. Verify the secret name matches the pattern: `<project>-<env>/*`
2. Check that Terraform has been applied to grant permissions
3. Review IAM role policies in AWS Console

### Error: "Key not found in secret"

**Cause**: The requested key doesn't exist in the secret's JSON.

**Solution**: 
1. Check the secret value: `aws secretsmanager get-secret-value --secret-id <name>`
2. Verify the key name matches exactly (case-sensitive)
3. Update the secret to include the missing key

### Secrets not updating in DAG

**Cause**: Secrets are cached in memory.

**Solution**: 
- Restart the Airflow worker (secrets will be refreshed on next run)
- Or wait for the next DAG execution (new process = new cache)

## Examples

### Multiple Secrets in One DAG

```python
def process_data():
    # Get different types of credentials
    db_host = get_secret_value("genie-dev/database", "host")
    db_user = get_secret_value("genie-dev/database", "username")
    db_pass = get_secret_value("genie-dev/database", "password")
    
    api_key = get_secret_value("genie-dev/api-keys", "external_api")
    
    # Use credentials...
```

### Conditional Secrets by Environment

```python
import os

def get_env_secret(secret_category: str, key: str) -> str:
    """Get secret based on current environment."""
    # Environment is typically set via MWAA environment variables
    env = os.getenv("ENVIRONMENT", "dev")
    secret_name = f"genie-{env}/{secret_category}"
    return get_secret_value(secret_name, key)

# Usage
api_key = get_env_secret("api-keys", "github_token")
```

## Cost Considerations

AWS Secrets Manager pricing (as of 2024):
- $0.40 per secret per month
- $0.05 per 10,000 API calls

With caching enabled, a DAG running hourly makes ~24 API calls/month per secret.

Estimated monthly cost for 10 secrets with hourly access:
- Storage: 10 secrets × $0.40 = $4.00
- API calls: 10 secrets × 24 calls × 30 days × $0.05/10,000 = $0.36
- **Total: ~$4.36/month**

## Migration Guide

If you have existing secrets in environment variables or configuration files:

1. **Inventory your secrets**: List all API keys, passwords, tokens currently in use
2. **Create secrets in AWS Secrets Manager**: Use AWS CLI or Console
3. **Update DAG code**: Replace hardcoded values with `get_secret_value()` calls
4. **Test in dev**: Verify DAGs work with Secrets Manager
5. **Deploy to prod**: Roll out changes to production
6. **Remove old secrets**: Delete from environment variables/config files

Example migration:

```python
# Before
API_KEY = "hardcoded_key_12345"  # Bad!

# After
from libs.python_common.secrets import get_secret_value
api_key = get_secret_value("genie-dev/api-keys", "external_api")  # Good!
```
