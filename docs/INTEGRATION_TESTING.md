# Integration Testing

The project includes an automated integration test workflow that deploys and tears down infrastructure in AWS to validate the complete deployment flow.

## Overview

The integration test workflow (`.github/workflows/integration-test.yml`):

1. **Deploys** a complete test environment using Terraform
2. **Verifies** the infrastructure was created successfully
3. **Tests** DAG deployment to the MWAA environment
4. **Tears down** all resources automatically

This validates:
- Terraform initialization and backend configuration
- Infrastructure deployment with real AWS resources
- The fix for the "Releasing state lock" hanging issue
- Complete end-to-end deployment flow

## Running Integration Tests

### Via GitHub Actions (Recommended)

Integration tests run automatically on:
- Pull requests that modify infrastructure code (`terraform/**`, `cli/dwiz.py`, etc.)
- Manual trigger via "Run workflow" button in GitHub Actions UI

### Locally

You can run integration tests locally if you have AWS credentials configured:

```bash
# Set up test environment
export AWS_PROFILE=your-profile  # or configure AWS credentials

# Initialize and apply
make tf-init ENV=test
make tf-apply ENV=test

# Verify deployment
terraform -chdir=terraform/envs/test output

# Deploy DAGs
./scripts/deploy_dags.sh test

# Clean up
make tf-destroy ENV=test
```

## AWS Configuration

### Required IAM Permissions

The integration test requires an IAM role with permissions to create:

- **Network**: VPC, Subnets, Security Groups, Route Tables
- **Storage**: S3 Buckets
- **Compute**: MWAA Environments, ECS Clusters
- **Identity**: IAM Roles and Policies
- **Monitoring**: CloudWatch Log Groups and Dashboards
- **Secrets**: AWS Secrets Manager secrets and KMS keys
- **Streaming**: Kinesis Firehose delivery streams

### GitHub Secrets Setup

To enable integration tests in CI:

1. Create an IAM role for GitHub Actions OIDC:
   ```bash
   # Use the existing IAM module
   dwiz up test
   ```

2. Add the role ARN to GitHub secrets:
   - Go to repository Settings → Secrets and variables → Actions
   - Create secret: `AWS_ROLE_TEST`
   - Value: `arn:aws:iam::YOUR_ACCOUNT:role/github-deploy-test`

3. Configure S3 backend:
   - Update `terraform/envs/test/backend.tf` with your bucket/table names
   - Or run `dwiz bootstrap` to create backend resources

## Test Environment

The test environment (`terraform/envs/test/`):

- Uses a separate VPC CIDR: `10.20.0.0/16` (vs dev: `10.10.0.0/16`)
- Resource naming: `dwiz-*-test` (vs dev: `dwiz-*-dev`)
- Shorter log retention: 7 days (vs dev: 14 days)
- Separate Terraform state: `test/terraform.tfstate`

This isolation ensures tests don't interfere with dev/prod environments.

## Cost Optimization

Integration tests incur AWS costs. To minimize costs:

1. **Automatic cleanup**: The workflow destroys all resources after testing
2. **Minimal retention**: Log retention is only 7 days for test environment
3. **Manual trigger**: Tests don't run on every commit, only on infrastructure changes
4. **Quick validation**: Tests focus on deployment validation, not long-running operations

Estimated cost per test run: ~$5-10 (mostly MWAA environment creation)

## Troubleshooting

### Test Skipped

If you see "⚠️ Skipped: AWS credentials not configured":
- The `AWS_ROLE_TEST` secret is not configured
- Add the secret as described in "GitHub Secrets Setup" above

### Deployment Failed

If deployment fails:
1. Check the GitHub Actions logs for specific error messages
2. Look for permission errors (403) - the IAM role may need additional permissions
3. Check for resource conflicts - resources may exist from a previous failed run

### Cleanup Failed

If cleanup fails with "Some resources may need manual cleanup":
1. Go to AWS Console
2. Search for resources tagged with `Environment: test`
3. Manually delete remaining resources (most common: MWAA environment takes 20-30 minutes to delete)
4. Check S3 buckets for any remaining data

### State Lock Issues

If you see "Error acquiring state lock":
- A previous test run may have left the lock acquired
- Go to DynamoDB → `org-dwiz-tf-lock` table
- Delete the lock entry for `test/terraform.tfstate`
- Re-run the test

## Best Practices

1. **Review changes**: Always review Terraform plan output before merging
2. **Monitor costs**: Check AWS Cost Explorer after test runs
3. **Update IAM**: Keep IAM permissions in sync with infrastructure changes
4. **Parallel tests**: Avoid running multiple integration tests simultaneously (state lock conflicts)

## Continuous Improvement

The integration test workflow helps catch issues early:

- Infrastructure changes that would break deployment
- Permission problems before they reach production
- Output buffering issues (like the "Releasing state lock" hang)
- Backend configuration problems

Run integration tests before merging significant infrastructure changes.
