#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from cli.aws_preflight import run_preflight_check

REPO_ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_ENVS = {"dev", "prod"}


def run(cmd: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def require_tools(*tools: str) -> None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def run_make(target: str, env: str | None = None) -> None:
    env_vars = os.environ.copy()
    if env:
        env_vars["ENV"] = env
    result = subprocess.run(["make", target], cwd=REPO_ROOT, env=env_vars, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def get_caller_identity() -> tuple[str | None, str | None]:
    """Get AWS account ID and caller ARN."""
    try:
        sts = boto3.client("sts")
        response = sts.get_caller_identity()
        return response.get("Account"), response.get("Arn")
    except ClientError:
        return None, None


def get_aws_account_id() -> str | None:
    """Try to get AWS account ID from current credentials."""
    account_id, _ = get_caller_identity()
    return account_id


def extract_identity_name(caller_arn: str | None) -> str | None:
    """Extract user or role name from caller ARN."""
    if not caller_arn:
        return None

    # ARN format: arn:aws:iam::account-id:user/username
    # or: arn:aws:iam::account-id:role/rolename
    # or: arn:aws:sts::account-id:assumed-role/rolename/session-name
    parts = caller_arn.split(":")
    if len(parts) >= 6:
        resource = parts[5]
        if "/" in resource:
            resource_parts = resource.split("/")
            if len(resource_parts) >= 2:
                return resource_parts[1]
    return None


def get_identity_type(caller_arn: str | None) -> str:
    """Get the type of identity (user, role, or assumed-role)."""
    if not caller_arn:
        return "user"

    if ":assumed-role/" in caller_arn:
        return "assumed-role"
    elif ":role/" in caller_arn:
        return "role"
    elif ":user/" in caller_arn:
        return "user"
    return "user"


def parse_aws_permission_error(error: ClientError) -> list[str]:
    """Parse AWS ClientError to extract missing permissions.

    Args:
        error: The ClientError exception from boto3

    Returns:
        List of missing IAM actions (e.g., ['s3:CreateBucket'])
    """
    error_code = error.response.get("Error", {}).get("Code", "")
    error_message = error.response.get("Error", {}).get("Message", "")

    # Check if it's an access denied error
    if error_code not in ["AccessDenied", "UnauthorizedOperation"]:
        return []

    # Try to extract the action from the error message
    # Pattern: "not authorized to perform: ACTION on resource"
    match = re.search(r"not authorized to perform: ([^\s]+)", error_message)
    if match:
        return [match.group(1)]

    # If we can't parse the specific action, return empty list
    return []


def print_permission_error_remediation(
    error: ClientError,
    missing_actions: list[str],
    resource_name: str = "",
) -> None:
    """Print remediation steps for AWS permission errors.

    Args:
        error: The ClientError exception from boto3
        missing_actions: List of missing IAM actions
        resource_name: Optional resource name for context
    """
    error_message = error.response.get("Error", {}).get("Message", str(error))

    print()
    print("=" * 80)
    print("AWS PERMISSION ERROR")
    print("=" * 80)
    print()
    print(f"Error: {error_message}")
    print()

    # Get caller identity
    account_id, caller_arn = get_caller_identity()

    if not missing_actions:
        print("Unable to automatically determine the missing permissions.")
        print("Please check the error message above and grant the necessary permissions.")
        print()
        if caller_arn:
            print(f"Your AWS Identity: {caller_arn}")
        print("=" * 80)
        return

    # Generate policy document
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": missing_actions,
                "Resource": "*",
            }
        ],
    }
    policy_json = json.dumps(policy_doc, indent=2)

    print(f"Your AWS Identity: {caller_arn or 'Unknown'}")
    print()
    print("The following IAM permissions are required:")
    print()
    print(policy_json)
    print()

    # Determine identity type and provide appropriate commands
    identity_type = get_identity_type(caller_arn)
    identity_name = extract_identity_name(caller_arn)

    print("To grant these permissions, follow one of these options:")
    print()
    print("OPTION 1: Grant specific permissions (recommended)")
    print("-" * 80)
    print("1. Save the policy above to a file: bootstrap-policy.json")
    print()

    if identity_type == "user" and identity_name:
        print("2. Attach the policy to your user:")
        print(
            f"   aws iam put-user-policy --user-name {identity_name} "
            "--policy-name DWizBootstrapPermissions --policy-document file://bootstrap-policy.json"
        )
    elif identity_type in ["role", "assumed-role"] and identity_name:
        print("2. Attach the policy to your role:")
        print(
            f"   aws iam put-role-policy --role-name {identity_name} "
            "--policy-name DWizBootstrapPermissions --policy-document file://bootstrap-policy.json"
        )
    else:
        print("2. Attach the policy to your IAM user or role using the AWS Console")
        print("   or CLI commands appropriate for your identity type.")

    print()
    print("OPTION 2: Use Terraform to grant permissions")
    print("-" * 80)
    if identity_type == "user" and identity_name:
        print("Create a Terraform configuration file (e.g., iam-permissions.tf):")
        print()
        print('resource "aws_iam_user_policy" "dwiz_bootstrap" {')
        print('  name = "DWizBootstrapPermissions"')
        print(f'  user = "{identity_name}"')
        print()
        print("  policy = jsonencode({")
        print('    Version = "2012-10-17"')
        print("    Statement = [")
        print("      {")
        print('        Effect   = "Allow"')
        print(f"        Action   = {json.dumps(missing_actions)}")
        print('        Resource = "*"')
        print("      },")
        print("    ]")
        print("  })")
        print("}")
    elif identity_type in ["role", "assumed-role"] and identity_name:
        print("Create a Terraform configuration file (e.g., iam-permissions.tf):")
        print()
        print('resource "aws_iam_role_policy" "dwiz_bootstrap" {')
        print('  name = "DWizBootstrapPermissions"')
        print(f'  role = "{identity_name}"')
        print()
        print("  policy = jsonencode({")
        print('    Version = "2012-10-17"')
        print("    Statement = [")
        print("      {")
        print('        Effect   = "Allow"')
        print(f"        Action   = {json.dumps(missing_actions)}")
        print('        Resource = "*"')
        print("      },")
        print("    ]")
        print("  })")
        print("}")
    else:
        print("Create a Terraform configuration with appropriate resource type")
        print("(aws_iam_user_policy or aws_iam_role_policy) for your identity.")

    print()
    print("Then run:")
    print("  terraform init")
    print("  terraform plan")
    print("  terraform apply")
    print()
    print("OPTION 3: Grant full admin access (not recommended for production)")
    print("-" * 80)
    if identity_type == "user" and identity_name:
        print("Attach AdministratorAccess policy to your user:")
        print(
            f"   aws iam attach-user-policy --user-name {identity_name} "
            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
    elif identity_type in ["role", "assumed-role"] and identity_name:
        print("Attach AdministratorAccess policy to your role:")
        print(
            f"   aws iam attach-role-policy --role-name {identity_name} "
            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
    else:
        print("Attach the AdministratorAccess managed policy using the AWS Console.")

    print()
    print("=" * 80)


def validate_resource_names(bucket: str, table: str) -> None:
    """Validate bucket and table names, detecting placeholders and providing helpful errors."""
    # Check for placeholder patterns
    placeholder_patterns = [
        "YOUR_ORG",
        "YOUR-ORG",
        "YOURORG",
        "YOUR_ACCOUNT",
        "YOUR-ACCOUNT",
    ]

    bucket_has_placeholder = any(
        pattern.lower() in bucket.lower() for pattern in placeholder_patterns
    )
    table_has_placeholder = any(
        pattern.lower() in table.lower() for pattern in placeholder_patterns
    )

    if bucket_has_placeholder or table_has_placeholder:
        error_parts = []
        error_parts.append("Error: Placeholder values detected in resource names.")
        error_parts.append("")

        if bucket_has_placeholder:
            error_parts.append(f"  Bucket name contains placeholder: {bucket}")
        if table_has_placeholder:
            error_parts.append(f"  Table name contains placeholder: {table}")

        error_parts.append("")
        error_parts.append(
            "You need to replace placeholders with your actual AWS organization "
            "or account identifier."
        )
        error_parts.append("")

        # Try to get AWS account ID
        account_id = get_aws_account_id()
        if account_id:
            error_parts.append(f"Your AWS Account ID: {account_id}")
            error_parts.append("")
            # Replace all placeholder patterns with account ID
            suggested_bucket = bucket
            suggested_table = table
            for pattern in placeholder_patterns:
                suggested_bucket = suggested_bucket.replace(pattern, account_id)
                suggested_table = suggested_table.replace(pattern, account_id)
            error_parts.append("Suggested command with your account ID:")
            error_parts.append(
                f"  genie bootstrap --bucket {suggested_bucket} --table {suggested_table}"
            )
        else:
            error_parts.append("To find your AWS Account ID, run:")
            error_parts.append("  aws sts get-caller-identity --query Account --output text")
            error_parts.append("")
            error_parts.append(
                "Or check the AWS Console at: https://console.aws.amazon.com/billing/home#/account"
            )

        raise SystemExit("\n".join(error_parts))

    # Basic S3 bucket name validation
    if len(bucket) < 3 or len(bucket) > 63:
        raise SystemExit(
            f"Error: S3 bucket name must be between 3 and 63 characters. Got: {bucket}"
        )

    if not all(c.islower() or c.isdigit() or c in "-." for c in bucket):
        raise SystemExit(
            f"Error: S3 bucket name can only contain lowercase letters, numbers, "
            f"hyphens, and periods.\nGot: {bucket}"
        )

    if (
        bucket.startswith("-")
        or bucket.endswith("-")
        or bucket.startswith(".")
        or bucket.endswith(".")
    ):
        raise SystemExit(
            f"Error: S3 bucket name cannot start or end with a hyphen or period.\nGot: {bucket}"
        )


def cmd_bootstrap(args: argparse.Namespace) -> None:
    require_tools("aws")
    region = args.region
    bucket = args.bucket
    table = args.table

    # Validate resource names before attempting to create them
    validate_resource_names(bucket, table)

    # Use boto3 for better error handling
    try:
        s3_client = boto3.client("s3", region_name=region)
        dynamodb_client = boto3.client("dynamodb", region_name=region)

        # Check if bucket exists
        bucket_exists = False
        try:
            s3_client.head_bucket(Bucket=bucket)
            bucket_exists = True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code not in ["404", "NoSuchBucket"]:
                # It's not a "bucket doesn't exist" error, so re-raise
                raise

        if bucket_exists:
            print(f"S3 bucket already exists, skipping creation: {bucket}")
        else:
            print(f"Creating S3 state bucket: {bucket}")
            try:
                if region == "us-east-1":
                    s3_client.create_bucket(Bucket=bucket)
                else:
                    s3_client.create_bucket(
                        Bucket=bucket,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    missing_actions = parse_aws_permission_error(e)
                    if not missing_actions:
                        missing_actions = ["s3:CreateBucket"]
                    print_permission_error_remediation(e, missing_actions, bucket)
                    raise SystemExit(1) from e
                raise

        print(f"Enabling versioning on bucket: {bucket}")
        try:
            s3_client.put_bucket_versioning(
                Bucket=bucket,
                VersioningConfiguration={"Status": "Enabled"},
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                missing_actions = parse_aws_permission_error(e)
                if not missing_actions:
                    missing_actions = ["s3:PutBucketVersioning"]
                print_permission_error_remediation(e, missing_actions, bucket)
                raise SystemExit(1) from e
            raise

        # Check if DynamoDB table exists
        table_exists = False
        try:
            dynamodb_client.describe_table(TableName=table)
            table_exists = True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "ResourceNotFoundException":
                # It's not a "table doesn't exist" error, so re-raise
                raise

        if table_exists:
            print(f"DynamoDB table already exists, skipping creation: {table}")
        else:
            print(f"Creating DynamoDB lock table: {table}")
            try:
                dynamodb_client.create_table(
                    TableName=table,
                    BillingMode="PAY_PER_REQUEST",
                    AttributeDefinitions=[{"AttributeName": "LockID", "AttributeType": "S"}],
                    KeySchema=[{"AttributeName": "LockID", "KeyType": "HASH"}],
                )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    missing_actions = parse_aws_permission_error(e)
                    if not missing_actions:
                        missing_actions = ["dynamodb:CreateTable"]
                    print_permission_error_remediation(e, missing_actions, table)
                    raise SystemExit(1) from e
                raise

        print()
        print("Bootstrap complete. Update backend.tf files with:")
        print(f'  bucket         = "{bucket}"')
        print(f'  dynamodb_table = "{table}"')
        print(f'  region         = "{region}"')

    except ClientError as e:
        # Catch any other AWS errors that weren't handled above
        error_code = e.response.get("Error", {}).get("Code", "")
        error_message = e.response.get("Error", {}).get("Message", "")
        if error_code in ["AccessDenied", "UnauthorizedOperation"]:
            missing_actions = parse_aws_permission_error(e)
            print_permission_error_remediation(e, missing_actions)
        else:
            print(f"AWS Error: {error_message}")
        raise SystemExit(1) from e


def cmd_init(args: argparse.Namespace) -> None:
    require_tools("terraform", "aws")
    # Run preflight check
    run_preflight_check(verbose=args.verbose, write_probes=args.preflight_write)
    print("Initialized. Ensure terraform backend config is updated.")


def cmd_up(args: argparse.Namespace) -> None:
    require_tools("terraform")
    if args.env not in TERRAFORM_ENVS:
        raise SystemExit("env must be dev or prod")
    # Run preflight check
    run_preflight_check(verbose=args.verbose, write_probes=args.preflight_write)
    run_make("tf-init", args.env)
    run_make("tf-plan", args.env)
    run_make("tf-apply", args.env)


def cmd_deploy(args: argparse.Namespace) -> None:
    require_tools("aws")
    if args.env not in TERRAFORM_ENVS:
        raise SystemExit("env must be dev or prod")
    # Run preflight check
    run_preflight_check(verbose=args.verbose, write_probes=args.preflight_write)
    run_make("deploy", args.env)


def cmd_new_source(args: argparse.Namespace) -> None:
    source_dir = REPO_ROOT / "pipelines" / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    path = source_dir / f"{args.name}.yaml"
    if path.exists():
        raise SystemExit("source already exists")
    path.write_text("name: {name}\nowner: data-eng\n".format(name=args.name))
    print(f"Created {path}")


def cmd_add_stream(args: argparse.Namespace) -> None:
    stream_dir = REPO_ROOT / "pipelines" / "streams"
    stream_dir.mkdir(parents=True, exist_ok=True)
    path = stream_dir / f"{args.name}.yaml"
    if path.exists():
        raise SystemExit("stream already exists")
    path.write_text("name: {name}\nowner: data-eng\nsource: example\n".format(name=args.name))
    print(f"Created {path}")


def get_date_range(period: str) -> tuple[str, str]:
    """Get start and end dates for the specified billing period.

    Args:
        period: One of 'day', 'month', 'year', or 'all'

    Returns:
        Tuple of (start_date, end_date) in YYYY-MM-DD format
    """
    today = datetime.now().date()
    end_date = today.strftime("%Y-%m-%d")

    if period == "day":
        start_date = (today - timedelta(days=1)).strftime("%Y-%m-%d")
    elif period == "month":
        start_date = today.replace(day=1).strftime("%Y-%m-%d")
    elif period == "year":
        start_date = today.replace(month=1, day=1).strftime("%Y-%m-%d")
    elif period == "all":
        # AWS Cost Explorer supports data from up to 12 months ago
        start_date = (today - timedelta(days=365)).strftime("%Y-%m-%d")
    else:
        raise ValueError(f"Invalid period: {period}")

    return start_date, end_date


def cmd_billing(args: argparse.Namespace) -> None:
    """Show AWS billing and usage information sorted by cost."""
    require_tools("aws")

    # Determine the time period
    period = args.period

    try:
        # Get date range for the period
        start_date, end_date = get_date_range(period)

        # Cost Explorer API is only available in us-east-1
        ce_client = boto3.client("ce", region_name="us-east-1")

        print(f"Fetching billing data for period: {period}")
        print(f"Date range: {start_date} to {end_date}")
        print()

        # Get cost and usage data grouped by service
        response = ce_client.get_cost_and_usage(
            TimePeriod={"Start": start_date, "End": end_date},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )

        # Parse and aggregate costs by service
        service_costs = {}
        for result in response.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                service_name = group["Keys"][0]
                cost_amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if service_name in service_costs:
                    service_costs[service_name] += cost_amount
                else:
                    service_costs[service_name] = cost_amount

        # Sort by cost (descending)
        sorted_services = sorted(
            service_costs.items(), key=lambda x: x[1], reverse=True
        )

        # Display results
        if not sorted_services:
            print("No billing data found for the specified period.")
            return

        print("AWS Billing Summary (sorted by cost)")
        print("=" * 80)
        print(f"{'Service':<50} {'Cost (USD)':>15}")
        print("-" * 80)

        total_cost = 0.0
        for service, cost in sorted_services:
            if cost > 0.01:  # Only show services with non-negligible costs
                print(f"{service:<50} ${cost:>14.2f}")
                total_cost += cost

        print("-" * 80)
        print(f"{'TOTAL':<50} ${total_cost:>14.2f}")
        print("=" * 80)

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        error_message = e.response.get("Error", {}).get("Message", "")

        if error_code in ["AccessDenied", "UnauthorizedOperation"]:
            print()
            print("=" * 80)
            print("AWS PERMISSION ERROR")
            print("=" * 80)
            print()
            print(f"Error: {error_message}")
            print()
            print("The billing command requires Cost Explorer API permissions.")
            print()
            print("Required IAM permissions:")
            print('  - ce:GetCostAndUsage')
            print()
            print("To grant these permissions, add the following to your IAM policy:")
            print()
            print(json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ce:GetCostAndUsage"],
                        "Resource": "*"
                    }
                ]
            }, indent=2))
            print()
            print("=" * 80)
            raise SystemExit(1) from e
        else:
            print(f"AWS Error: {error_message}")
            raise SystemExit(1) from e
    except Exception as e:
        print(f"Error: {str(e)}")
        raise SystemExit(1) from e


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genie")
    sub = parser.add_subparsers(dest="command", required=True)

    bootstrap_parser = sub.add_parser(
        "bootstrap",
        help="Create S3 state bucket and DynamoDB lock table for Terraform remote state",
    )
    bootstrap_parser.add_argument(
        "--bucket", required=True, help="S3 bucket name for Terraform state"
    )
    bootstrap_parser.add_argument(
        "--table", required=True, help="DynamoDB table name for state locking"
    )
    bootstrap_parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)"
    )
    bootstrap_parser.set_defaults(func=cmd_bootstrap)

    init_parser = sub.add_parser("init", help="Verify prerequisites")
    init_parser.add_argument(
        "--verbose", action="store_true", help="Print detailed output including account info"
    )
    init_parser.add_argument(
        "--preflight-write",
        action="store_true",
        help="Run write probes (create/delete test resources)",
    )
    init_parser.set_defaults(func=cmd_init)

    up_parser = sub.add_parser("up", help="Provision infra")
    up_parser.add_argument("env")
    up_parser.add_argument(
        "--verbose", action="store_true", help="Print detailed output including account info"
    )
    up_parser.add_argument(
        "--preflight-write",
        action="store_true",
        help="Run write probes (create/delete test resources)",
    )
    up_parser.set_defaults(func=cmd_up)

    deploy_parser = sub.add_parser("deploy", help="Deploy DAGs")
    deploy_parser.add_argument("env")
    deploy_parser.add_argument(
        "--verbose", action="store_true", help="Print detailed output including account info"
    )
    deploy_parser.add_argument(
        "--preflight-write",
        action="store_true",
        help="Run write probes (create/delete test resources)",
    )
    deploy_parser.set_defaults(func=cmd_deploy)

    new_source = sub.add_parser("new-source", help="Create source scaffold")
    new_source.add_argument("name")
    new_source.set_defaults(func=cmd_new_source)

    add_stream = sub.add_parser("add-stream", help="Create stream scaffold")
    add_stream.add_argument("name")
    add_stream.set_defaults(func=cmd_add_stream)

    billing_parser = sub.add_parser(
        "billing",
        help="Show AWS billing and usage information sorted by cost",
    )
    billing_parser.add_argument(
        "period",
        choices=["day", "month", "year", "all"],
        help="Time period: day=yesterday, month=current month, year=YTD, all=last 12mo",
    )
    billing_parser.set_defaults(func=cmd_billing)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
