#!/usr/bin/env python3
"""AWS permissions preflight checks for DWiz.

This module validates that the current AWS credentials have the minimum
permissions needed to run DWiz operations (init, up, deploy).
"""
import json
import os
import random
import string
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


@dataclass
class ProbeResult:
    """Result of a permission probe."""

    service: str
    action: str
    ok: bool
    details: str
    missing_actions: list[str]
    suggested_fix: str = ""


def check_aws_credentials() -> tuple[bool, str]:
    """Check if AWS credentials are configured and provide helpful guidance.

    This function checks if AWS credentials are available and provides
    guidance for AWS SSO authentication if needed.

    Returns:
        Tuple of (credentials_available, message)
        - credentials_available: True if valid credentials are found
        - message: Helpful message about credential status
    """
    aws_profile = os.environ.get("AWS_PROFILE")

    # Try to get caller identity to test credentials
    try:
        session = boto3.Session()
        sts = session.client("sts")
        response = sts.get_caller_identity()

        # Credentials are valid
        if aws_profile:
            msg = f"✓ Using AWS_PROFILE='{aws_profile}'"
        else:
            msg = "✓ Using default AWS credentials"

        # Add caller identity info
        caller_arn = response.get("Arn", "")
        if caller_arn:
            msg += f" (Identity: {caller_arn})"

        return True, msg

    except ProfileNotFound:
        # AWS_PROFILE is set but the profile doesn't exist
        msg = (
            f"✗ AWS_PROFILE is set to '{aws_profile}' but the profile does not exist.\n"
            f"\n"
            f"To configure this AWS SSO profile, run:\n"
            f"  aws configure sso --profile {aws_profile}\n"
            f"\n"
            f"Then authenticate:\n"
            f"  aws sso login --profile {aws_profile}"
        )
        return False, msg

    except NoCredentialsError:
        # No credentials found at all
        if aws_profile:
            msg = (
                f"✗ AWS_PROFILE is set to '{aws_profile}' but no valid credentials found.\n"
                f"\n"
                f"To authenticate with AWS SSO, run:\n"
                f"  aws sso login --profile {aws_profile}\n"
                f"\n"
                f"If the profile doesn't exist, configure it first:\n"
                f"  aws configure sso --profile {aws_profile}"
            )
        else:
            msg = (
                "✗ No AWS credentials found and AWS_PROFILE is not set.\n"
                "\n"
                "To use AWS SSO authentication:\n"
                "  1. Configure an AWS SSO profile:\n"
                "     aws configure sso --profile YOUR_PROFILE_NAME\n"
                "\n"
                "  2. Set the profile and authenticate:\n"
                "     export AWS_PROFILE=YOUR_PROFILE_NAME\n"
                "     aws sso login --profile YOUR_PROFILE_NAME\n"
                "\n"
                "Or configure traditional credentials:\n"
                "  aws configure"
            )
        return False, msg

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        # Check for expired SSO token
        if error_code == "InvalidClientTokenId" or "token" in str(e).lower():
            if aws_profile:
                msg = (
                    f"✗ AWS credentials may be expired (using AWS_PROFILE='{aws_profile}').\n"
                    f"\n"
                    f"To refresh your AWS SSO session, run:\n"
                    f"  aws sso login --profile {aws_profile}"
                )
            else:
                msg = (
                    "✗ AWS credentials may be expired.\n"
                    "\n"
                    "If using AWS SSO, set AWS_PROFILE and login:\n"
                    "  export AWS_PROFILE=YOUR_PROFILE_NAME\n"
                    "  aws sso login --profile YOUR_PROFILE_NAME\n"
                    "\n"
                    "Or refresh your credentials using:\n"
                    "  aws configure"
                )
        else:
            # Other ClientError
            if aws_profile:
                msg = (
                    f"✗ Error validating AWS credentials (using AWS_PROFILE='{aws_profile}'): {e}\n"
                    f"\n"
                    f"Try refreshing your credentials:\n"
                    f"  aws sso login --profile {aws_profile}"
                )
            else:
                msg = f"✗ Error validating AWS credentials: {e}"

        return False, msg


class AWSPreflight:
    """AWS permissions preflight checker."""

    def __init__(self, verbose: bool = False, write_probes: bool = False):
        """Initialize preflight checker.

        Args:
            verbose: Print detailed output including account info
            write_probes: Run write probes (create/delete resources) in addition to read-only
        """
        self.verbose = verbose
        self.write_probes = write_probes
        self.session = boto3.Session()
        self.account_id: str | None = None
        self.caller_arn: str | None = None

    def get_caller_identity(self) -> tuple[str, str]:
        """Get current AWS identity using STS.

        Returns:
            Tuple of (account_id, caller_arn)

        Raises:
            SystemExit: If unable to get caller identity
        """
        try:
            sts = self.session.client("sts")
            response = sts.get_caller_identity()
            self.account_id = response["Account"]
            self.caller_arn = response["Arn"]

            if self.verbose:
                print(f"AWS Account ID: {self.account_id}")
                print(f"Caller ARN: {self.caller_arn}")

            return self.account_id, self.caller_arn
        except ClientError as e:
            raise SystemExit(
                f"Failed to get AWS caller identity: {e}\n"
                "Ensure AWS credentials are configured."
            ) from e

    def _generate_test_suffix(self) -> str:
        """Generate a random suffix for test resource names.

        Returns:
            Random 8-character string of lowercase letters and digits
        """
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def probe_s3_list(self) -> ProbeResult:
        """Probe S3 ListAllMyBuckets permission."""
        try:
            s3 = self.session.client("s3")
            s3.list_buckets()
            return ProbeResult(
                service="S3",
                action="ListAllMyBuckets",
                ok=True,
                details="Can list S3 buckets",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="S3",
                    action="ListAllMyBuckets",
                    ok=False,
                    details=f"Cannot list S3 buckets: {e}",
                    missing_actions=["s3:ListAllMyBuckets"],
                )
            raise

    def probe_s3_write(self) -> ProbeResult:
        """Probe S3 CreateBucket/DeleteBucket permissions (optional write test)."""
        if not self.account_id:
            return ProbeResult(
                service="S3",
                action="CreateBucket",
                ok=False,
                details="Skipped: account_id not available",
                missing_actions=[],
            )

        # Generate a random bucket name
        rand_suffix = self._generate_test_suffix()
        bucket_name = f"{self.account_id}-dwiz-perm-test-{rand_suffix}"

        try:
            s3 = self.session.client("s3")
            # Try to create a bucket
            region = self.session.region_name or "us-east-1"
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )

            # Clean up immediately
            cleanup_details = ""
            try:
                s3.delete_bucket(Bucket=bucket_name)
            except ClientError as cleanup_error:
                cleanup_details = f" (Warning: cleanup failed: {cleanup_error})"
                if self.verbose:
                    print(f"Warning: Failed to delete test bucket {bucket_name}: {cleanup_error}")

            return ProbeResult(
                service="S3",
                action="CreateBucket/DeleteBucket",
                ok=True,
                details=f"Can create and delete S3 buckets{cleanup_details}",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="S3",
                    action="CreateBucket",
                    ok=False,
                    details=f"Cannot create S3 buckets: {e}",
                    missing_actions=["s3:CreateBucket", "s3:DeleteBucket"],
                )
            raise

    def probe_dynamodb_list(self) -> ProbeResult:
        """Probe DynamoDB ListTables permission."""
        try:
            dynamodb = self.session.client("dynamodb")
            dynamodb.list_tables()
            return ProbeResult(
                service="DynamoDB",
                action="ListTables",
                ok=True,
                details="Can list DynamoDB tables",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="DynamoDB",
                    action="ListTables",
                    ok=False,
                    details=f"Cannot list DynamoDB tables: {e}",
                    missing_actions=["dynamodb:ListTables"],
                )
            raise

    def probe_dynamodb_write(self) -> ProbeResult:
        """Probe DynamoDB CreateTable/DeleteTable permissions (optional write test)."""
        rand_suffix = self._generate_test_suffix()
        table_name = f"dwiz-perm-test-{rand_suffix}"

        try:
            dynamodb = self.session.client("dynamodb")
            # Try to create a table
            dynamodb.create_table(
                TableName=table_name,
                BillingMode="PAY_PER_REQUEST",
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            )

            # Wait briefly and clean up
            cleanup_details = ""
            try:
                dynamodb.delete_table(TableName=table_name)
            except ClientError as cleanup_error:
                cleanup_details = f" (Warning: cleanup failed: {cleanup_error})"
                if self.verbose:
                    print(
                        f"Warning: Failed to delete test table {table_name}: {cleanup_error}"
                    )

            return ProbeResult(
                service="DynamoDB",
                action="CreateTable/DeleteTable",
                ok=True,
                details=f"Can create and delete DynamoDB tables{cleanup_details}",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="DynamoDB",
                    action="CreateTable",
                    ok=False,
                    details=f"Cannot create DynamoDB tables: {e}",
                    missing_actions=["dynamodb:CreateTable", "dynamodb:DeleteTable"],
                )
            raise

    def probe_iam_list(self) -> ProbeResult:
        """Probe IAM ListRoles permission."""
        try:
            iam = self.session.client("iam")
            iam.list_roles(MaxItems=1)
            return ProbeResult(
                service="IAM",
                action="ListRoles",
                ok=True,
                details="Can list IAM roles",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="IAM",
                    action="ListRoles",
                    ok=False,
                    details=f"Cannot list IAM roles: {e}",
                    missing_actions=["iam:ListRoles"],
                )
            raise

    def probe_ec2_describe(self) -> ProbeResult:
        """Probe EC2 DescribeVpcs permission."""
        try:
            ec2 = self.session.client("ec2")
            ec2.describe_vpcs(MaxResults=5)
            return ProbeResult(
                service="EC2",
                action="DescribeVpcs",
                ok=True,
                details="Can describe VPCs",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="EC2",
                    action="DescribeVpcs",
                    ok=False,
                    details=f"Cannot describe VPCs: {e}",
                    missing_actions=["ec2:DescribeVpcs"],
                )
            raise

    def probe_mwaa_list(self) -> ProbeResult:
        """Probe MWAA ListEnvironments permission."""
        try:
            mwaa = self.session.client("mwaa")
            mwaa.list_environments(MaxResults=1)
            return ProbeResult(
                service="MWAA",
                action="ListEnvironments",
                ok=True,
                details="Can list MWAA environments",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="MWAA",
                    action="ListEnvironments",
                    ok=False,
                    details=f"Cannot list MWAA environments: {e}",
                    missing_actions=["airflow:ListEnvironments"],
                )
            raise

    def probe_ecr_describe(self) -> ProbeResult:
        """Probe ECR DescribeRepositories permission."""
        try:
            ecr = self.session.client("ecr")
            ecr.describe_repositories(maxResults=1)
            return ProbeResult(
                service="ECR",
                action="DescribeRepositories",
                ok=True,
                details="Can describe ECR repositories",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="ECR",
                    action="DescribeRepositories",
                    ok=False,
                    details=f"Cannot describe ECR repositories: {e}",
                    missing_actions=["ecr:DescribeRepositories"],
                )
            raise

    def probe_ecs_list(self) -> ProbeResult:
        """Probe ECS ListClusters permission."""
        try:
            ecs = self.session.client("ecs")
            ecs.list_clusters(maxResults=1)
            return ProbeResult(
                service="ECS",
                action="ListClusters",
                ok=True,
                details="Can list ECS clusters",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="ECS",
                    action="ListClusters",
                    ok=False,
                    details=f"Cannot list ECS clusters: {e}",
                    missing_actions=["ecs:ListClusters"],
                )
            raise

    def probe_logs_describe(self) -> ProbeResult:
        """Probe CloudWatch Logs DescribeLogGroups permission."""
        try:
            logs = self.session.client("logs")
            logs.describe_log_groups(limit=1)
            return ProbeResult(
                service="CloudWatch Logs",
                action="DescribeLogGroups",
                ok=True,
                details="Can describe CloudWatch log groups",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="CloudWatch Logs",
                    action="DescribeLogGroups",
                    ok=False,
                    details=f"Cannot describe CloudWatch log groups: {e}",
                    missing_actions=["logs:DescribeLogGroups"],
                )
            raise

    def probe_firehose_list(self) -> ProbeResult:
        """Probe Kinesis Firehose ListDeliveryStreams permission."""
        try:
            firehose = self.session.client("firehose")
            firehose.list_delivery_streams(Limit=1)
            return ProbeResult(
                service="Kinesis Firehose",
                action="ListDeliveryStreams",
                ok=True,
                details="Can list Kinesis Firehose delivery streams",
                missing_actions=[],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["AccessDenied", "UnauthorizedOperation"]:
                return ProbeResult(
                    service="Kinesis Firehose",
                    action="ListDeliveryStreams",
                    ok=False,
                    details=f"Cannot list Kinesis Firehose delivery streams: {e}",
                    missing_actions=["firehose:ListDeliveryStreams"],
                )
            raise

    def run_all_probes(self) -> list[ProbeResult]:
        """Run all permission probes.

        Returns:
            List of ProbeResults
        """
        results = []

        # Get caller identity first
        self.get_caller_identity()

        # Run read-only probes
        results.append(self.probe_s3_list())
        results.append(self.probe_dynamodb_list())
        results.append(self.probe_iam_list())
        results.append(self.probe_ec2_describe())
        results.append(self.probe_mwaa_list())
        results.append(self.probe_ecr_describe())
        results.append(self.probe_ecs_list())
        results.append(self.probe_logs_describe())
        results.append(self.probe_firehose_list())

        # Run write probes if requested
        if self.write_probes:
            results.append(self.probe_s3_write())
            results.append(self.probe_dynamodb_write())

        return results

    def generate_policy_document(self, missing_actions: list[str]) -> dict[str, Any]:
        """Generate an IAM policy document for missing actions.

        Args:
            missing_actions: List of missing IAM actions

        Returns:
            IAM policy document as a dict
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": missing_actions,
                    "Resource": "*",
                }
            ],
        }

    def extract_identity_name(self) -> str | None:
        """Extract user or role name from caller ARN.

        Returns:
            Username or role name, or None if unable to parse
        """
        if not self.caller_arn:
            return None

        # ARN format: arn:aws:iam::account-id:user/username
        # or: arn:aws:iam::account-id:role/rolename
        # or: arn:aws:sts::account-id:assumed-role/rolename/session-name
        parts = self.caller_arn.split(":")
        if len(parts) >= 6:
            resource = parts[5]
            if "/" in resource:
                resource_parts = resource.split("/")
                if len(resource_parts) >= 2:
                    # For assumed-role, get the role name (second part)
                    # For user/role, get the name (second part)
                    return resource_parts[1]
        return None

    def get_identity_type(self) -> str:
        """Get the type of identity (user, role, or assumed-role).

        Returns:
            'user', 'role', or 'assumed-role'
        """
        if not self.caller_arn:
            return "user"

        if ":assumed-role/" in self.caller_arn:
            return "assumed-role"
        elif ":role/" in self.caller_arn:
            return "role"
        elif ":user/" in self.caller_arn:
            return "user"
        return "user"

    def print_remediation(self, results: list[ProbeResult]) -> None:
        """Print remediation steps for failed probes.

        Args:
            results: List of ProbeResults
        """
        failed = [r for r in results if not r.ok]

        if not failed:
            print("\n✓ All permission checks passed!")
            return

        print("\n✗ Permission checks failed:")
        print()

        # Group by service
        by_service: dict[str, list[ProbeResult]] = {}
        for result in failed:
            by_service.setdefault(result.service, []).append(result)

        for service, service_results in by_service.items():
            print(f"  {service}:")
            for result in service_results:
                print(f"    - {result.action}: {result.details}")
        print()

        # Collect all missing actions
        all_missing: list[str] = []
        for result in failed:
            all_missing.extend(result.missing_actions)

        if not all_missing:
            print("Unable to determine specific missing permissions.")
            raise SystemExit(1)

        # Generate policy
        policy_doc = self.generate_policy_document(all_missing)
        policy_json = json.dumps(policy_doc, indent=2)

        print("=" * 80)
        print("REMEDIATION STEPS")
        print("=" * 80)
        print()
        print(f"Your AWS Identity: {self.caller_arn}")
        print()
        print("DWiz requires the following IAM permissions:")
        print()
        print(policy_json)
        print()

        # Determine identity type and provide appropriate commands
        identity_type = self.get_identity_type()
        identity_name = self.extract_identity_name()

        print("To grant these permissions, follow one of these options:")
        print()
        print("OPTION 1: Minimal permissions (recommended)")
        print("-" * 80)
        print("1. Save the policy above to a file: dwiz-bootstrap-policy.json")
        print()

        if identity_type == "user" and identity_name:
            print("2. Attach the policy to your user:")
            print(
                f"   aws iam put-user-policy --user-name {identity_name} "
                "--policy-name DWizBootstrap --policy-document file://dwiz-bootstrap-policy.json"
            )
        elif identity_type == "role" and identity_name:
            print("2. Attach the policy to your role:")
            print(
                f"   aws iam put-role-policy --role-name {identity_name} "
                "--policy-name DWizBootstrap --policy-document file://dwiz-bootstrap-policy.json"
            )
        elif identity_type == "assumed-role" and identity_name:
            print("2. Attach the policy to your role:")
            print(
                f"   aws iam put-role-policy --role-name {identity_name} "
                "--policy-name DWizBootstrap --policy-document file://dwiz-bootstrap-policy.json"
            )
        else:
            print("2. Attach the policy to your IAM user or role using the AWS Console")
            print("   or CLI commands appropriate for your identity type.")

        print()
        print("OPTION 2: Quick and dirty (full admin access)")
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

        raise SystemExit(1)


def run_preflight_check(verbose: bool = False, write_probes: bool = False) -> None:
    """Run AWS permissions preflight check.

    Args:
        verbose: Print detailed output
        write_probes: Run write probes in addition to read-only

    Raises:
        SystemExit: If any permission checks fail
    """
    print("Running AWS permissions preflight check...")
    if write_probes:
        print("(including write probes - will create and delete test resources)")
    print()

    # Check AWS credentials first
    creds_ok, creds_msg = check_aws_credentials()
    print(creds_msg)
    print()

    if not creds_ok:
        raise SystemExit(1)

    preflight = AWSPreflight(verbose=verbose, write_probes=write_probes)
    results = preflight.run_all_probes()

    if verbose:
        print()
        print("Probe results:")
        for result in results:
            status = "✓" if result.ok else "✗"
            print(f"  {status} {result.service}: {result.action}")

    preflight.print_remediation(results)
