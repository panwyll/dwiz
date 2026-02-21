#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path

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


def get_aws_account_id() -> str | None:
    """Try to get AWS account ID from current credentials."""
    result = subprocess.run(
        ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


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
            f"Error: S3 bucket name cannot start or end with a hyphen or period.\n"
            f"Got: {bucket}"
        )


def cmd_bootstrap(args: argparse.Namespace) -> None:
    require_tools("aws")
    region = args.region
    bucket = args.bucket
    table = args.table
    
    # Validate resource names before attempting to create them
    validate_resource_names(bucket, table)

    bucket_exists = (
        subprocess.run(
            ["aws", "s3api", "head-bucket", "--bucket", bucket, "--region", region],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )
    if bucket_exists:
        print(f"S3 bucket already exists, skipping creation: {bucket}")
    else:
        print(f"Creating S3 state bucket: {bucket}")
        if region == "us-east-1":
            run(["aws", "s3", "mb", f"s3://{bucket}", "--region", region])
        else:
            run(
                [
                    "aws",
                    "s3api",
                    "create-bucket",
                    "--bucket",
                    bucket,
                    "--region",
                    region,
                    "--create-bucket-configuration",
                    f"LocationConstraint={region}",
                ]
            )

    print(f"Enabling versioning on bucket: {bucket}")
    run(
        [
            "aws",
            "s3api",
            "put-bucket-versioning",
            "--bucket",
            bucket,
            "--versioning-configuration",
            "Status=Enabled",
        ]
    )

    table_exists = (
        subprocess.run(
            ["aws", "dynamodb", "describe-table", "--table-name", table, "--region", region],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )
    if table_exists:
        print(f"DynamoDB table already exists, skipping creation: {table}")
    else:
        print(f"Creating DynamoDB lock table: {table}")
        run(
            [
                "aws",
                "dynamodb",
                "create-table",
                "--table-name",
                table,
                "--billing-mode",
                "PAY_PER_REQUEST",
                "--attribute-definitions",
                "AttributeName=LockID,AttributeType=S",
                "--key-schema",
                "AttributeName=LockID,KeyType=HASH",
                "--region",
                region,
            ]
        )

    print()
    print("Bootstrap complete. Update backend.tf files with:")
    print(f"  bucket         = \"{bucket}\"")
    print(f"  dynamodb_table = \"{table}\"")
    print(f"  region         = \"{region}\"")


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
    path.write_text(
        "name: {name}\nowner: data-eng\nsource: example\n".format(name=args.name)
    )
    print(f"Created {path}")


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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
