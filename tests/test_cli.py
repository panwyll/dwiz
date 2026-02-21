import argparse
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from cli.genie import build_parser, cmd_bootstrap, get_aws_account_id, validate_resource_names


def _bootstrap_args(**kwargs) -> argparse.Namespace:
    defaults = {"bucket": "my-tf-state", "table": "my-tf-lock", "region": "us-east-1"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_bootstrap_parser_registered() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["bootstrap", "--bucket", "b", "--table", "t", "--region", "eu-west-1"]
    )
    assert args.bucket == "b"
    assert args.table == "t"
    assert args.region == "eu-west-1"


def test_bootstrap_parser_default_region() -> None:
    parser = build_parser()
    args = parser.parse_args(["bootstrap", "--bucket", "b", "--table", "t"])
    assert args.region == "us-east-1"


def test_bootstrap_missing_bucket_exits() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["bootstrap", "--table", "t"])


def test_bootstrap_us_east_1_uses_s3_mb(capsys) -> None:
    args = _bootstrap_args(region="us-east-1")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        # Simulate bucket doesn't exist
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        # Simulate table doesn't exist
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    # Verify that create_bucket was called (us-east-1 doesn't need LocationConstraint)
    assert mock_s3.create_bucket.called
    out = capsys.readouterr().out
    assert "Bootstrap complete" in out


def test_bootstrap_other_region_uses_create_bucket() -> None:
    args = _bootstrap_args(region="eu-west-1")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    # Verify that create_bucket was called with LocationConstraint
    assert mock_s3.create_bucket.called
    call_args = mock_s3.create_bucket.call_args
    assert "CreateBucketConfiguration" in call_args[1]


def test_bootstrap_enables_versioning() -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    # Verify that put_bucket_versioning was called
    assert mock_s3.put_bucket_versioning.called


def test_bootstrap_creates_dynamodb_table() -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    # Verify that create_table was called
    assert mock_dynamodb.create_table.called


def test_bootstrap_skips_bucket_creation_when_exists(capsys) -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        # head_bucket and describe_table succeed (resources exist)
        mock_s3.head_bucket.return_value = {}
        mock_dynamodb.describe_table.return_value = {}
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    # Verify that create_bucket and create_table were NOT called
    assert not mock_s3.create_bucket.called
    assert not mock_dynamodb.create_table.called
    out = capsys.readouterr().out
    assert "already exists" in out


def test_bootstrap_prints_backend_config(capsys) -> None:
    args = _bootstrap_args(bucket="my-bucket", table="my-table", region="us-east-1")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )
        cmd_bootstrap(args)

    out = capsys.readouterr().out
    assert "my-bucket" in out
    assert "my-table" in out
    assert "us-east-1" in out


def test_get_aws_account_id_success() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = ("123456789012", "arn:aws:iam::123456789012:user/test")
        account_id = get_aws_account_id()
        assert account_id == "123456789012"


def test_get_aws_account_id_failure() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = (None, None)
        account_id = get_aws_account_id()
        assert account_id is None


def test_validate_resource_names_detects_placeholder_bucket() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = (None, None)
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR_ORG-genie-tf-state", "my-lock")
        assert "Placeholder values detected" in str(exc_info.value)
        assert "YOUR_ORG-genie-tf-state" in str(exc_info.value)


def test_validate_resource_names_detects_placeholder_table() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = (None, None)
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("my-bucket", "YOUR_ORG-genie-tf-lock")
        assert "Placeholder values detected" in str(exc_info.value)
        assert "YOUR_ORG-genie-tf-lock" in str(exc_info.value)


def test_validate_resource_names_provides_suggestion_with_account_id() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = ("123456789012", "arn:aws:iam::123456789012:user/test")
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR_ORG-genie-tf-state", "YOUR_ORG-genie-tf-lock")
        error_msg = str(exc_info.value)
        assert "Your AWS Account ID: 123456789012" in error_msg
        assert "123456789012-genie-tf-state" in error_msg
        assert "123456789012-genie-tf-lock" in error_msg


def test_validate_resource_names_handles_all_placeholder_patterns() -> None:
    """Test that all placeholder patterns are replaced in suggestions."""
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = ("987654321098", "arn:aws:iam::987654321098:user/test")
        # Test YOUR_ACCOUNT pattern
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR_ACCOUNT-bucket", "YOUR_ACCOUNT-table")
        error_msg = str(exc_info.value)
        assert "987654321098-bucket" in error_msg
        assert "987654321098-table" in error_msg
        assert "YOUR_ACCOUNT" not in error_msg.split("Suggested command")[1]


def test_validate_resource_names_provides_help_without_account_id() -> None:
    with patch("cli.genie.get_caller_identity") as mock_identity:
        mock_identity.return_value = (None, None)
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR-ORG-genie-tf-state", "my-lock")
        error_msg = str(exc_info.value)
        assert "aws sts get-caller-identity" in error_msg
        assert "console.aws.amazon.com" in error_msg


def test_validate_resource_names_bucket_too_short() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("ab", "my-lock")
    assert "between 3 and 63 characters" in str(exc_info.value)


def test_validate_resource_names_bucket_too_long() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("a" * 64, "my-lock")
    assert "between 3 and 63 characters" in str(exc_info.value)


def test_validate_resource_names_bucket_invalid_chars() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("My-Bucket", "my-lock")
    assert "lowercase letters, numbers, hyphens, and periods" in str(exc_info.value)


def test_validate_resource_names_bucket_starts_with_hyphen() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("-my-bucket", "my-lock")
    assert "cannot start or end with a hyphen or period" in str(exc_info.value)


def test_validate_resource_names_valid_names() -> None:
    # Should not raise any exception
    validate_resource_names("my-valid-bucket", "my-valid-table")
    validate_resource_names("abc", "t")
    validate_resource_names("bucket.with.dots", "table-with-dashes")


def test_bootstrap_validates_names_before_creating() -> None:
    args = _bootstrap_args(bucket="YOUR_ORG-genie-tf-state", table="my-lock")
    with patch("cli.genie.require_tools"), patch(
        "cli.genie.get_caller_identity"
    ) as mock_identity, patch("cli.genie.check_aws_credentials") as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_identity.return_value = (None, None)
        with pytest.raises(SystemExit) as exc_info:
            cmd_bootstrap(args)
        assert "Placeholder values detected" in str(exc_info.value)


def test_bootstrap_handles_s3_permission_error(capsys) -> None:
    """Test bootstrap provides helpful suggestions when S3 CreateBucket fails with AccessDenied."""
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        # Simulate bucket doesn't exist
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        # Simulate CreateBucket permission denied
        error_msg = (
            "User: arn:aws:iam::903783614598:user/dwiz is not authorized to "
            "perform: s3:CreateBucket on resource: arn:aws:s3:::test-bucket "
            "because no identity-based policy allows the s3:CreateBucket action"
        )
        mock_s3.create_bucket.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": error_msg,
                }
            },
            "CreateBucket",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )

        with patch("cli.genie.get_caller_identity") as mock_identity:
            mock_identity.return_value = ("903783614598", "arn:aws:iam::903783614598:user/dwiz")

            with pytest.raises(SystemExit):
                cmd_bootstrap(args)

        out = capsys.readouterr().out
        # Check for remediation output
        assert "AWS PERMISSION ERROR" in out
        assert "s3:CreateBucket" in out
        assert "REMEDIATION STEPS" in out or "OPTION 1" in out
        assert "aws iam put-user-policy" in out or "OPTION" in out


def test_bootstrap_handles_dynamodb_permission_error(capsys) -> None:
    """Test bootstrap provides helpful suggestions when DynamoDB CreateTable fails."""
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3, patch(
        "cli.genie.check_aws_credentials"
    ) as mock_check_creds:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        # S3 operations succeed
        mock_s3.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
        )
        # DynamoDB CreateTable permission denied
        mock_dynamodb.describe_table.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not Found"}},
            "DescribeTable",
        )
        error_msg = (
            "User: arn:aws:iam::123456789012:user/test is not authorized to "
            "perform: dynamodb:CreateTable"
        )
        mock_dynamodb.create_table.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": error_msg,
                }
            },
            "CreateTable",
        )
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )

        with patch("cli.genie.get_caller_identity") as mock_identity:
            mock_identity.return_value = ("123456789012", "arn:aws:iam::123456789012:user/test")

            with pytest.raises(SystemExit):
                cmd_bootstrap(args)

        out = capsys.readouterr().out
        # Check for remediation output
        assert "AWS PERMISSION ERROR" in out
        assert "dynamodb:CreateTable" in out


def test_bootstrap_checks_credentials_first(capsys) -> None:
    """Test that bootstrap checks credentials before doing anything else."""
    from botocore.exceptions import NoCredentialsError

    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch.dict(
        "os.environ", {}, clear=True
    ), patch("boto3.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        with pytest.raises(SystemExit) as exc_info:
            cmd_bootstrap(args)

        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "No AWS credentials found" in out
        assert "aws configure sso" in out


def test_bootstrap_with_sso_profile(capsys) -> None:
    """Test bootstrap with AWS_PROFILE set for SSO."""
    args = _bootstrap_args()
    mock_response = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/MySSORole/session",
    }

    with patch("cli.genie.require_tools"), patch.dict(
        "os.environ", {"AWS_PROFILE": "my-sso-profile"}
    ), patch("boto3.Session") as mock_session_class, patch("cli.genie.boto3") as mock_boto3:
        # Mock credential check
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = mock_response
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        # Mock S3 and DynamoDB clients
        mock_s3 = MagicMock()
        mock_dynamodb = MagicMock()
        mock_s3.head_bucket.return_value = {}
        mock_dynamodb.describe_table.return_value = {}
        mock_boto3.client.side_effect = lambda service, **kwargs: (
            mock_s3 if service == "s3" else mock_dynamodb
        )

        cmd_bootstrap(args)

        out = capsys.readouterr().out
        assert "my-sso-profile" in out
        assert "Bootstrap complete" in out
