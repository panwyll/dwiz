import argparse
from unittest.mock import MagicMock, patch

import pytest

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
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ) as mock_run:
        mock_sub.return_value.returncode = 1  # resources don't exist yet
        cmd_bootstrap(args)

    calls = [str(c) for c in mock_run.call_args_list]
    # s3 mb is expected for us-east-1
    assert any("s3" in c and "mb" in c for c in calls)
    out = capsys.readouterr().out
    assert "Bootstrap complete" in out


def test_bootstrap_other_region_uses_create_bucket() -> None:
    args = _bootstrap_args(region="eu-west-1")
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ) as mock_run:
        mock_sub.return_value.returncode = 1
        cmd_bootstrap(args)

    calls = [str(c) for c in mock_run.call_args_list]
    assert any("create-bucket" in c for c in calls)


def test_bootstrap_enables_versioning() -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ) as mock_run:
        mock_sub.return_value.returncode = 1
        cmd_bootstrap(args)

    calls = [str(c) for c in mock_run.call_args_list]
    assert any("put-bucket-versioning" in c for c in calls)


def test_bootstrap_creates_dynamodb_table() -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ) as mock_run:
        mock_sub.return_value.returncode = 1
        cmd_bootstrap(args)

    calls = [str(c) for c in mock_run.call_args_list]
    assert any("create-table" in c for c in calls)


def test_bootstrap_skips_bucket_creation_when_exists(capsys) -> None:
    args = _bootstrap_args()
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ) as mock_run:
        mock_sub.return_value.returncode = 0  # resources already exist
        cmd_bootstrap(args)

    calls = [str(c) for c in mock_run.call_args_list]
    assert not any("mb" in c or "create-bucket" in c for c in calls)
    assert not any("create-table" in c for c in calls)
    out = capsys.readouterr().out
    assert "already exists" in out


def test_bootstrap_prints_backend_config(capsys) -> None:
    args = _bootstrap_args(bucket="my-bucket", table="my-table", region="us-east-1")
    with patch("cli.genie.require_tools"), patch("subprocess.run") as mock_sub, patch(
        "cli.genie.run"
    ):
        mock_sub.return_value.returncode = 1
        cmd_bootstrap(args)

    out = capsys.readouterr().out
    assert "my-bucket" in out
    assert "my-table" in out
    assert "us-east-1" in out


def test_get_aws_account_id_success() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "123456789012\n"
    with patch("subprocess.run", return_value=mock_result):
        account_id = get_aws_account_id()
        assert account_id == "123456789012"


def test_get_aws_account_id_failure() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 1
    with patch("subprocess.run", return_value=mock_result):
        account_id = get_aws_account_id()
        assert account_id is None


def test_validate_resource_names_detects_placeholder_bucket() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("YOUR_ORG-genie-tf-state", "my-lock")
    assert "Placeholder values detected" in str(exc_info.value)
    assert "YOUR_ORG-genie-tf-state" in str(exc_info.value)


def test_validate_resource_names_detects_placeholder_table() -> None:
    with pytest.raises(SystemExit) as exc_info:
        validate_resource_names("my-bucket", "YOUR_ORG-genie-tf-lock")
    assert "Placeholder values detected" in str(exc_info.value)
    assert "YOUR_ORG-genie-tf-lock" in str(exc_info.value)


def test_validate_resource_names_provides_suggestion_with_account_id() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "123456789012\n"
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR_ORG-genie-tf-state", "YOUR_ORG-genie-tf-lock")
        error_msg = str(exc_info.value)
        assert "Your AWS Account ID: 123456789012" in error_msg
        assert "123456789012-genie-tf-state" in error_msg
        assert "123456789012-genie-tf-lock" in error_msg


def test_validate_resource_names_handles_all_placeholder_patterns() -> None:
    """Test that all placeholder patterns are replaced in suggestions."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "987654321098\n"
    with patch("subprocess.run", return_value=mock_result):
        # Test YOUR_ACCOUNT pattern
        with pytest.raises(SystemExit) as exc_info:
            validate_resource_names("YOUR_ACCOUNT-bucket", "YOUR_ACCOUNT-table")
        error_msg = str(exc_info.value)
        assert "987654321098-bucket" in error_msg
        assert "987654321098-table" in error_msg
        assert "YOUR_ACCOUNT" not in error_msg.split("Suggested command")[1]


def test_validate_resource_names_provides_help_without_account_id() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 1
    with patch("subprocess.run", return_value=mock_result):
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
    with patch("cli.genie.require_tools"):
        with pytest.raises(SystemExit) as exc_info:
            cmd_bootstrap(args)
        assert "Placeholder values detected" in str(exc_info.value)
