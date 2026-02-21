import argparse
from unittest.mock import patch

import pytest

from cli.genie import build_parser, cmd_bootstrap


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
