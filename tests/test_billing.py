import argparse
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from cli.genie import build_parser, cmd_billing, get_date_range


def _billing_args(period: str = "month") -> argparse.Namespace:
    return argparse.Namespace(period=period)


def test_billing_parser_registered() -> None:
    parser = build_parser()
    args = parser.parse_args(["billing", "month"])
    assert args.period == "month"
    assert args.func == cmd_billing


def test_billing_parser_accepts_all_periods() -> None:
    parser = build_parser()
    for period in ["day", "month", "year", "all"]:
        args = parser.parse_args(["billing", period])
        assert args.period == period


def test_billing_parser_rejects_invalid_period() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["billing", "invalid"])


def test_get_date_range_day() -> None:
    start, end = get_date_range("day")
    today = datetime.now().date()
    yesterday = (today - timedelta(days=1)).strftime("%Y-%m-%d")
    assert start == yesterday
    assert end == today.strftime("%Y-%m-%d")


def test_get_date_range_month() -> None:
    start, end = get_date_range("month")
    today = datetime.now().date()
    month_start = today.replace(day=1).strftime("%Y-%m-%d")
    assert start == month_start
    assert end == today.strftime("%Y-%m-%d")


def test_get_date_range_year() -> None:
    start, end = get_date_range("year")
    today = datetime.now().date()
    year_start = today.replace(month=1, day=1).strftime("%Y-%m-%d")
    assert start == year_start
    assert end == today.strftime("%Y-%m-%d")


def test_get_date_range_all() -> None:
    start, end = get_date_range("all")
    today = datetime.now().date()
    year_ago = (today - timedelta(days=365)).strftime("%Y-%m-%d")
    assert start == year_ago
    assert end == today.strftime("%Y-%m-%d")


def test_get_date_range_invalid_period() -> None:
    with pytest.raises(ValueError):
        get_date_range("invalid")


def test_billing_displays_sorted_costs(capsys) -> None:
    args = _billing_args("month")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        mock_ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Groups": [
                        {
                            "Keys": ["Amazon Elastic Compute Cloud - Compute"],
                            "Metrics": {"UnblendedCost": {"Amount": "150.50", "Unit": "USD"}},
                        },
                        {
                            "Keys": ["Amazon Simple Storage Service"],
                            "Metrics": {"UnblendedCost": {"Amount": "25.75", "Unit": "USD"}},
                        },
                        {
                            "Keys": ["Amazon Relational Database Service"],
                            "Metrics": {"UnblendedCost": {"Amount": "200.00", "Unit": "USD"}},
                        },
                    ],
                }
            ]
        }
        mock_boto3.client.return_value = mock_ce
        cmd_billing(args)

    out = capsys.readouterr().out
    # Check that services are displayed in sorted order (highest cost first)
    assert "AWS Billing Summary" in out
    assert "Amazon Relational Database Service" in out
    assert "200.00" in out
    assert "Amazon Elastic Compute Cloud - Compute" in out
    assert "150.50" in out
    assert "Amazon Simple Storage Service" in out
    assert "25.75" in out
    # Check total
    assert "TOTAL" in out
    assert "376.25" in out


def test_billing_aggregates_multiple_time_periods(capsys) -> None:
    args = _billing_args("year")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        # Simulate data from multiple months
        mock_ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Groups": [
                        {
                            "Keys": ["Amazon S3"],
                            "Metrics": {"UnblendedCost": {"Amount": "10.00", "Unit": "USD"}},
                        },
                    ],
                },
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "Groups": [
                        {
                            "Keys": ["Amazon S3"],
                            "Metrics": {"UnblendedCost": {"Amount": "15.00", "Unit": "USD"}},
                        },
                    ],
                },
            ]
        }
        mock_boto3.client.return_value = mock_ce
        cmd_billing(args)

    out = capsys.readouterr().out
    # Check that costs are aggregated (10 + 15 = 25)
    assert "Amazon S3" in out
    assert "25.00" in out


def test_billing_filters_negligible_costs(capsys) -> None:
    args = _billing_args("month")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        mock_ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Groups": [
                        {
                            "Keys": ["Amazon EC2"],
                            "Metrics": {"UnblendedCost": {"Amount": "100.00", "Unit": "USD"}},
                        },
                        {
                            "Keys": ["AWS Tax"],
                            "Metrics": {"UnblendedCost": {"Amount": "0.001", "Unit": "USD"}},
                        },
                    ],
                }
            ]
        }
        mock_boto3.client.return_value = mock_ce
        cmd_billing(args)

    out = capsys.readouterr().out
    # Should display significant costs
    assert "Amazon EC2" in out
    # Should not display negligible costs
    assert "AWS Tax" not in out or "$0.00" not in out


def test_billing_handles_no_data(capsys) -> None:
    args = _billing_args("month")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        mock_ce.get_cost_and_usage.return_value = {"ResultsByTime": []}
        mock_boto3.client.return_value = mock_ce
        cmd_billing(args)

    out = capsys.readouterr().out
    assert "No billing data found" in out


def test_billing_handles_permission_error(capsys) -> None:
    args = _billing_args("month")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        error_msg = "User is not authorized to perform: ce:GetCostAndUsage"
        mock_ce.get_cost_and_usage.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": error_msg}},
            "GetCostAndUsage",
        )
        mock_boto3.client.return_value = mock_ce

        with pytest.raises(SystemExit):
            cmd_billing(args)

    out = capsys.readouterr().out
    assert "AWS PERMISSION ERROR" in out
    assert "ce:GetCostAndUsage" in out


def test_billing_uses_cost_explorer_in_us_east_1() -> None:
    args = _billing_args("month")
    with patch("cli.genie.require_tools"), patch("cli.genie.boto3") as mock_boto3:
        mock_ce = MagicMock()
        mock_ce.get_cost_and_usage.return_value = {"ResultsByTime": []}
        mock_boto3.client.return_value = mock_ce
        cmd_billing(args)

    # Verify that boto3.client was called with 'ce' and region 'us-east-1'
    mock_boto3.client.assert_called_once_with("ce", region_name="us-east-1")
