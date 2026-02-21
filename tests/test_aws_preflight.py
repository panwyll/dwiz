"""Tests for AWS preflight checks."""
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from cli.aws_preflight import AWSPreflight, ProbeResult, run_preflight_check
from cli.genie import build_parser, cmd_deploy, cmd_init, cmd_up


def test_probe_result_creation() -> None:
    """Test ProbeResult dataclass."""
    result = ProbeResult(
        service="S3",
        action="ListBuckets",
        ok=True,
        details="Success",
        missing_actions=[],
    )
    assert result.service == "S3"
    assert result.action == "ListBuckets"
    assert result.ok is True


def test_get_caller_identity_success() -> None:
    """Test successful caller identity retrieval."""
    preflight = AWSPreflight(verbose=False)
    mock_response = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test-user",
    }

    with patch.object(preflight.session, "client") as mock_client:
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = mock_response
        mock_client.return_value = mock_sts

        account_id, arn = preflight.get_caller_identity()

        assert account_id == "123456789012"
        assert arn == "arn:aws:iam::123456789012:user/test-user"
        assert preflight.account_id == "123456789012"
        assert preflight.caller_arn == "arn:aws:iam::123456789012:user/test-user"


def test_get_caller_identity_failure() -> None:
    """Test caller identity retrieval failure."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "GetCallerIdentity",
        )
        mock_client.return_value = mock_sts

        with pytest.raises(SystemExit) as exc_info:
            preflight.get_caller_identity()
        # SystemExit was raised, which is what we expect
        assert exc_info.value.code != 0


def test_probe_s3_list_success() -> None:
    """Test successful S3 list buckets probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": []}
        mock_client.return_value = mock_s3

        result = preflight.probe_s3_list()

        assert result.ok is True
        assert result.service == "S3"
        assert result.action == "ListAllMyBuckets"
        assert len(result.missing_actions) == 0


def test_probe_s3_list_access_denied() -> None:
    """Test S3 list buckets probe with access denied."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_s3 = MagicMock()
        mock_s3.list_buckets.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "ListBuckets"
        )
        mock_client.return_value = mock_s3

        result = preflight.probe_s3_list()

        assert result.ok is False
        assert result.service == "S3"
        assert "s3:ListAllMyBuckets" in result.missing_actions


def test_probe_dynamodb_list_success() -> None:
    """Test successful DynamoDB list tables probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_ddb = MagicMock()
        mock_ddb.list_tables.return_value = {"TableNames": []}
        mock_client.return_value = mock_ddb

        result = preflight.probe_dynamodb_list()

        assert result.ok is True
        assert result.service == "DynamoDB"
        assert result.action == "ListTables"


def test_probe_dynamodb_list_access_denied() -> None:
    """Test DynamoDB list tables probe with access denied."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_ddb = MagicMock()
        mock_ddb.list_tables.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "ListTables"
        )
        mock_client.return_value = mock_ddb

        result = preflight.probe_dynamodb_list()

        assert result.ok is False
        assert "dynamodb:ListTables" in result.missing_actions


def test_probe_iam_list_success() -> None:
    """Test successful IAM list roles probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_iam = MagicMock()
        mock_iam.list_roles.return_value = {"Roles": []}
        mock_client.return_value = mock_iam

        result = preflight.probe_iam_list()

        assert result.ok is True
        assert result.service == "IAM"


def test_probe_ec2_describe_success() -> None:
    """Test successful EC2 describe VPCs probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        mock_client.return_value = mock_ec2

        result = preflight.probe_ec2_describe()

        assert result.ok is True
        assert result.service == "EC2"


def test_probe_mwaa_list_success() -> None:
    """Test successful MWAA list environments probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_mwaa = MagicMock()
        mock_mwaa.list_environments.return_value = {"Environments": []}
        mock_client.return_value = mock_mwaa

        result = preflight.probe_mwaa_list()

        assert result.ok is True
        assert result.service == "MWAA"


def test_probe_ecr_describe_success() -> None:
    """Test successful ECR describe repositories probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_ecr = MagicMock()
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        mock_client.return_value = mock_ecr

        result = preflight.probe_ecr_describe()

        assert result.ok is True
        assert result.service == "ECR"


def test_probe_ecs_list_success() -> None:
    """Test successful ECS list clusters probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_ecs = MagicMock()
        mock_ecs.list_clusters.return_value = {"clusterArns": []}
        mock_client.return_value = mock_ecs

        result = preflight.probe_ecs_list()

        assert result.ok is True
        assert result.service == "ECS"


def test_probe_logs_describe_success() -> None:
    """Test successful CloudWatch Logs describe log groups probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_logs = MagicMock()
        mock_logs.describe_log_groups.return_value = {"logGroups": []}
        mock_client.return_value = mock_logs

        result = preflight.probe_logs_describe()

        assert result.ok is True
        assert result.service == "CloudWatch Logs"


def test_probe_firehose_list_success() -> None:
    """Test successful Kinesis Firehose list delivery streams probe."""
    preflight = AWSPreflight(verbose=False)

    with patch.object(preflight.session, "client") as mock_client:
        mock_firehose = MagicMock()
        mock_firehose.list_delivery_streams.return_value = {"DeliveryStreamNames": []}
        mock_client.return_value = mock_firehose

        result = preflight.probe_firehose_list()

        assert result.ok is True
        assert result.service == "Kinesis Firehose"


def test_generate_policy_document() -> None:
    """Test IAM policy document generation."""
    preflight = AWSPreflight(verbose=False)
    missing_actions = ["s3:ListAllMyBuckets", "dynamodb:ListTables"]

    policy = preflight.generate_policy_document(missing_actions)

    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 1
    assert policy["Statement"][0]["Effect"] == "Allow"
    assert policy["Statement"][0]["Action"] == missing_actions
    assert policy["Statement"][0]["Resource"] == "*"


def test_extract_identity_name_user() -> None:
    """Test extracting username from user ARN."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:iam::123456789012:user/test-user"

    name = preflight.extract_identity_name()

    assert name == "test-user"


def test_extract_identity_name_role() -> None:
    """Test extracting role name from role ARN."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:iam::123456789012:role/test-role"

    name = preflight.extract_identity_name()

    assert name == "test-role"


def test_extract_identity_name_assumed_role() -> None:
    """Test extracting role name from assumed role ARN."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:sts::123456789012:assumed-role/test-role/session-name"

    name = preflight.extract_identity_name()

    assert name == "test-role"


def test_get_identity_type_user() -> None:
    """Test identifying user identity type."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:iam::123456789012:user/test-user"

    identity_type = preflight.get_identity_type()

    assert identity_type == "user"


def test_get_identity_type_role() -> None:
    """Test identifying role identity type."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:iam::123456789012:role/test-role"

    identity_type = preflight.get_identity_type()

    assert identity_type == "role"


def test_get_identity_type_assumed_role() -> None:
    """Test identifying assumed role identity type."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:sts::123456789012:assumed-role/test-role/session"

    identity_type = preflight.get_identity_type()

    assert identity_type == "assumed-role"


def test_run_all_probes_success() -> None:
    """Test running all probes successfully."""
    preflight = AWSPreflight(verbose=False, write_probes=False)

    # Mock all boto3 clients
    with patch.object(preflight.session, "client") as mock_client:
        # Mock STS for identity
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }

        # Mock all other services
        mock_service = MagicMock()
        mock_service.list_buckets.return_value = {}
        mock_service.list_tables.return_value = {}
        mock_service.list_roles.return_value = {}
        mock_service.describe_vpcs.return_value = {}
        mock_service.list_environments.return_value = {}
        mock_service.describe_repositories.return_value = {}
        mock_service.list_clusters.return_value = {}
        mock_service.describe_log_groups.return_value = {}
        mock_service.list_delivery_streams.return_value = {}

        def client_factory(service_name):
            if service_name == "sts":
                return mock_sts
            return mock_service

        mock_client.side_effect = client_factory

        results = preflight.run_all_probes()

        # Should have 9 results (no write probes)
        assert len(results) == 9
        assert all(r.ok for r in results)


def test_run_all_probes_with_write_probes() -> None:
    """Test running all probes including write probes."""
    preflight = AWSPreflight(verbose=False, write_probes=True)
    preflight.account_id = "123456789012"

    with patch.object(preflight.session, "client") as mock_client:
        # Mock STS for identity
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }

        # Mock all other services
        mock_service = MagicMock()
        mock_service.list_buckets.return_value = {}
        mock_service.list_tables.return_value = {}
        mock_service.list_roles.return_value = {}
        mock_service.describe_vpcs.return_value = {}
        mock_service.list_environments.return_value = {}
        mock_service.describe_repositories.return_value = {}
        mock_service.list_clusters.return_value = {}
        mock_service.describe_log_groups.return_value = {}
        mock_service.list_delivery_streams.return_value = {}
        mock_service.create_bucket.return_value = {}
        mock_service.delete_bucket.return_value = {}
        mock_service.create_table.return_value = {}
        mock_service.delete_table.return_value = {}

        def client_factory(service_name):
            if service_name == "sts":
                return mock_sts
            return mock_service

        mock_client.side_effect = client_factory

        results = preflight.run_all_probes()

        # Should have 11 results (including write probes)
        assert len(results) == 11


def test_print_remediation_all_passed(capsys) -> None:
    """Test remediation output when all checks pass."""
    preflight = AWSPreflight(verbose=False)
    results = [
        ProbeResult(
            service="S3", action="ListBuckets", ok=True, details="Success", missing_actions=[]
        )
    ]

    preflight.print_remediation(results)

    captured = capsys.readouterr()
    assert "All permission checks passed" in captured.out


def test_print_remediation_with_failures(capsys) -> None:
    """Test remediation output when checks fail."""
    preflight = AWSPreflight(verbose=False)
    preflight.caller_arn = "arn:aws:iam::123456789012:user/test-user"
    results = [
        ProbeResult(
            service="S3",
            action="ListBuckets",
            ok=False,
            details="Access denied",
            missing_actions=["s3:ListAllMyBuckets"],
        )
    ]

    with pytest.raises(SystemExit):
        preflight.print_remediation(results)

    captured = capsys.readouterr()
    assert "Permission checks failed" in captured.out
    assert "s3:ListAllMyBuckets" in captured.out
    assert "REMEDIATION STEPS" in captured.out


def test_run_preflight_check_success(capsys) -> None:
    """Test successful preflight check."""
    with patch("cli.aws_preflight.check_aws_credentials") as mock_check_creds, patch(
        "cli.aws_preflight.AWSPreflight"
    ) as mock_preflight_class:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_preflight = MagicMock()
        mock_preflight.run_all_probes.return_value = [
            ProbeResult(
                service="S3", action="ListBuckets", ok=True, details="Success", missing_actions=[]
            )
        ]
        mock_preflight_class.return_value = mock_preflight

        run_preflight_check(verbose=False, write_probes=False)

        captured = capsys.readouterr()
        assert "Running AWS permissions preflight check" in captured.out


def test_run_preflight_check_with_write_probes(capsys) -> None:
    """Test preflight check with write probes enabled."""
    with patch("cli.aws_preflight.check_aws_credentials") as mock_check_creds, patch(
        "cli.aws_preflight.AWSPreflight"
    ) as mock_preflight_class:
        mock_check_creds.return_value = (True, "✓ Using default AWS credentials")
        mock_preflight = MagicMock()
        mock_preflight.run_all_probes.return_value = [
            ProbeResult(
                service="S3", action="ListBuckets", ok=True, details="Success", missing_actions=[]
            )
        ]
        mock_preflight_class.return_value = mock_preflight

        run_preflight_check(verbose=False, write_probes=True)

        captured = capsys.readouterr()
        assert "including write probes" in captured.out


def test_init_command_runs_preflight() -> None:
    """Test that init command runs preflight check."""
    parser = build_parser()
    args = parser.parse_args(["init"])

    with patch("cli.genie.require_tools"), patch(
        "cli.genie.run_preflight_check"
    ) as mock_preflight:
        cmd_init(args)
        mock_preflight.assert_called_once_with(verbose=False, write_probes=False)


def test_init_command_passes_verbose_flag() -> None:
    """Test that init command passes verbose flag to preflight check."""
    parser = build_parser()
    args = parser.parse_args(["init", "--verbose"])

    with patch("cli.genie.require_tools"), patch(
        "cli.genie.run_preflight_check"
    ) as mock_preflight:
        cmd_init(args)
        mock_preflight.assert_called_once_with(verbose=True, write_probes=False)


def test_init_command_passes_preflight_write_flag() -> None:
    """Test that init command passes preflight-write flag to preflight check."""
    parser = build_parser()
    args = parser.parse_args(["init", "--preflight-write"])

    with patch("cli.genie.require_tools"), patch(
        "cli.genie.run_preflight_check"
    ) as mock_preflight:
        cmd_init(args)
        mock_preflight.assert_called_once_with(verbose=False, write_probes=True)


def test_up_command_runs_preflight() -> None:
    """Test that up command runs preflight check."""
    parser = build_parser()
    args = parser.parse_args(["up", "dev"])

    with patch("cli.genie.require_tools"), patch("cli.genie.run_make"), patch(
        "cli.genie.run_preflight_check"
    ) as mock_preflight:
        cmd_up(args)
        mock_preflight.assert_called_once_with(verbose=False, write_probes=False)


def test_deploy_command_runs_preflight() -> None:
    """Test that deploy command runs preflight check."""
    parser = build_parser()
    args = parser.parse_args(["deploy", "dev"])

    with patch("cli.genie.require_tools"), patch("cli.genie.run_make"), patch(
        "cli.genie.run_preflight_check"
    ) as mock_preflight:
        cmd_deploy(args)
        mock_preflight.assert_called_once_with(verbose=False, write_probes=False)


def test_check_aws_credentials_with_profile_success() -> None:
    """Test credential check with AWS_PROFILE set and valid credentials."""
    from cli.aws_preflight import check_aws_credentials

    mock_response = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/MySSORole/session",
    }

    with patch.dict("os.environ", {"AWS_PROFILE": "my-sso-profile"}), patch(
        "boto3.Session"
    ) as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = mock_response
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is True
        assert "my-sso-profile" in msg
        assert "arn:aws:sts::123456789012:assumed-role/MySSORole/session" in msg


def test_check_aws_credentials_without_profile_success() -> None:
    """Test credential check without AWS_PROFILE but valid credentials."""
    from cli.aws_preflight import check_aws_credentials

    mock_response = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test-user",
    }

    with patch.dict("os.environ", {}, clear=True), patch("boto3.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = mock_response
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is True
        assert "default AWS credentials" in msg


def test_check_aws_credentials_no_credentials_with_profile() -> None:
    """Test credential check with AWS_PROFILE set but no credentials."""
    from botocore.exceptions import NoCredentialsError

    from cli.aws_preflight import check_aws_credentials

    with patch.dict("os.environ", {"AWS_PROFILE": "my-profile"}), patch(
        "boto3.Session"
    ) as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is False
        assert "my-profile" in msg
        assert "aws sso login --profile my-profile" in msg


def test_check_aws_credentials_no_credentials_without_profile() -> None:
    """Test credential check without AWS_PROFILE and no credentials."""
    from botocore.exceptions import NoCredentialsError

    from cli.aws_preflight import check_aws_credentials

    with patch.dict("os.environ", {}, clear=True), patch("boto3.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is False
        assert "No AWS credentials found" in msg
        assert "aws configure sso" in msg


def test_check_aws_credentials_profile_not_found() -> None:
    """Test credential check when AWS_PROFILE is set but profile doesn't exist."""
    from botocore.exceptions import ProfileNotFound

    from cli.aws_preflight import check_aws_credentials

    with patch.dict("os.environ", {"AWS_PROFILE": "nonexistent-profile"}), patch(
        "boto3.Session"
    ) as mock_session_class:
        mock_session_class.side_effect = ProfileNotFound(profile="nonexistent-profile")

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is False
        assert "nonexistent-profile" in msg
        assert "profile does not exist" in msg
        assert "aws configure sso --profile nonexistent-profile" in msg


def test_check_aws_credentials_expired_token_with_profile() -> None:
    """Test credential check with expired SSO token."""
    from cli.aws_preflight import check_aws_credentials

    with patch.dict("os.environ", {"AWS_PROFILE": "my-sso-profile"}), patch(
        "boto3.Session"
    ) as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid"}},
            "GetCallerIdentity",
        )
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is False
        assert "expired" in msg
        assert "my-sso-profile" in msg
        assert "aws sso login" in msg


def test_check_aws_credentials_expired_token_without_profile() -> None:
    """Test credential check with expired token but no profile set."""
    from cli.aws_preflight import check_aws_credentials

    with patch.dict("os.environ", {}, clear=True), patch("boto3.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid"}},
            "GetCallerIdentity",
        )
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        creds_ok, msg = check_aws_credentials()

        assert creds_ok is False
        assert "expired" in msg
        assert "export AWS_PROFILE" in msg


def test_run_preflight_check_fails_on_invalid_credentials(capsys) -> None:
    """Test that preflight check exits early if credentials are invalid."""
    from botocore.exceptions import NoCredentialsError

    from cli.aws_preflight import run_preflight_check

    with patch.dict("os.environ", {}, clear=True), patch("boto3.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_check(verbose=False, write_probes=False)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No AWS credentials found" in captured.out
