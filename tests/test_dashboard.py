from pathlib import Path

# Get repository root from test file location
REPO_ROOT = Path(__file__).parent.parent


def test_dashboard_module_exists():
    """Test that the dashboard module directory exists"""
    dashboard_path = REPO_ROOT / "terraform/modules/dashboard"
    assert dashboard_path.exists()
    assert dashboard_path.is_dir()


def test_dashboard_main_tf_exists():
    """Test that dashboard main.tf exists"""
    main_tf = REPO_ROOT / "terraform/modules/dashboard/main.tf"
    assert main_tf.exists()
    assert main_tf.is_file()


def test_dashboard_variables_tf_exists():
    """Test that dashboard variables.tf exists"""
    variables_tf = REPO_ROOT / "terraform/modules/dashboard/variables.tf"
    assert variables_tf.exists()
    assert variables_tf.is_file()


def test_dashboard_main_tf_content():
    """Test that dashboard main.tf contains required CloudWatch dashboard resource"""
    main_tf = REPO_ROOT / "terraform/modules/dashboard/main.tf"
    content = main_tf.read_text()

    # Check for CloudWatch dashboard resource
    assert 'resource "aws_cloudwatch_dashboard"' in content
    assert "dashboard_name" in content
    assert "dashboard_body" in content

    # Check for usage metrics
    assert "MWAA" in content or "AWS/MWAA" in content
    assert "ECS" in content or "AWS/ECS" in content
    assert "Firehose" in content or "AWS/Firehose" in content

    # Check for billing metrics
    assert "Billing" in content or "AWS/Billing" in content
    assert "EstimatedCharges" in content

    # Check for log insights
    assert "log" in content or "query" in content


def test_dashboard_variables_tf_content():
    """Test that dashboard variables.tf contains required variables"""
    variables_tf = REPO_ROOT / "terraform/modules/dashboard/variables.tf"
    content = variables_tf.read_text()

    # Check for required variables
    assert 'variable "name"' in content
    assert 'variable "environment"' in content
    assert 'variable "region"' in content
    assert 'variable "log_group_name"' in content


def test_dashboard_integrated_in_dev():
    """Test that dashboard module is integrated in dev environment"""
    dev_main = REPO_ROOT / "terraform/envs/dev/main.tf"
    content = dev_main.read_text()

    # Check dashboard module is included
    assert 'module "dashboard"' in content
    assert "../../modules/dashboard" in content
    assert "log_group_name = module.observability.log_group_name" in content


def test_dashboard_integrated_in_prod():
    """Test that dashboard module is integrated in prod environment"""
    prod_main = REPO_ROOT / "terraform/envs/prod/main.tf"
    content = prod_main.read_text()

    # Check dashboard module is included
    assert 'module "dashboard"' in content
    assert "../../modules/dashboard" in content
    assert "log_group_name = module.observability.log_group_name" in content


def test_dashboard_outputs_in_dev():
    """Test that dashboard outputs are present in dev environment"""
    dev_main = REPO_ROOT / "terraform/envs/dev/main.tf"
    content = dev_main.read_text()

    # Check dashboard URL output
    assert 'output "dashboard_url"' in content
    assert "module.dashboard.dashboard_url" in content


def test_dashboard_outputs_in_prod():
    """Test that dashboard outputs are present in prod environment"""
    prod_main = REPO_ROOT / "terraform/envs/prod/main.tf"
    content = prod_main.read_text()

    # Check dashboard URL output
    assert 'output "dashboard_url"' in content
    assert "module.dashboard.dashboard_url" in content
