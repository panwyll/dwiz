"""Tests for secrets management library."""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from libs.python_common.secrets import clear_cache, get_secret, get_secret_value


@pytest.fixture(autouse=True)
def reset_cache():
    """Clear cache before and after each test."""
    clear_cache()
    yield
    clear_cache()


def test_get_secret_success():
    """Test successful secret retrieval."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"api_key": "test_key_123", "username": "test_user"})
    }

    with patch("boto3.client", return_value=mock_client):
        secret = get_secret("test-secret")

    assert secret == {"api_key": "test_key_123", "username": "test_user"}
    mock_client.get_secret_value.assert_called_once_with(SecretId="test-secret")


def test_get_secret_caching():
    """Test that secrets are cached to avoid repeated API calls."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"api_key": "test_key"})
    }

    with patch("boto3.client", return_value=mock_client):
        # First call
        secret1 = get_secret("test-secret")
        # Second call should use cache
        secret2 = get_secret("test-secret")

    assert secret1 == secret2
    # Should only call AWS once due to caching
    mock_client.get_secret_value.assert_called_once()


def test_get_secret_not_found():
    """Test error handling when secret doesn't exist."""
    mock_client = MagicMock()
    mock_client.get_secret_value.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Secret not found"}},
        "GetSecretValue",
    )

    with patch("boto3.client", return_value=mock_client):
        with pytest.raises(ValueError, match="Secret test-secret not found"):
            get_secret("test-secret")


def test_get_secret_access_denied():
    """Test error handling when access is denied."""
    mock_client = MagicMock()
    mock_client.get_secret_value.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        "GetSecretValue",
    )

    with patch("boto3.client", return_value=mock_client):
        with pytest.raises(PermissionError, match="Access denied to secret"):
            get_secret("test-secret")


def test_get_secret_binary_data():
    """Test error handling for binary secrets."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {"SecretBinary": b"binary_data"}

    with patch("boto3.client", return_value=mock_client):
        with pytest.raises(ValueError, match="contains binary data"):
            get_secret("test-secret")


def test_get_secret_value_success():
    """Test retrieving a specific value from a secret."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"api_key": "test_key_123", "username": "test_user"})
    }

    with patch("boto3.client", return_value=mock_client):
        value = get_secret_value("test-secret", "api_key")

    assert value == "test_key_123"


def test_get_secret_value_key_not_found():
    """Test error when requested key doesn't exist in secret."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"api_key": "test_key_123"})
    }

    with patch("boto3.client", return_value=mock_client):
        with pytest.raises(KeyError, match="Key 'missing_key' not found"):
            get_secret_value("test-secret", "missing_key")


def test_get_secret_different_regions():
    """Test that secrets from different regions are cached separately."""
    mock_client_us_east = MagicMock()
    mock_client_us_east.get_secret_value.return_value = {
        "SecretString": json.dumps({"key": "us-east-value"})
    }

    mock_client_eu_west = MagicMock()
    mock_client_eu_west.get_secret_value.return_value = {
        "SecretString": json.dumps({"key": "eu-west-value"})
    }

    def mock_boto_client(service, region_name):
        if region_name == "us-east-1":
            return mock_client_us_east
        return mock_client_eu_west

    with patch("boto3.client", side_effect=mock_boto_client):
        secret_us = get_secret("test-secret", region_name="us-east-1")
        secret_eu = get_secret("test-secret", region_name="eu-west-1")

    assert secret_us == {"key": "us-east-value"}
    assert secret_eu == {"key": "eu-west-value"}


def test_clear_cache():
    """Test that cache can be cleared."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"key": "value"})
    }

    with patch("boto3.client", return_value=mock_client):
        # First call
        get_secret("test-secret")
        assert mock_client.get_secret_value.call_count == 1

        # Second call uses cache
        get_secret("test-secret")
        assert mock_client.get_secret_value.call_count == 1

        # Clear cache
        clear_cache()

        # Third call makes new API call
        get_secret("test-secret")
        assert mock_client.get_secret_value.call_count == 2


def test_get_secret_invalid_json():
    """Test error handling when secret value is not valid JSON."""
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {"SecretString": "not valid json{"}

    with patch("boto3.client", return_value=mock_client):
        with pytest.raises(json.JSONDecodeError):
            get_secret("test-secret")
