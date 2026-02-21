"""Secure secrets management for Airflow and streaming pipelines.

This module provides a simple interface for retrieving secrets from AWS Secrets Manager.
Secrets are cached for the lifetime of the process to minimize API calls.
"""

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Cache for secrets to avoid repeated API calls
_secrets_cache: dict[str, Any] = {}


def get_secret(secret_name: str, region_name: str = "us-east-1") -> dict[str, Any]:
    """Retrieve a secret from AWS Secrets Manager.

    Args:
        secret_name: Name or ARN of the secret to retrieve
        region_name: AWS region where the secret is stored

    Returns:
        Dictionary containing the secret value

    Raises:
        ClientError: If the secret cannot be retrieved
        json.JSONDecodeError: If the secret value is not valid JSON

    Example:
        >>> api_keys = get_secret("wizard-dev/api-keys")
        >>> api_key = api_keys.get("external_api_key")
    """
    cache_key = f"{region_name}:{secret_name}"

    if cache_key in _secrets_cache:
        logger.debug("Using cached secret: %s", secret_name)
        return _secrets_cache[cache_key]

    logger.info("Retrieving secret from AWS Secrets Manager: %s", secret_name)

    try:
        client = boto3.client("secretsmanager", region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)

        if "SecretString" in response:
            secret_value = json.loads(response["SecretString"])
        else:
            # Binary secrets are not commonly used for API keys/credentials
            raise ValueError(f"Secret {secret_name} contains binary data, not JSON string")

        _secrets_cache[cache_key] = secret_value
        logger.debug("Successfully retrieved and cached secret: %s", secret_name)
        return secret_value

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            logger.error("Secret not found: %s", secret_name)
            raise ValueError(f"Secret {secret_name} not found in AWS Secrets Manager") from e
        elif error_code == "AccessDeniedException":
            logger.error("Access denied to secret: %s", secret_name)
            raise PermissionError(
                f"Access denied to secret {secret_name}. "
                "Ensure MWAA execution role has secretsmanager:GetSecretValue permission."
            ) from e
        else:
            logger.error("Error retrieving secret %s: %s", secret_name, error_code)
            raise


def get_secret_value(secret_name: str, key: str, region_name: str = "us-east-1") -> str:
    """Retrieve a specific value from a secret.

    Args:
        secret_name: Name or ARN of the secret
        key: Key within the secret JSON to retrieve
        region_name: AWS region where the secret is stored

    Returns:
        The secret value as a string

    Raises:
        KeyError: If the key does not exist in the secret
        ClientError: If the secret cannot be retrieved

    Example:
        >>> api_key = get_secret_value("wizard-dev/api-keys", "external_api_key")
    """
    secret = get_secret(secret_name, region_name)
    if key not in secret:
        raise KeyError(f"Key '{key}' not found in secret '{secret_name}'")
    return secret[key]


def clear_cache() -> None:
    """Clear the secrets cache.

    This is primarily useful for testing or when you need to force
    a refresh of secrets from AWS Secrets Manager.
    """
    global _secrets_cache
    _secrets_cache = {}
    logger.debug("Secrets cache cleared")
