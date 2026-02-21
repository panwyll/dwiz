terraform {
  required_version = ">= 1.5"
}

# KMS key for encrypting secrets
resource "aws_kms_key" "secrets" {
  description             = "KMS key for encrypting secrets in ${var.environment}"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags = {
    Environment = var.environment
    Name        = "${var.name}-secrets-key"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# Example secret for API keys (to be populated via CLI or console)
resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${var.name}/api-keys"
  description             = "API keys for external services"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
  tags = {
    Environment = var.environment
  }
}

# Example secret for database credentials
resource "aws_secretsmanager_secret" "database" {
  name                    = "${var.name}/database"
  description             = "Database credentials"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
  tags = {
    Environment = var.environment
  }
}

# Example secret for streaming service credentials
resource "aws_secretsmanager_secret" "streaming" {
  name                    = "${var.name}/streaming"
  description             = "Streaming service credentials and configuration"
  kms_key_id              = aws_kms_key.secrets.id
  recovery_window_in_days = 7
  tags = {
    Environment = var.environment
  }
}

output "kms_key_id" {
  value = aws_kms_key.secrets.id
}

output "kms_key_arn" {
  value = aws_kms_key.secrets.arn
}

output "api_keys_secret_arn" {
  value = aws_secretsmanager_secret.api_keys.arn
}

output "database_secret_arn" {
  value = aws_secretsmanager_secret.database.arn
}

output "streaming_secret_arn" {
  value = aws_secretsmanager_secret.streaming.arn
}

output "secret_prefix" {
  value = "${var.name}/"
}
