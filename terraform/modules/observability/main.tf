terraform {
  required_version = ">= 1.6"
}

resource "aws_cloudwatch_log_group" "mwaa" {
  name              = "/aws/mwaa/${var.name}"
  retention_in_days = var.log_retention_days
  tags = {
    Environment = var.environment
  }
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.mwaa.name
}
