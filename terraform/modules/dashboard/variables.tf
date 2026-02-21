variable "name" {
  type        = string
  description = "Name prefix for the dashboard"
}

variable "environment" {
  type        = string
  description = "Environment (dev, prod, etc.)"
}

variable "region" {
  type        = string
  description = "AWS region for the dashboard"
}

variable "log_group_name" {
  type        = string
  description = "CloudWatch Log Group name for log insights queries"
}
