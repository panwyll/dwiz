variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "airflow_version" {
  type = string
}

variable "dags_bucket" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "vpc_id" {
  type = string
}

variable "secrets_arns" {
  type        = list(string)
  description = "ARNs of secrets that MWAA can access"
  default     = []
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of KMS key for decrypting secrets"
  default     = ""
}
