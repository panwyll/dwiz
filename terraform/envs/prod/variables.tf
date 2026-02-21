variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "wizard"
}

variable "airflow_version" {
  type    = string
  default = "2.7.2"
}

variable "oidc_provider_arn" {
  type = string
}

variable "repo" {
  type = string
}

variable "account_id" {
  type = string
}
