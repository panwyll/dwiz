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
