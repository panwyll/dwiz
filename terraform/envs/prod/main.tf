terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  env = "prod"
}

module "network" {
  source          = "../../modules/network"
  name            = "wizard-prod"
  environment     = local.env
  cidr            = "10.20.0.0/16"
  public_subnets  = ["10.20.1.0/24", "10.20.2.0/24"]
  private_subnets = ["10.20.11.0/24", "10.20.12.0/24"]
  azs             = ["${var.region}a", "${var.region}b"]
}

module "s3_lake" {
  source         = "../../modules/s3_lake"
  raw_bucket     = "${var.project}-raw-prod"
  curated_bucket = "${var.project}-curated-prod"
  environment    = local.env
}

module "secrets_manager" {
  source      = "../../modules/secrets_manager"
  name        = "${var.project}-prod"
  environment = local.env
}

module "mwaa" {
  source             = "../../modules/mwaa"
  name               = "${var.project}-mwaa-prod"
  environment        = local.env
  airflow_version    = var.airflow_version
  dags_bucket        = "${var.project}-dags-prod"
  private_subnet_ids = module.network.private_subnet_ids
  vpc_id             = module.network.vpc_id
  # Grant access to predefined secrets plus any future secrets under this prefix
  # This allows adding new secrets without Terraform changes
  # For stricter security, remove the wildcard and only include specific secret ARNs
  secrets_arns = [
    module.secrets_manager.api_keys_secret_arn,
    module.secrets_manager.database_secret_arn,
    module.secrets_manager.streaming_secret_arn,
    "${module.secrets_manager.secret_prefix}*"
  ]
  kms_key_arn = module.secrets_manager.kms_key_arn
}

module "ecs_jobs" {
  source      = "../../modules/ecs_jobs"
  name        = "${var.project}-jobs-prod"
  environment = local.env
}

module "firehose" {
  source      = "../../modules/kinesis_firehose"
  name        = "${var.project}-firehose-prod"
  environment = local.env
  bucket_arn  = "arn:aws:s3:::${var.project}-raw-prod"
}

module "observability" {
  source             = "../../modules/observability"
  name               = "${var.project}-mwaa-prod"
  environment        = local.env
  log_retention_days = 30
}

module "iam_prod" {
  source            = "../../modules/iam"
  environment       = local.env
  role_name         = "github-deploy-prod"
  oidc_provider_arn = var.oidc_provider_arn
  repo              = var.repo
  ref               = "refs/tags/v*"
  region            = var.region
  account_id        = var.account_id
  resource_prefix   = var.project
}

module "dashboard" {
  source         = "../../modules/dashboard"
  name           = "${var.project}-prod"
  environment    = local.env
  region         = var.region
  log_group_name = module.observability.log_group_name
}

output "dags_bucket" {
  value = module.mwaa.dags_bucket
}

output "dashboard_url" {
  value       = module.dashboard.dashboard_url
  description = "CloudWatch Dashboard URL"
}
