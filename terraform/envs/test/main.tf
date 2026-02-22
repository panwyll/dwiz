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
  env = "test"
}

module "network" {
  source          = "../../modules/network"
  name            = "dwiz-test"
  environment     = local.env
  cidr            = "10.20.0.0/16"
  public_subnets  = ["10.20.1.0/24", "10.20.2.0/24"]
  private_subnets = ["10.20.11.0/24", "10.20.12.0/24"]
  azs             = ["${var.region}a", "${var.region}b"]
}

module "s3_lake" {
  source         = "../../modules/s3_lake"
  raw_bucket     = "${var.project}-raw-test"
  curated_bucket = "${var.project}-curated-test"
  environment    = local.env
}

module "secrets_manager" {
  source      = "../../modules/secrets_manager"
  name        = "${var.project}-test"
  environment = local.env
}

module "mwaa" {
  source             = "../../modules/mwaa"
  name               = "${var.project}-mwaa-test"
  environment        = local.env
  airflow_version    = var.airflow_version
  dags_bucket        = "${var.project}-dags-test"
  private_subnet_ids = module.network.private_subnet_ids
  vpc_id             = module.network.vpc_id
  secrets_arns = [
    module.secrets_manager.api_keys_secret_arn,
    module.secrets_manager.database_secret_arn,
    module.secrets_manager.streaming_secret_arn,
    "${module.secrets_manager.secret_arn_prefix}*"
  ]
  kms_key_arn = module.secrets_manager.kms_key_arn
}

module "ecs_jobs" {
  source      = "../../modules/ecs_jobs"
  name        = "${var.project}-jobs-test"
  environment = local.env
}

module "firehose" {
  source      = "../../modules/kinesis_firehose"
  name        = "${var.project}-firehose-test"
  environment = local.env
  bucket_arn  = "arn:aws:s3:::${var.project}-raw-test"
}

module "observability" {
  source             = "../../modules/observability"
  name               = "${var.project}-mwaa-test"
  environment        = local.env
  log_retention_days = 7
}

module "iam_test" {
  source            = "../../modules/iam"
  environment       = local.env
  role_name         = "github-deploy-test"
  oidc_provider_arn = var.oidc_provider_arn
  repo              = var.repo
  ref               = "refs/heads/*"
  region            = var.region
  account_id        = var.account_id
  resource_prefix   = var.project
}

module "dashboard" {
  source         = "../../modules/dashboard"
  name           = "${var.project}-test"
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
