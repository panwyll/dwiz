terraform {
  required_version = ">= 1.6"
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
  env = "dev"
}

module "network" {
  source          = "../../modules/network"
  name            = "genie-dev"
  environment     = local.env
  cidr            = "10.10.0.0/16"
  public_subnets  = ["10.10.1.0/24", "10.10.2.0/24"]
  private_subnets = ["10.10.11.0/24", "10.10.12.0/24"]
  azs             = ["${var.region}a", "${var.region}b"]
}

module "s3_lake" {
  source         = "../../modules/s3_lake"
  raw_bucket     = "${var.project}-raw-dev"
  curated_bucket = "${var.project}-curated-dev"
  environment    = local.env
}

module "secrets_manager" {
  source      = "../../modules/secrets_manager"
  name        = "${var.project}-dev"
  environment = local.env
}

module "mwaa" {
  source             = "../../modules/mwaa"
  name               = "${var.project}-mwaa-dev"
  environment        = local.env
  airflow_version    = var.airflow_version
  dags_bucket        = "${var.project}-dags-dev"
  private_subnet_ids = module.network.private_subnet_ids
  vpc_id             = module.network.vpc_id
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
  name        = "${var.project}-jobs-dev"
  environment = local.env
}

module "firehose" {
  source      = "../../modules/kinesis_firehose"
  name        = "${var.project}-firehose-dev"
  environment = local.env
  bucket_arn  = "arn:aws:s3:::${var.project}-raw-dev"
}

module "observability" {
  source             = "../../modules/observability"
  name               = "${var.project}-mwaa-dev"
  environment        = local.env
  log_retention_days = 14
}

module "iam_dev" {
  source            = "../../modules/iam"
  environment       = local.env
  role_name         = "github-deploy-dev"
  oidc_provider_arn = var.oidc_provider_arn
  repo              = var.repo
  ref               = "refs/heads/main"
  region            = var.region
  account_id        = var.account_id
  resource_prefix   = var.project
}

output "dags_bucket" {
  value = module.mwaa.dags_bucket
}
