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
  env = "prod"
}

module "network" {
  source          = "../../modules/network"
  name            = "genie-prod"
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

module "mwaa" {
  source            = "../../modules/mwaa"
  name              = "${var.project}-mwaa-prod"
  environment       = local.env
  airflow_version   = var.airflow_version
  dags_bucket       = "${var.project}-dags-prod"
  private_subnet_ids = module.network.private_subnet_ids
  vpc_id            = module.network.vpc_id
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
}

output "dags_bucket" {
  value = module.mwaa.dags_bucket
}
