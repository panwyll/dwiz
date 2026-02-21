terraform {
  backend "s3" {
    bucket         = "org-wizard-tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "org-wizard-tf-lock"
    encrypt        = true
  }
}
