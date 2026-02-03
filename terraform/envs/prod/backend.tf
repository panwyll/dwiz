terraform {
  backend "s3" {
    bucket         = "org-genie-tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "org-genie-tf-lock"
    encrypt        = true
  }
}
