terraform {
  backend "s3" {
    bucket         = "org-wizard-tf-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "org-wizard-tf-lock"
    encrypt        = true
  }
}
