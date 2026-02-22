terraform {
  backend "s3" {
    bucket         = "org-dwiz-tf-state"
    key            = "test/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "org-dwiz-tf-lock"
    encrypt        = true
  }
}
