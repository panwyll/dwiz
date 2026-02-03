terraform {
  required_version = ">= 1.6"
}

resource "aws_s3_bucket" "raw" {
  bucket = var.raw_bucket
  tags = {
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "curated" {
  bucket = var.curated_bucket
  tags = {
    Environment = var.environment
  }
}

output "raw_bucket" {
  value = aws_s3_bucket.raw.bucket
}

output "curated_bucket" {
  value = aws_s3_bucket.curated.bucket
}
