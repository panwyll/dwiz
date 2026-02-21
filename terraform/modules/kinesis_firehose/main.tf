terraform {
  required_version = ">= 1.5"
}

resource "aws_kinesis_firehose_delivery_stream" "this" {
  name        = "${var.name}-firehose"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = var.bucket_arn
  }
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role" "firehose" {
  name               = "${var.name}-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
  tags = {
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "firehose" {
  name = "${var.name}-firehose-policy"
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:ListBucket"]
        Resource = [var.bucket_arn, "${var.bucket_arn}/*"]
      }
    ]
  })
}

output "firehose_name" {
  value = aws_kinesis_firehose_delivery_stream.this.name
}
