terraform {
  required_version = ">= 1.5"
}

resource "aws_s3_bucket" "dags" {
  bucket = var.dags_bucket
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role" "mwaa" {
  name               = "${var.name}-mwaa-role"
  assume_role_policy = data.aws_iam_policy_document.mwaa_assume.json
  tags = {
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "mwaa_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "mwaa" {
  name = "${var.name}-mwaa-policy"
  role = aws_iam_role.mwaa.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.dags.arn,
          "${aws_s3_bucket.dags.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_mwaa_environment" "this" {
  name               = var.name
  airflow_version    = var.airflow_version
  environment_class  = "mw1.small"
  dag_s3_path        = "dags"
  source_bucket_arn  = aws_s3_bucket.dags.arn
  execution_role_arn = aws_iam_role.mwaa.arn
  network_configuration {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.mwaa.id]
  }
  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "INFO"
    }
    scheduler_logs {
      enabled   = true
      log_level = "INFO"
    }
    task_logs {
      enabled   = true
      log_level = "INFO"
    }
  }
  tags = {
    Environment = var.environment
  }
}

resource "aws_security_group" "mwaa" {
  name        = "${var.name}-mwaa-sg"
  description = "MWAA security group"
  vpc_id      = var.vpc_id
  tags = {
    Environment = var.environment
  }
}

resource "aws_security_group_rule" "mwaa_ingress_self" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  self              = true
  security_group_id = aws_security_group.mwaa.id
}

resource "aws_security_group_rule" "mwaa_egress_https" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.mwaa.id
}

output "dags_bucket" {
  value = aws_s3_bucket.dags.bucket
}
