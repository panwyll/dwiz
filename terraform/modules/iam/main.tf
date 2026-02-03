terraform {
  required_version = ">= 1.6"
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.repo}:ref:${var.ref}"]
    }
  }
}

resource "aws_iam_role" "github" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.github_assume.json
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "github" {
  name = "${var.role_name}-policy"
  role = aws_iam_role.github.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject",
          "s3:DeleteObject",
          "mwaa:CreateEnvironment",
          "mwaa:UpdateEnvironment",
          "mwaa:DeleteEnvironment",
          "mwaa:GetEnvironment",
          "ecs:CreateCluster",
          "ecs:DescribeClusters",
          "ecs:DeleteCluster",
          "firehose:CreateDeliveryStream",
          "firehose:UpdateDestination",
          "firehose:DescribeDeliveryStream",
          "firehose:DeleteDeliveryStream",
          "logs:CreateLogGroup",
          "logs:PutRetentionPolicy",
          "logs:DescribeLogGroups",
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:s3:::${var.resource_prefix}-${var.environment}-*",
          "arn:aws:s3:::${var.resource_prefix}-${var.environment}-*/*",
          "arn:aws:mwaa:${var.region}:${var.account_id}:environment/${var.resource_prefix}-mwaa-${var.environment}",
          "arn:aws:ecs:${var.region}:${var.account_id}:cluster/${var.resource_prefix}-jobs-${var.environment}-cluster",
          "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${var.resource_prefix}-firehose-${var.environment}-firehose",
          "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/mwaa/${var.resource_prefix}-mwaa-${var.environment}"
        ]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      }
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.github.arn
}
