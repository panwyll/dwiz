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
          "s3:*",
          "mwaa:*",
          "ecs:*",
          "firehose:*",
          "logs:*",
          "iam:PassRole"
        ]
        Resource = "*"
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
