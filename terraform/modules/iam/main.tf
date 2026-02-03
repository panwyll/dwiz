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
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketTagging",
          "s3:GetBucketTagging",
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.resource_prefix}-*-${var.environment}",
          "arn:aws:s3:::${var.resource_prefix}-*-${var.environment}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "mwaa:CreateEnvironment",
          "mwaa:UpdateEnvironment",
          "mwaa:DeleteEnvironment",
          "mwaa:GetEnvironment"
        ]
        Resource = [
          "arn:aws:mwaa:${var.region}:${var.account_id}:environment/${var.resource_prefix}-mwaa-${var.environment}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:CreateCluster",
          "ecs:DescribeClusters",
          "ecs:DeleteCluster",
          "ecs:TagResource",
          "ecs:UntagResource"
        ]
        Resource = [
          "arn:aws:ecs:${var.region}:${var.account_id}:cluster/${var.resource_prefix}-jobs-${var.environment}-cluster"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "firehose:CreateDeliveryStream",
          "firehose:UpdateDestination",
          "firehose:DescribeDeliveryStream",
          "firehose:DeleteDeliveryStream"
        ]
        Resource = [
          "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/${var.resource_prefix}-firehose-${var.environment}-firehose"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:PutRetentionPolicy",
          "logs:DescribeLogGroups",
          "logs:DeleteLogGroup"
        ]
        Resource = [
          "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/mwaa/${var.resource_prefix}-mwaa-${var.environment}",
          "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/mwaa/${var.resource_prefix}-mwaa-${var.environment}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListRolePolicies",
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::${var.account_id}:role/${var.resource_prefix}-*-${var.environment}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:CreateSubnet",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = ["Environment"]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DeleteVpc",
          "ec2:DeleteSubnet",
          "ec2:DeleteSecurityGroup",
          "ec2:ModifyVpcAttribute",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.github.arn
}
