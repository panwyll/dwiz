terraform {
  required_version = ">= 1.6"
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-cluster"
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags = {
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}
