terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type    = string
  default = "HorizonCloudMigrationExecutionRole"
}

variable "worker_role_arn" {
  type        = string
  description = "ARN output by the worker-irsa module."
}

variable "external_id" {
  type        = string
  description = "Client-generated secret external ID. Store it in a Kubernetes Secret, never in Helm values."
  sensitive   = true
}

variable "execution_enabled" {
  type        = bool
  description = "Adds MGN mutation permissions only after the client approves execution."
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.worker_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "target" {
  name                 = var.name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = merge(var.tags, { "HorizonComponent" = "cloud-migration-target" })
}

locals {
  read_actions = [
    "mgn:DescribeJobs",
    "mgn:DescribeSourceServers",
  ]
  execution_actions = [
    "mgn:ChangeServerLifeCycleState",
    "mgn:FinalizeCutover",
    "mgn:StartCutover",
    "mgn:StartTest",
    "mgn:TerminateTargetInstances",
  ]
}

data "aws_iam_policy_document" "permissions" {
  statement {
    sid       = "ReadMigrationState"
    effect    = "Allow"
    actions   = local.read_actions
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = var.execution_enabled ? [1] : []
    content {
      sid       = "ExecuteApprovedMigrationActions"
      effect    = "Allow"
      actions   = local.execution_actions
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "permissions" {
  name   = "horizon-cloud-migration-execution"
  role   = aws_iam_role.target.id
  policy = data.aws_iam_policy_document.permissions.json
}

output "target_execution_role_arn" {
  value = aws_iam_role.target.arn
}
