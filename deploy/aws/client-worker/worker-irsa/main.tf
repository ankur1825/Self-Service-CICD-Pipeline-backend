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
  default = "horizon-cloud-migration-worker"
}

variable "cluster_oidc_provider_arn" {
  type        = string
  description = "ARN of the client EKS cluster IAM OIDC provider."
}

variable "cluster_oidc_issuer" {
  type        = string
  description = "EKS OIDC issuer without the https:// prefix."
}

variable "kubernetes_namespace" {
  type    = string
  default = "horizon-cloud-migration-dev"
}

variable "kubernetes_service_account" {
  type    = string
  default = "horizon-cloud-migration-backend-worker"
}

variable "target_execution_role_arn" {
  type        = string
  description = "Client target-account role assumed by the execution worker."
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.cluster_oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.cluster_oidc_issuer}:sub"
      values   = ["system:serviceaccount:${var.kubernetes_namespace}:${var.kubernetes_service_account}"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name                 = var.name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = merge(var.tags, { "HorizonComponent" = "cloud-migration-worker" })
}

data "aws_iam_policy_document" "assume_target" {
  statement {
    sid       = "AssumeClientMigrationExecutionRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [var.target_execution_role_arn]
  }
}

resource "aws_iam_role_policy" "assume_target" {
  name   = "assume-client-migration-execution-role"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.assume_target.json
}

output "worker_role_arn" {
  value = aws_iam_role.worker.arn
}

output "helm_service_account_annotations" {
  value = {
    "eks.amazonaws.com/role-arn" = aws_iam_role.worker.arn
  }
}
