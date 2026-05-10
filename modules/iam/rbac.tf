# ============================================================
# IAM RBAC Module - Least Privilege, Service Control Policies
# Implements: Developer, DevOps, ReadOnly, and Admin roles
# ============================================================

locals {
  name_prefix = "${var.environment}-${var.project_name}"
  common_tags = merge(var.tags, {
    Module      = "iam-rbac"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# ─── Permission Boundaries ────────────────────────────────
# Prevents privilege escalation - all roles are bounded
resource "aws_iam_policy" "permission_boundary" {
  name        = "${local.name_prefix}-permission-boundary"
  description = "Permission boundary for all project IAM roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowProjectServices"
        Effect = "Allow"
        Action = [
          "ec2:*", "eks:*", "ecr:*", "s3:*",
          "cloudwatch:*", "logs:*", "iam:Get*",
          "iam:List*", "iam:PassRole", "sts:AssumeRole",
          "secretsmanager:GetSecretValue",
          "kms:Decrypt", "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
        }
      },
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:CreateAccessKey",
          "iam:UpdateLoginProfile"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyRootAccountActions"
        Effect = "Deny"
        NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice"]
        Resource = "arn:aws:iam::*:root"
      }
    ]
  })
  tags = local.common_tags
}

# ─── Developer Role ───────────────────────────────────────
resource "aws_iam_role" "developer" {
  name                 = "${local.name_prefix}-developer-role"
  max_session_duration = 28800  # 8 hours
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "28800" }
        }
      },
      {
        Effect    = "Allow"
        Principal = { Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/${var.saml_provider_name}" }
        Action    = "sts:AssumeRoleWithSAML"
        Condition = {
          StringEquals = { "SAML:aud" = "https://signin.aws.amazon.com/saml" }
        }
      }
    ]
  })
  tags = merge(local.common_tags, { Role = "developer" })
}

resource "aws_iam_role_policy" "developer" {
  name = "${local.name_prefix}-developer-policy"
  role = aws_iam_role.developer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAccess"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "ecr:ResourceTag/Environment" = var.environment }
        }
      },
      {
        Sid    = "EKSReadAccess"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:AccessKubernetesApi"
        ]
        Resource = "arn:aws:eks:*:${data.aws_caller_identity.current.account_id}:cluster/${local.name_prefix}-*"
      },
      {
        Sid    = "S3ProjectAccess"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-*",
          "arn:aws:s3:::${local.name_prefix}-*/*"
        ]
      },
      {
        Sid    = "CloudWatchLogsRead"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${var.environment}/*"
      },
      {
        Sid    = "DenyProductionDestructive"
        Effect = "Deny"
        Action = [
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "eks:DeleteCluster",
          "s3:DeleteBucket"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Environment" = "prod" }
        }
      }
    ]
  })
}

# ─── DevOps Engineer Role ─────────────────────────────────
resource "aws_iam_role" "devops_engineer" {
  name                 = "${local.name_prefix}-devops-engineer-role"
  max_session_duration = 14400  # 4 hours
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
  tags = merge(local.common_tags, { Role = "devops-engineer" })
}

resource "aws_iam_role_policy_attachment" "devops_managed_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchFullAccess"
  ])
  role       = aws_iam_role.devops_engineer.name
  policy_arn = each.value
}

# ─── Read-Only Role (for auditors, external teams) ────────
resource "aws_iam_role" "read_only" {
  name                 = "${local.name_prefix}-readonly-role"
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.trusted_account_ids }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
        StringEquals = { "sts:ExternalId" = var.external_id }
      }
    }]
  })
  tags = merge(local.common_tags, { Role = "readonly" })
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.read_only.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ─── GitHub Actions OIDC Role ─────────────────────────────
resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
  tags            = local.common_tags
}

resource "aws_iam_role" "github_actions" {
  name                 = "${local.name_prefix}-github-actions-role"
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_actions.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.project_name}:ref:refs/heads/main",
            "repo:${var.github_org}/${var.project_name}:environment:*"
          ]
        }
      }
    }]
  })
  tags = merge(local.common_tags, { Role = "github-actions" })
}

resource "aws_iam_role_policy" "github_actions_terraform" {
  name = "${local.name_prefix}-github-actions-terraform"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
          "s3:ListBucket", "s3:GetBucketVersioning"
        ]
        Resource = [
          "arn:aws:s3:::${var.state_bucket}",
          "arn:aws:s3:::${var.state_bucket}/*"
        ]
      },
      {
        Sid    = "TerraformLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem", "dynamodb:PutItem",
          "dynamodb:DeleteItem", "dynamodb:DescribeTable"
        ]
        Resource = "arn:aws:dynamodb:*:${data.aws_caller_identity.current.account_id}:table/${var.lock_table}"
      },
      {
        Sid    = "InfrastructureProvision"
        Effect = "Allow"
        Action = [
          "ec2:*", "eks:*", "iam:*", "kms:*",
          "s3:*", "ecr:*", "logs:*", "cloudwatch:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.allowed_regions }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
