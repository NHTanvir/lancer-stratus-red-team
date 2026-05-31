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

resource "aws_iam_role" "ssm_role" {
  name = "stratus-red-team-ssm-cmd-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name = "stratus-red-team-ssm-cmd-${random_string.suffix.result}"
  role = aws_iam_role.ssm_role.name
}

resource "aws_instance" "target" {
  ami                  = data.aws_ami.amazon_linux_2.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ssm_profile.name

  tags = {
    Name = "stratus-red-team-ssm-send-command-${random_string.suffix.result}"
  }
}

output "instance_id" {
  value = aws_instance.target.id
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let instance_id = outputs
        .get("instance_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: instance_id"))?;

    let mut params = HashMap::new();
    params.insert(
        "commands".to_string(),
        vec!["id && whoami && cat /etc/passwd".to_string()],
    );

    let resp = aws
        .ssm
        .send_command()
        .instance_ids(instance_id)
        .document_name("AWS-RunShellScript")
        .set_parameters(Some(params))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let command_id = resp
        .command()
        .and_then(|c| c.command_id())
        .unwrap_or("unknown");

    println!(
        "Sent SSM RunShellScript command to instance {}. Command ID: {}",
        instance_id, command_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.execution.ssm-send-command",
        friendly_name: "Execute Commands on EC2 via SSM SendCommand",
        description: "Uses the SSM SendCommand API to remotely execute a shell script on an EC2 instance using the AWS-RunShellScript document. Simulates an attacker running arbitrary commands on managed instances.",
        detection: "CloudTrail: SendCommand with AWS-RunShellScript document.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
