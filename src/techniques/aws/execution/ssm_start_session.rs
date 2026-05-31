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
  name = "stratus-red-team-ssm-sess-${random_string.suffix.result}"
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
  name = "stratus-red-team-ssm-sess-${random_string.suffix.result}"
  role = aws_iam_role.ssm_role.name
}

resource "aws_instance" "target" {
  ami                  = data.aws_ami.amazon_linux_2.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ssm_profile.name

  tags = {
    Name = "stratus-red-team-ssm-start-session-${random_string.suffix.result}"
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

    let resp = aws
        .ssm
        .start_session()
        .target(instance_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let session_id = resp.session_id().unwrap_or("unknown");
    println!(
        "Started SSM session on instance {}. Session ID: {}",
        instance_id, session_id
    );

    // Immediately terminate the session — we only need the CloudTrail event
    let result = aws
        .ssm
        .terminate_session()
        .session_id(session_id)
        .send()
        .await;

    match result {
        Ok(_) => println!("Terminated SSM session: {}", session_id),
        Err(e) => println!("Note: could not terminate session {}: {}", session_id, e),
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.execution.ssm-start-session",
        friendly_name: "Execute Commands on EC2 via SSM StartSession",
        description: "Uses the SSM StartSession API to initiate an interactive session on an EC2 instance, then immediately terminates it. Generates the CloudTrail StartSession event that detectors monitor for unauthorized remote access.",
        detection: "CloudTrail: StartSession via SSM.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
