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

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "ssh" {
  name        = "stratus-red-team-ec2ic-sg-${random_string.suffix.result}"
  description = "Allow SSH inbound"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "target" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.public.ids[0]
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  associate_public_ip_address = true

  tags = {
    Name = "stratus-red-team-ec2-instance-connect-${random_string.suffix.result}"
  }
}

output "instance_id" {
  value = aws_instance.target.id
}
"#;

/// A static RSA public key for testing purposes.
/// In a real attack scenario this would be a freshly generated ephemeral key pair.
const TEST_SSH_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3km4yjqLKJt7e/\
W9oWWb7TDVQ6eHaHiJL6mR8FvlFT8GWPZ7TiUTDJk8R1eFOgaqP3fO0j/\
9CRHSNv4TbOPq6ZIiJd1bNkOhw4E8vJiLoI9Qe3Ehn3OxVn5Gl1uY8D4B\
FgH5gT2dLjR7Wv4MkZvH9Oi8cLa2pXqT3NkEnM+stratus-test-key";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let instance_id = outputs
        .get("instance_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: instance_id"))?;

    aws.ec2instanceconnect
        .send_ssh_public_key()
        .instance_id(instance_id)
        .instance_os_user("ec2-user")
        .ssh_public_key(TEST_SSH_PUBLIC_KEY)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Pushed SSH public key to instance {} via EC2 Instance Connect (ec2-user). Key expires in 60 seconds.",
        instance_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.lateral-movement.ec2-instance-connect",
        friendly_name: "Lateral Movement via EC2 Instance Connect",
        description: "Pushes a temporary SSH public key to an EC2 instance using EC2 Instance Connect. The key grants SSH access for 60 seconds — enough for an attacker to connect. This technique requires no long-term credentials on the instance.",
        detection: "CloudTrail: SendSSHPublicKey via EC2 Instance Connect.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::LateralMovement],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
