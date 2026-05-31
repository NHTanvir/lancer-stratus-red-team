use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "aws_key_pair" "stratus" {
  key_name   = "stratus-red-team-${random_string.suffix.result}"
  public_key = tls_private_key.stratus.public_key_openssh
}

resource "tls_private_key" "stratus" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "target" {
  ami           = data.aws_ami.windows.id
  instance_type = "t3.small"
  key_name      = aws_key_pair.stratus.key_name

  tags = { StratusRedTeam = "true", Name = "stratus-red-team-target" }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
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
        .ec2
        .get_password_data()
        .instance_id(instance_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let password_data = resp.password_data().unwrap_or("");
    if password_data.is_empty() {
        println!(
            "Retrieved password data for instance {} (empty — Windows may still be initializing)",
            instance_id
        );
    } else {
        println!(
            "Retrieved encrypted password data for instance {}:\n{}",
            instance_id, password_data
        );
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.credential-access.ec2-get-password-data",
        friendly_name: "Retrieve EC2 Password Data",
        description: "Retrieves the encrypted administrator password for a Windows EC2 instance using GetPasswordData. An attacker with the EC2 key pair private key can decrypt this to obtain the Windows administrator password.",
        detection: "CloudTrail: GetPasswordData.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
