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

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "target" {
  name        = "stratus-red-team-sg-${random_string.suffix.result}"
  description = "Stratus Red Team test security group"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "stratus-red-team-sg-${random_string.suffix.result}"
  }
}

output "security_group_id" {
  value = aws_security_group.target.id
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let sg_id = outputs
        .get("security_group_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: security_group_id"))?;

    aws.ec2
        .authorize_security_group_ingress()
        .group_id(sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(22)
                .to_port(22)
                .ip_ranges(
                    aws_sdk_ec2::types::IpRange::builder()
                        .cidr_ip("0.0.0.0/0")
                        .description("Stratus Red Team - open SSH")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Opened port 22 (SSH) from 0.0.0.0/0 on security group: {}",
        sg_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let sg_id = outputs
        .get("security_group_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: security_group_id"))?;

    let result = aws
        .ec2
        .revoke_security_group_ingress()
        .group_id(sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(22)
                .to_port(22)
                .ip_ranges(
                    aws_sdk_ec2::types::IpRange::builder()
                        .cidr_ip("0.0.0.0/0")
                        .build(),
                )
                .build(),
        )
        .send()
        .await;

    match result {
        Ok(_) => println!("Revoked port 22 ingress from 0.0.0.0/0 on security group: {}", sg_id),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("InvalidPermission.NotFound") {
                println!("Rule already removed from security group: {}", sg_id);
            } else {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
    }

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.exfiltration.ec2-security-group-open-port-22-ingress",
        friendly_name: "Open Ingress Port 22 on a Security Group",
        description: "Adds an inbound rule to an EC2 security group allowing SSH (TCP port 22) from the internet (0.0.0.0/0). Simulates an attacker opening a backdoor into the environment for exfiltration or lateral movement.",
        detection: "CloudTrail: AuthorizeSecurityGroupIngress with port 22 from 0.0.0.0/0.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
