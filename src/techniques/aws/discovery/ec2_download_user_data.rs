use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use aws_sdk_ec2::types::InstanceAttributeName;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "target" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  user_data     = <<-EOT
    #!/bin/bash
    # Stratus Red Team test instance
    DB_PASSWORD=supersecret-db-password-${random_string.suffix.result}
    API_KEY=AKIAIOSFODNN7EXAMPLE-fake-api-key
    export DB_PASSWORD API_KEY
  EOT

  tags = { StratusRedTeam = "true", Name = "stratus-red-team-${random_string.suffix.result}" }
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
        .describe_instance_attribute()
        .instance_id(instance_id)
        .attribute(InstanceAttributeName::UserData)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let encoded = resp
        .user_data()
        .and_then(|ud| ud.value())
        .unwrap_or("");

    if encoded.is_empty() {
        println!("Instance {} has no user data set.", instance_id);
    } else {
        let decoded = BASE64
            .decode(encoded)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|_| format!("<failed to decode base64: {}>", encoded));
        println!(
            "Downloaded user data for instance {}:\n{}",
            instance_id, decoded
        );
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.discovery.ec2-download-user-data",
        friendly_name: "Download EC2 Instance User Data",
        description: "Retrieves the user data of an EC2 instance using DescribeInstanceAttribute. User data scripts frequently contain secrets, credentials, or configuration details that can be leveraged by an attacker for lateral movement or privilege escalation.",
        detection: "CloudTrail: DescribeInstanceAttribute with attribute=userData.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Discovery],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
