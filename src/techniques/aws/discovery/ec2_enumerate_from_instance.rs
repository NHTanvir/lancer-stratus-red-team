use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

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

resource "aws_iam_role" "instance" {
  name = "stratus-red-team-enum-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { StratusRedTeam = "true" }
}

resource "aws_iam_role_policy" "instance" {
  name = "stratus-red-team-enum-policy-${random_string.suffix.result}"
  role = aws_iam_role.instance.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "s3:List*", "s3:GetBucketLocation", "iam:List*", "iam:Get*"]
        Resource = "*"
      }
    ]
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
  tags                 = { StratusRedTeam = "true", Name = "stratus-red-team-${random_string.suffix.result}" }
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

    // Simulate broad enumeration as an attacker operating from inside an EC2 instance.

    let instances_resp = aws
        .ec2
        .describe_instances()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("DescribeInstances: {}", e))?;
    let instance_count: usize = instances_resp
        .reservations()
        .iter()
        .map(|r| r.instances().len())
        .sum();
    println!("DescribeInstances: found {} instances", instance_count);

    let sg_resp = aws
        .ec2
        .describe_security_groups()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("DescribeSecurityGroups: {}", e))?;
    println!(
        "DescribeSecurityGroups: found {} security groups",
        sg_resp.security_groups().len()
    );

    let vpc_resp = aws
        .ec2
        .describe_vpcs()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("DescribeVpcs: {}", e))?;
    println!("DescribeVpcs: found {} VPCs", vpc_resp.vpcs().len());

    let subnet_resp = aws
        .ec2
        .describe_subnets()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("DescribeSubnets: {}", e))?;
    println!(
        "DescribeSubnets: found {} subnets",
        subnet_resp.subnets().len()
    );

    let buckets_resp = aws
        .s3
        .list_buckets()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("ListBuckets: {}", e))?;
    println!(
        "ListBuckets: found {} S3 buckets",
        buckets_resp.buckets().len()
    );

    println!(
        "Completed enumeration from instance {} — simulating attacker recon from compromised EC2",
        instance_id
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.discovery.ec2-enumerate-from-instance",
        friendly_name: "Enumerate AWS Resources from an EC2 Instance",
        description: "Performs broad AWS resource enumeration (EC2, VPC, S3) simulating an attacker who has compromised an EC2 instance and is using its IAM instance profile to map the environment for lateral movement or data exfiltration.",
        detection: "Multiple Describe* and List* CloudTrail events originating from an EC2 instance ARN in a short time window.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Discovery],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
