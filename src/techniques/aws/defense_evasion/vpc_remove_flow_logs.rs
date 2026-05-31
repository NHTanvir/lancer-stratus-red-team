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

resource "aws_vpc" "stratus" {
  cidr_block = "10.0.0.0/16"
  tags       = { StratusRedTeam = "true" }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/stratus-red-team/vpc-flow-logs-${random_string.suffix.result}"
  retention_in_days = 1
}

resource "aws_iam_role" "flow_logs" {
  name = "stratus-red-team-flow-logs-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_flow_log" "stratus" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.stratus.id
}

output "vpc_id" {
  value = aws_vpc.stratus.id
}

output "flow_log_id" {
  value = aws_flow_log.stratus.id
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let flow_log_id = outputs
        .get("flow_log_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: flow_log_id"))?;

    aws.ec2
        .delete_flow_logs()
        .flow_log_ids(flow_log_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Deleted VPC flow log: {}", flow_log_id);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.defense-evasion.vpc-remove-flow-logs",
        friendly_name: "Remove VPC Flow Logs",
        description: "Deletes VPC flow logs to stop network traffic monitoring for a VPC. This impairs the ability to detect lateral movement, data exfiltration, and other network-based threats.",
        detection: "CloudTrail: DeleteFlowLogs.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
