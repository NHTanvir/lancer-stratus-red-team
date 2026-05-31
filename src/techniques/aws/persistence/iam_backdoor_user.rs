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

  tags = {
    StratusRedTeam = "true"
  }
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

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    let result = aws.iam
        .create_access_key()
        .user_name(user_name)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(key) = result.access_key() {
        println!(
            "Created backdoor access key: AccessKeyId={} for user={}",
            key.access_key_id(),
            key.user_name()
        );
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = outputs.get("user_name").ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;

    let list_result = aws.iam
        .list_access_keys()
        .user_name(user_name)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    for key_meta in list_result.access_key_metadata() {
        let key_id = key_meta.access_key_id().unwrap_or("");
        let del = aws.iam
            .delete_access_key()
            .user_name(user_name)
            .access_key_id(key_id)
            .send()
            .await;

        match del {
            Err(e) => {
                let msg = format!("{}", e);
                if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                    // ignore
                } else {
                    return Err(anyhow::anyhow!("{}", e));
                }
            }
            Ok(_) => {
                println!("Deleted access key: {}", key_id);
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
        id: "aws.persistence.iam-backdoor-user",
        friendly_name: "Backdoor IAM User",
        description: "Creates an access key on an existing IAM user to establish a backdoor for persistent access.",
        detection: "CloudTrail: CreateAccessKey. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
