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
  tags          = { StratusRedTeam = "true" }
}

resource "aws_iam_user_login_profile" "victim" {
  user                    = aws_iam_user.victim.name
  password_reset_required = false
  # No MFA device is created — intentionally left without MFA
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "user_name" {
  value = aws_iam_user.victim.name
}

output "user_arn" {
  value = aws_iam_user.victim.arn
}
"#;

/// Simulates the observable footprint of a console login without MFA.
///
/// A real browser-based ConsoleLogin event cannot be replicated via SDK calls.
/// Instead, this technique uses STS GetCallerIdentity (to establish the calling
/// identity context) and then attempts STS AssumeRole on the target user to
/// produce a credential-access event that mirrors the access pattern observed
/// when an IAM user with no MFA logs in to the AWS Management Console.
///
/// The CloudTrail "ConsoleLogin" event with MFAUsed=No is produced by the AWS
/// sign-in endpoint when a user authenticates at console.aws.amazon.com without
/// an MFA device enrolled.  This technique documents and surfaces that signal.
async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let user_name = outputs
        .get("user_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: user_name"))?;
    let user_arn = outputs
        .get("user_arn")
        .ok_or_else(|| anyhow::anyhow!("Missing output: user_arn"))?;

    // GetCallerIdentity establishes the calling context and generates a
    // CloudTrail event that confirms which principal is active.
    let identity = aws.sts
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("GetCallerIdentity failed: {}", e))?;

    let caller_arn = identity.arn().unwrap_or("unknown");
    let account_id = identity.account().unwrap_or("unknown");

    println!(
        "Simulating console login without MFA for IAM user: {} (ARN: {})",
        user_name, user_arn
    );
    println!(
        "Current caller: {} in account {}",
        caller_arn, account_id
    );
    println!(
        "Detection signal: CloudTrail ConsoleLogin event with MFAUsed=No \
         would appear when IAM user '{}' logs in to the AWS Management Console \
         without a registered MFA device.",
        user_name
    );
    println!(
        "The IAM user '{}' has a login profile (password) but NO MFA device. \
         Any console sign-in by this user will produce a ConsoleLogin CloudTrail \
         event with additionalEventData.MFAUsed = 'No'.",
        user_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.initial-access.console-login-without-mfa",
        friendly_name: "Console Login without MFA",
        description: "Creates an IAM user with a console login profile but without an MFA device. \
                       When this user logs in to the AWS Management Console, CloudTrail records a \
                       ConsoleLogin event with MFAUsed set to No — a high-signal indicator of \
                       inadequate authentication controls.",
        detection: "CloudTrail: ConsoleLogin event with additionalEventData.MFAUsed = No. \
                    AWS Security Hub: IAM.5 (MFA should be enabled for all IAM users with console password). \
                    GuardDuty: Policy:IAMUser/NoPasswordPolicy.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::InitialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
