use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let identities_resp = aws
        .ses
        .list_email_identities()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("ListEmailIdentities: {}", e))?;

    println!(
        "ListEmailIdentities: found {} verified email identities",
        identities_resp.email_identities().len()
    );
    for identity in identities_resp.email_identities() {
        println!(
            "  - {} (type: {:?})",
            identity.identity_name().unwrap_or("<unknown>"),
            identity.identity_type()
        );
    }

    let account_resp = aws
        .ses
        .get_account()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("GetAccount: {}", e))?;

    let send_quota = account_resp.send_quota();
    if let Some(quota) = send_quota {
        println!(
            "GetAccount: max 24h send={}, max send rate={}/s, sent last 24h={}",
            quota.max24_hour_send(),
            quota.max_send_rate(),
            quota.sent_last24_hours()
        );
    } else {
        println!("GetAccount: no send quota information returned");
    }

    if account_resp.enforcement_status().is_some() {
        println!(
            "GetAccount: enforcement status = {:?}",
            account_resp.enforcement_status()
        );
    }

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.discovery.ses-enumerate",
        friendly_name: "Enumerate SES Email Identities",
        description: "Enumerates verified SES email identities and retrieves account-level sending quota information. An attacker who has compromised AWS credentials may enumerate SES to identify sending identities for phishing or spam campaigns.",
        detection: "CloudTrail: ListEmailIdentities, GetAccount in SES (sesv2:ListEmailIdentities, sesv2:GetAccount).",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Discovery],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
