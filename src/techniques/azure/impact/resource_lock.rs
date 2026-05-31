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
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
    random   = { source = "hashicorp/random",  version = "~> 3.0" }
  }
}

provider "azurerm" { features {} }

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-${random_string.suffix.result}"
  location = "East US"
}

resource "azurerm_storage_account" "sa" {
  name                     = "stratusrt${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

output "resource_group_name" { value = azurerm_resource_group.rg.name }
output "subscription_id"    { value = "" }
"#;

const LOCK_NAME: &str = "stratus-red-team-lock";

async fn azure_token(tenant_id: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let http = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://management.azure.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let resp: serde_json::Value = http
        .post(&token_url)
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
    let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_SUBSCRIPTION_ID env var not set"))?;
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;

    let rg = outputs
        .get("resource_group_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: resource_group_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Authorization/locks/{}?api-version=2016-09-01",
        subscription_id, rg, LOCK_NAME
    );

    let body = serde_json::json!({
        "properties": {
            "level": "CanNotDelete",
            "notes": "Stratus Red Team: CanNotDelete lock simulating impact technique T1485"
        }
    });

    let resp = http
        .put(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 201 {
        println!(
            "Created CanNotDelete lock '{}' on resource group '{}' — resources cannot be deleted",
            LOCK_NAME, rg
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create resource lock ({}): {}", status, text);
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
    let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_SUBSCRIPTION_ID env var not set"))?;
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;

    let rg = outputs
        .get("resource_group_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: resource_group_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Authorization/locks/{}?api-version=2016-09-01",
        subscription_id, rg, LOCK_NAME
    );

    let resp = http.delete(&url).bearer_auth(&token).send().await?;

    if resp.status().is_success() || resp.status().as_u16() == 204 {
        println!("Deleted resource lock '{}' from resource group '{}'", LOCK_NAME, rg);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to delete resource lock ({}): {}", status, text);
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
        id: "azure.impact.resource-lock",
        friendly_name: "Create Azure Resource Lock to Prevent Deletion",
        description: "Creates a CanNotDelete management lock on an Azure resource group, preventing resource deletion and simulating an impact/disruption technique.",
        detection: "Azure Activity Log: Microsoft.Authorization/locks/write. Unusual lock creation by non-privileged identity.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
