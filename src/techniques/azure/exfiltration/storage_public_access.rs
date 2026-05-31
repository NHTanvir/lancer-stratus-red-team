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
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "container" {
  name                  = "private-container"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

output "resource_group_name"  { value = azurerm_resource_group.rg.name }
output "storage_account_name" { value = azurerm_storage_account.sa.name }
output "container_name"       { value = azurerm_storage_container.container.name }
"#;

async fn azure_token(tenant_id: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let client = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://management.azure.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let resp: serde_json::Value = client
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
    let sa = outputs
        .get("storage_account_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: storage_account_name"))?;
    let container = outputs
        .get("container_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: container_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // Step 1: Enable public blob access on the storage account
    let sa_url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}?api-version=2023-01-01",
        subscription_id, rg, sa
    );
    let sa_body = serde_json::json!({
        "properties": {
            "allowBlobPublicAccess": true
        }
    });
    let sa_resp = http
        .patch(&sa_url)
        .bearer_auth(&token)
        .json(&sa_body)
        .send()
        .await?;
    if !sa_resp.status().is_success() {
        let status = sa_resp.status();
        let text = sa_resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to enable public blob access on storage account ({}): {}",
            status,
            text
        );
    }
    println!("Enabled public blob access on storage account {}", sa);

    // Step 2: Set container public access level to "blob"
    let container_url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}/blobServices/default/containers/{}?api-version=2023-01-01",
        subscription_id, rg, sa, container
    );
    let container_body = serde_json::json!({
        "properties": {
            "publicAccess": "Blob"
        }
    });
    let container_resp = http
        .patch(&container_url)
        .bearer_auth(&token)
        .json(&container_body)
        .send()
        .await?;
    if !container_resp.status().is_success() {
        let status = container_resp.status();
        let text = container_resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to set container public access level ({}): {}",
            status,
            text
        );
    }
    println!(
        "Set container '{}' in storage account '{}' to public blob access",
        container, sa
    );

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
    let sa = outputs
        .get("storage_account_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: storage_account_name"))?;
    let container = outputs
        .get("container_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: container_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // Restore container access to private
    let container_url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}/blobServices/default/containers/{}?api-version=2023-01-01",
        subscription_id, rg, sa, container
    );
    http.patch(&container_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "properties": { "publicAccess": "None" } }))
        .send()
        .await?;
    println!("Restored container '{}' to private access", container);

    // Disable public blob access on the storage account
    let sa_url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}?api-version=2023-01-01",
        subscription_id, rg, sa
    );
    http.patch(&sa_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "properties": { "allowBlobPublicAccess": false } }))
        .send()
        .await?;
    println!("Disabled public blob access on storage account {}", sa);

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
        id: "azure.exfiltration.storage-public-access",
        friendly_name: "Make Azure Blob Storage Publicly Accessible",
        description: "Enables public blob access on an Azure storage account and sets a container to public access level, allowing unauthenticated read of blob contents.",
        detection: "Azure Activity Log: Microsoft.Storage/storageAccounts/write, Microsoft.Storage/storageAccounts/blobServices/containers/write. Defender for Cloud: Storage account public access alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
