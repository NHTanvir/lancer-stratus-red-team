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

resource "azurerm_storage_encryption_scope" "scope" {
  name               = "original-scope"
  storage_account_id = azurerm_storage_account.sa.id
  source             = "Microsoft.Storage"
}

resource "azurerm_storage_container" "container" {
  name                  = "ransomware-test"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "blobs" {
  count                  = 3
  name                   = "file-${count.index}.txt"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.container.name
  type                   = "Block"
  source_content         = "Sensitive data ${count.index}"
}

output "resource_group_name"  { value = azurerm_resource_group.rg.name }
output "storage_account_name" { value = azurerm_storage_account.sa.name }
output "encryption_scope"     { value = azurerm_storage_encryption_scope.scope.name }
"#;

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
    let sa = outputs
        .get("storage_account_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: storage_account_name"))?;
    let scope = outputs
        .get("encryption_scope")
        .ok_or_else(|| anyhow::anyhow!("Missing output: encryption_scope"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // Disable the encryption scope so existing blobs cannot be decrypted
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}/encryptionScopes/{}?api-version=2023-01-01",
        subscription_id, rg, sa, scope
    );
    let body = serde_json::json!({
        "properties": {
            "state": "Disabled"
        }
    });
    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!(
            "Disabled encryption scope '{}' on storage account '{}' — blobs using this scope are now inaccessible (simulated ransomware)",
            scope, sa
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to disable encryption scope ({}): {}",
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
    let scope = outputs
        .get("encryption_scope")
        .ok_or_else(|| anyhow::anyhow!("Missing output: encryption_scope"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}/encryptionScopes/{}?api-version=2023-01-01",
        subscription_id, rg, sa, scope
    );
    let body = serde_json::json!({
        "properties": {
            "state": "Enabled"
        }
    });
    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!("Re-enabled encryption scope '{}' on storage account '{}'", scope, sa);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to re-enable encryption scope ({}): {}",
            status,
            text
        );
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
        id: "azure.impact.blob-ransomware-client-encryption-scope",
        friendly_name: "Simulate Ransomware by Disabling Azure Storage Encryption Scope",
        description: "Disables an Azure Storage encryption scope, rendering all blobs encrypted with that scope unreadable — simulating a ransomware attack on Azure Blob Storage.",
        detection: "Azure Activity Log: Microsoft.Storage/storageAccounts/encryptionScopes/write. Defender for Cloud: Unusual storage modification alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: true,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
