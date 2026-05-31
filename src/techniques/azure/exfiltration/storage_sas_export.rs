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

resource "azurerm_storage_container" "container" {
  name                  = "exfil-container"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "blob" {
  name                   = "sensitive-data.txt"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.container.name
  type                   = "Block"
  source_content         = "This is sensitive data for exfiltration simulation."
}

output "resource_group_name"  { value = azurerm_resource_group.rg.name }
output "storage_account_name" { value = azurerm_storage_account.sa.name }
output "container_name"       { value = azurerm_storage_container.container.name }
output "blob_name"            { value = azurerm_storage_blob.blob.name }
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
    let container = outputs
        .get("container_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: container_name"))?;
    let blob = outputs
        .get("blob_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: blob_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // List storage account keys to generate SAS
    let keys_url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Storage/storageAccounts/{}/listKeys?api-version=2023-01-01",
        subscription_id, rg, sa
    );
    let keys_resp: serde_json::Value = http
        .post(&keys_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await?
        .json()
        .await?;

    let account_key = keys_resp["keys"][0]["value"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Could not retrieve storage account key"))?
        .to_string();

    println!(
        "Retrieved storage account key for '{}' — would generate SAS token for blob '{}/{}/{}'",
        sa, container, blob, account_key.chars().take(8).collect::<String>()
    );
    println!(
        "SAS URL would allow unauthenticated read access to blob: https://{}.blob.core.windows.net/{}/{}?<sas-token>",
        sa, container, blob
    );
    println!(
        "Note: Full SAS generation requires HMAC-SHA256 signing of the canonicalized string with the account key. \
         In a real attack, the attacker would use the Azure Storage SDK or az storage blob generate-sas CLI."
    );

    Ok(())
}

fn detonate(
    outputs: HashMap<String, String>,
    providers: Arc<CloudProviders>,
) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "azure.exfiltration.storage-sas-export",
        friendly_name: "Generate SAS Token for Azure Blob Exfiltration",
        description: "Retrieves storage account keys and simulates generating a SAS token for a blob, which would allow unauthenticated read access to sensitive data.",
        detection: "Azure Activity Log: Microsoft.Storage/storageAccounts/listKeys/action. Defender for Cloud: Unusual storage access pattern alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
