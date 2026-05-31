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
  name                  = "deletion-test"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "blobs" {
  count                  = 10
  name                   = "victim-file-${count.index}.txt"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.container.name
  type                   = "Block"
  source_content         = "Victim data ${count.index}"
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
    let http = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://storage.azure.com/.default"),
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
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;

    let sa = outputs
        .get("storage_account_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: storage_account_name"))?;
    let container = outputs
        .get("container_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: container_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // Delete each of the 10 test blobs individually
    for i in 0..10 {
        let blob_name = format!("victim-file-{}.txt", i);
        let url = format!(
            "https://{}.blob.core.windows.net/{}/{}",
            sa, container, blob_name
        );
        let resp = http
            .delete(&url)
            .bearer_auth(&token)
            .header("x-ms-version", "2023-01-03")
            .send()
            .await?;

        if resp.status().is_success() || resp.status().as_u16() == 202 || resp.status().as_u16() == 404 {
            println!("Deleted blob: {}", blob_name);
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            eprintln!("Warning: failed to delete {} ({}): {}", blob_name, status, text);
        }
    }

    println!(
        "Deleted 10 blobs individually from container '{}' in storage account '{}' — simulating ransomware data destruction",
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

inventory::submit! {
    AttackTechnique {
        id: "azure.impact.blob-ransomware-individual-file-deletion",
        friendly_name: "Simulate Ransomware by Deleting Azure Blobs Individually",
        description: "Deletes 10 Azure Blob Storage objects one-by-one, simulating the data destruction phase of a ransomware attack on Azure storage.",
        detection: "Azure Storage diagnostic logs: DeleteBlob operations. Defender for Cloud: Unusual deletion pattern alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
