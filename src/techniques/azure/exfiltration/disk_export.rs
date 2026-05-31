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

resource "azurerm_managed_disk" "disk" {
  name                 = "disk-${random_string.suffix.result}"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1
}

output "resource_group_name" { value = azurerm_resource_group.rg.name }
output "disk_name"           { value = azurerm_managed_disk.disk.name }
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
    let disk = outputs
        .get("disk_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: disk_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let client = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Compute/disks/{}/beginGetAccess?api-version=2023-04-02",
        subscription_id, rg, disk
    );

    let body = serde_json::json!({
        "access": "Read",
        "durationInSeconds": 3600
    });

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        println!(
            "Generated SAS URI for disk {}/{} — disk is now publicly accessible for exfiltration",
            rg, disk
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to generate disk SAS URI ({}): {}", status, text);
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
    let disk = outputs
        .get("disk_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: disk_name"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let client = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Compute/disks/{}/endGetAccess?api-version=2023-04-02",
        subscription_id, rg, disk
    );

    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        println!("Revoked SAS access for disk {}/{}", rg, disk);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to revoke disk SAS access ({}): {}", status, text);
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
        id: "azure.exfiltration.disk-export",
        friendly_name: "Export Azure Managed Disk via SAS URI",
        description: "Generates a publicly accessible SAS URI for an Azure Managed Disk, allowing an attacker to download disk contents without authentication.",
        detection: "Azure Activity Log: Microsoft.Compute/disks/beginGetAccess/action. Defender for Cloud: Unusual disk export alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
