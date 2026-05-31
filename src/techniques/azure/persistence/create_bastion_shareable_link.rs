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

resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-${random_string.suffix.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "vm_subnet" {
  name                 = "vm-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_public_ip" "bastion_pip" {
  name                = "bastion-pip-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  name                = "bastion-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"
  shareable_link_enabled = true

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion_pip.id
  }
}

resource "azurerm_network_interface" "nic" {
  name                = "nic-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "vm-${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = "Standard_B1s"
  admin_username                  = "adminuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  network_interface_ids = [azurerm_network_interface.nic.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

output "resource_group_name" { value = azurerm_resource_group.rg.name }
output "bastion_name"        { value = azurerm_bastion_host.bastion.name }
output "vm_id"               { value = azurerm_linux_virtual_machine.vm.id }
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
    let bastion_name = outputs
        .get("bastion_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: bastion_name"))?;
    let vm_id = outputs
        .get("vm_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: vm_id"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Network/bastionHosts/{}/createShareableLinks?api-version=2023-06-01",
        subscription_id, rg, bastion_name
    );

    let body = serde_json::json!({
        "vms": [{
            "vm": {
                "id": vm_id
            }
        }]
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        println!(
            "Created Bastion shareable link for VM '{}' via bastion '{}/{}' — attacker can now access VM without credentials",
            vm_id, rg, bastion_name
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to create Bastion shareable link ({}): {}",
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
    let bastion_name = outputs
        .get("bastion_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: bastion_name"))?;
    let vm_id = outputs
        .get("vm_id")
        .ok_or_else(|| anyhow::anyhow!("Missing output: vm_id"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Network/bastionHosts/{}/deleteShareableLinks?api-version=2023-06-01",
        subscription_id, rg, bastion_name
    );

    let body = serde_json::json!({
        "vms": [{
            "vm": {
                "id": vm_id
            }
        }]
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 || resp.status().as_u16() == 200 {
        println!(
            "Deleted Bastion shareable link for VM '{}' via bastion '{}/{}'",
            vm_id, rg, bastion_name
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to delete Bastion shareable link ({}): {}",
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
        id: "azure.persistence.create-bastion-shareable-link",
        friendly_name: "Create Azure Bastion Shareable Link for Persistence",
        description: "Creates an Azure Bastion shareable link for a VM, allowing an attacker to access the VM through a browser without credentials, establishing persistent access.",
        detection: "Azure Activity Log: Microsoft.Network/bastionHosts/createShareableLinks/action. Defender for Cloud: Unusual Bastion access alert.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
