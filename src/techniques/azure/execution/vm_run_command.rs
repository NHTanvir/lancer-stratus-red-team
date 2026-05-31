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

resource "azurerm_subnet" "subnet" {
  name                 = "subnet-${random_string.suffix.result}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_interface" "nic" {
  name                = "nic-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
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
output "vm_name"             { value = azurerm_linux_virtual_machine.vm.name }
output "subscription_id"    { value = "" }
"#;

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
    let vm = outputs
        .get("vm_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: vm_name"))?;

    // Obtain OAuth2 token
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let client = reqwest::Client::new();
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
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
    let token = resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))?
        .to_string();

    // POST runCommand
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/\
         Microsoft.Compute/virtualMachines/{}/runCommand?api-version=2023-03-01",
        subscription_id, rg, vm
    );
    let body = serde_json::json!({
        "commandId": "RunShellScript",
        "script": ["id && whoami"]
    });
    let run_resp = client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if run_resp.status().is_success() || run_resp.status().as_u16() == 202 {
        println!("RunCommand accepted on VM {}/{}", rg, vm);
    } else {
        let status = run_resp.status();
        let text = run_resp.text().await.unwrap_or_default();
        anyhow::bail!("RunCommand failed ({}): {}", status, text);
    }

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
        id: "azure.execution.vm-run-command",
        friendly_name: "Execute Commands on VM via RunCommand API",
        description: "Executes arbitrary shell commands on an Azure Linux VM using the RunCommand REST API, simulating T1059 command execution by an attacker with Contributor access.",
        detection: "Azure Activity Log: Microsoft.Compute/virtualMachines/runCommand/action. Defender for Cloud: VM behavioral alerts.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
