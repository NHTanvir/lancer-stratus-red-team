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
    google = { source = "hashicorp/google", version = "~> 4.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

variable "project_id" {}

provider "google" { project = var.project_id }

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "google_service_account" "sa" {
  account_id   = "stratus-sa-${random_string.suffix.result}"
  display_name = "Stratus Red Team Service Account"
}

output "sa_email" { value = google_service_account.sa.email }
"#;

async fn gcp_token() -> Result<String> {
    if let Ok(token) = std::env::var("GOOGLE_ACCESS_TOKEN") {
        return Ok(token);
    }
    let output = tokio::process::Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()
        .await?;
    let token = String::from_utf8(output.stdout)?.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("Could not obtain GCP access token via gcloud CLI");
    }
    Ok(token)
}

async fn gcp_project() -> Result<String> {
    std::env::var("GOOGLE_PROJECT_ID")
        .map_err(|_| anyhow::anyhow!("GOOGLE_PROJECT_ID not set"))
}

async fn detonate_impl(
    outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = gcp_token().await?;
    let project = gcp_project().await?;
    let http = reqwest::Client::new();

    let sa_email = outputs
        .get("sa_email")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sa_email"))?;

    let url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/keys",
        project, sa_email
    );

    let body = serde_json::json!({
        "keyAlgorithm": "KEY_ALG_RSA_2048",
        "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        let key_data: serde_json::Value = resp.json().await?;
        let key_name = key_data["name"].as_str().unwrap_or("unknown");
        println!(
            "Created service account key '{}' for '{}' — attacker has persistent credentials JSON",
            key_name, sa_email
        );
        // Store key name for revert
        // In a real impl we'd save to state; here we print the key ID
        if let Some(private_key_data) = key_data["privateKeyData"].as_str() {
            println!(
                "Key ID: {} (base64 credentials JSON generated — {} bytes)",
                key_name,
                private_key_data.len()
            );
        }
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create service account key ({}): {}", status, text);
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
    let token = gcp_token().await?;
    let project = gcp_project().await?;
    let http = reqwest::Client::new();

    let sa_email = outputs
        .get("sa_email")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sa_email"))?;

    // List all keys for the service account to find user-managed ones
    let list_url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/keys?keyTypes=USER_MANAGED",
        project, sa_email
    );

    let list_resp: serde_json::Value = http
        .get(&list_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let keys = list_resp["keys"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No keys array in response"))?;

    for key in keys {
        let key_name = key["name"].as_str().unwrap_or("");
        if key_name.is_empty() {
            continue;
        }
        let del_url = format!(
            "https://iam.googleapis.com/v1/{}",
            key_name
        );
        let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;
        if del_resp.status().is_success() || del_resp.status().as_u16() == 200 {
            println!("Deleted service account key: {}", key_name);
        }
    }

    println!("Reverted: removed all user-managed keys for service account '{}'", sa_email);

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
        id: "gcp.persistence.create-service-account-key",
        friendly_name: "Create GCP Service Account Key for Persistence",
        description: "Creates a user-managed RSA key for a GCP service account, generating long-lived credentials that an attacker can use for persistent access outside the cloud provider.",
        detection: "GCP Audit Log: iam.serviceAccountKeys.create. Cloud Security Command Center: Service account key creation alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
