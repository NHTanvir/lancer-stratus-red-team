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

resource "google_compute_network" "vpc" {
  name                    = "stratus-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "stratus-subnet-${random_string.suffix.result}"
  ip_cidr_range = "10.0.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

output "subnet_name"   { value = google_compute_subnetwork.subnet.name }
output "region"        { value = google_compute_subnetwork.subnet.region }
output "subnet_self_link" { value = google_compute_subnetwork.subnet.self_link }
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

    let subnet_name = outputs
        .get("subnet_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: subnet_name"))?;
    let region = outputs
        .get("region")
        .map(|s| s.as_str())
        .unwrap_or("us-central1");

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/regions/{}/subnetworks/{}",
        project, region, subnet_name
    );

    // Get current subnetwork to get fingerprint
    let current: serde_json::Value = http
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let fingerprint = current["fingerprint"].as_str().unwrap_or("").to_string();

    let patch_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/regions/{}/subnetworks/{}/patch",
        project, region, subnet_name
    );

    let body = serde_json::json!({
        "fingerprint": fingerprint,
        "logConfig": {
            "enable": false
        }
    });

    let resp = http
        .patch(&patch_url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!(
            "Disabled VPC flow logs on subnet '{}' in project '{}' — network traffic is no longer logged",
            subnet_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to disable VPC flow logs ({}): {}", status, text);
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

    let subnet_name = outputs
        .get("subnet_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: subnet_name"))?;
    let region = outputs
        .get("region")
        .map(|s| s.as_str())
        .unwrap_or("us-central1");

    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/regions/{}/subnetworks/{}",
        project, region, subnet_name
    );

    let current: serde_json::Value = http
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let fingerprint = current["fingerprint"].as_str().unwrap_or("").to_string();

    let patch_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/regions/{}/subnetworks/{}/patch",
        project, region, subnet_name
    );

    let body = serde_json::json!({
        "fingerprint": fingerprint,
        "logConfig": {
            "enable": true,
            "aggregationInterval": "INTERVAL_10_MIN",
            "flowSampling": 0.5,
            "metadata": "INCLUDE_ALL_METADATA"
        }
    });

    let resp = http
        .patch(&patch_url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!("Re-enabled VPC flow logs on subnet '{}' in project '{}'", subnet_name, project);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to re-enable VPC flow logs ({}): {}", status, text);
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
        id: "gcp.defense-evasion.disable-vpc-flow-logs",
        friendly_name: "Disable GCP VPC Flow Logs",
        description: "Disables VPC flow logs on a GCP subnet, preventing network traffic logging and impeding network-based detection and investigation.",
        detection: "GCP Audit Log: compute.subnetworks.patch with logConfig.enable=false. Cloud Security Command Center: Flow logs disabled finding.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
