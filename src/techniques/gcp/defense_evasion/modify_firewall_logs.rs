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

resource "google_compute_firewall" "rule" {
  name    = "stratus-fw-${random_string.suffix.result}"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  direction   = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

output "firewall_rule_name" { value = google_compute_firewall.rule.name }
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

    let rule_name = outputs
        .get("firewall_rule_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: firewall_rule_name"))?;

    // GET current rule to get fingerprint
    let get_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
        project, rule_name
    );
    let current: serde_json::Value = http
        .get(&get_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let fingerprint = current["fingerprint"].as_str().unwrap_or("").to_string();

    // Patch to disable logging
    let patch_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
        project, rule_name
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
            "Disabled logging on firewall rule '{}' in project '{}' — firewall traffic is no longer logged",
            rule_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to disable firewall logging ({}): {}", status, text);
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

    let rule_name = outputs
        .get("firewall_rule_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: firewall_rule_name"))?;

    let get_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
        project, rule_name
    );
    let current: serde_json::Value = http
        .get(&get_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let fingerprint = current["fingerprint"].as_str().unwrap_or("").to_string();

    let patch_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
        project, rule_name
    );

    let body = serde_json::json!({
        "fingerprint": fingerprint,
        "logConfig": {
            "enable": true,
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
        println!("Re-enabled logging on firewall rule '{}' in project '{}'", rule_name, project);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to re-enable firewall logging ({}): {}", status, text);
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
        id: "gcp.defense-evasion.modify-firewall-logs",
        friendly_name: "Disable GCP Firewall Rule Logging",
        description: "Disables logging on a GCP VPC firewall rule, preventing firewall traffic events from being captured and impeding network-based detection.",
        detection: "GCP Audit Log: compute.firewalls.patch with logConfig.enable=false. Cloud Security Command Center: Firewall logging disabled.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
