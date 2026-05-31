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

resource "google_dns_managed_zone" "zone" {
  name        = "stratus-zone-${random_string.suffix.result}"
  dns_name    = "stratus-red-team-${random_string.suffix.result}.example.com."
  description = "Stratus Red Team test zone"

  enable_logging = true
}

output "zone_name" { value = google_dns_managed_zone.zone.name }
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

    let zone_name = outputs
        .get("zone_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: zone_name"))?;

    let url = format!(
        "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}",
        project, zone_name
    );

    let body = serde_json::json!({
        "enableLogging": false
    });

    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!(
            "Disabled DNS query logging on zone '{}' in project '{}' — DNS queries are no longer logged",
            zone_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to disable DNS logging ({}): {}", status, text);
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

    let zone_name = outputs
        .get("zone_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: zone_name"))?;

    let url = format!(
        "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}",
        project, zone_name
    );

    let body = serde_json::json!({
        "enableLogging": true
    });

    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!("Re-enabled DNS query logging on zone '{}' in project '{}'", zone_name, project);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to re-enable DNS logging ({}): {}", status, text);
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
        id: "gcp.defense-evasion.disable-dns-logging",
        friendly_name: "Disable GCP DNS Query Logging",
        description: "Disables DNS query logging on a GCP Cloud DNS managed zone, preventing DNS-based detection of C2 communication and data exfiltration via DNS.",
        detection: "GCP Audit Log: dns.managedZones.patch with enableLogging=false. Cloud Security Command Center: DNS logging disabled.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
