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

resource "google_storage_bucket" "sink_bucket" {
  name          = "stratus-red-team-sink-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true
}

resource "google_logging_project_sink" "sink" {
  name        = "stratus-red-team-sink-${random_string.suffix.result}"
  destination = "storage.googleapis.com/${google_storage_bucket.sink_bucket.name}"
  filter      = "logName:cloudaudit.googleapis.com"

  unique_writer_identity = true
}

output "sink_name"       { value = google_logging_project_sink.sink.name }
output "sink_bucket"     { value = google_storage_bucket.sink_bucket.name }
output "sink_destination" { value = google_logging_project_sink.sink.destination }
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

    let sink_name = outputs
        .get("sink_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sink_name"))?;

    let url = format!(
        "https://logging.googleapis.com/v2/projects/{}/sinks/{}",
        project, sink_name
    );

    let resp = http.delete(&url).bearer_auth(&token).send().await?;

    if resp.status().is_success() || resp.status().as_u16() == 204 {
        println!(
            "Deleted GCP log sink '{}' in project '{}' — audit logs are no longer exported",
            sink_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to delete log sink ({}): {}", status, text);
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

    let sink_name = outputs
        .get("sink_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sink_name"))?;
    let sink_destination = outputs
        .get("sink_destination")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sink_destination"))?;

    let url = format!(
        "https://logging.googleapis.com/v2/projects/{}/sinks",
        project
    );
    let body = serde_json::json!({
        "name": sink_name,
        "destination": sink_destination,
        "filter": "logName:cloudaudit.googleapis.com",
        "description": "Stratus Red Team recreated sink"
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!(
            "Recreated GCP log sink '{}' in project '{}'",
            sink_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to recreate log sink ({}): {}", status, text);
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
        id: "gcp.defense-evasion.delete-log-sink",
        friendly_name: "Delete GCP Log Sink (CloudTrail Equivalent)",
        description: "Deletes a GCP Cloud Logging sink that exports audit logs to GCS, stopping audit log export and impeding forensic investigation.",
        detection: "GCP Audit Log: google.logging.v2.ConfigServiceV2.DeleteSink. Cloud Security Command Center: Log sink deleted finding.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
