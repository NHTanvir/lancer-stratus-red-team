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

resource "google_storage_bucket" "log_bucket" {
  name          = "stratus-log-bucket-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true
}

resource "google_storage_bucket" "target_bucket" {
  name          = "stratus-target-${random_string.suffix.result}"
  location      = "US"
  force_destroy = true

  logging {
    log_bucket        = google_storage_bucket.log_bucket.name
    log_object_prefix = "gcs-access-logs/"
  }
}

output "target_bucket" { value = google_storage_bucket.target_bucket.name }
output "log_bucket"    { value = google_storage_bucket.log_bucket.name }
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

async fn detonate_impl(
    outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = gcp_token().await?;
    let http = reqwest::Client::new();

    let bucket = outputs
        .get("target_bucket")
        .ok_or_else(|| anyhow::anyhow!("Missing output: target_bucket"))?;

    // Patch the bucket to remove logging configuration
    let url = format!(
        "https://storage.googleapis.com/storage/v1/b/{}",
        bucket
    );

    let body = serde_json::json!({
        "logging": null
    });

    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!(
            "Removed GCS access logging from bucket '{}' — object access is no longer logged",
            bucket
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove GCS logging ({}): {}", status, text);
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
    let http = reqwest::Client::new();

    let bucket = outputs
        .get("target_bucket")
        .ok_or_else(|| anyhow::anyhow!("Missing output: target_bucket"))?;
    let log_bucket = outputs
        .get("log_bucket")
        .ok_or_else(|| anyhow::anyhow!("Missing output: log_bucket"))?;

    let url = format!(
        "https://storage.googleapis.com/storage/v1/b/{}",
        bucket
    );

    let body = serde_json::json!({
        "logging": {
            "logBucket": log_bucket,
            "logObjectPrefix": "gcs-access-logs/"
        }
    });

    let resp = http
        .patch(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!("Restored GCS access logging on bucket '{}' to log bucket '{}'", bucket, log_bucket);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to restore GCS logging ({}): {}", status, text);
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
        id: "gcp.defense-evasion.remove-gcs-logging",
        friendly_name: "Remove GCS Bucket Access Logging",
        description: "Removes access logging configuration from a GCS bucket, preventing storage access events from being logged to the designated log bucket.",
        detection: "GCP Audit Log: storage.buckets.update with logging removal. Cloud Security Command Center: Bucket logging disabled finding.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
