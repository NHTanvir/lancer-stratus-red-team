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

# We create the deployment via the API since Terraform's google_deployment_manager_deployment
# requires a valid config. The output is used by the technique.
# Create a Deployment Manager deployment manually as a prereq.

output "deployment_name" { value = "stratus-deployment-${random_string.suffix.result}" }
output "project_id"      { value = var.project_id }
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

async fn create_deployment(
    http: &reqwest::Client,
    token: &str,
    project: &str,
    deployment_name: &str,
) -> Result<()> {
    let url = format!(
        "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/{}/global/deployments",
        project
    );

    // Minimal config: creates a single Pub/Sub topic as a managed resource
    let config_content = r#"resources:
- name: stratus-pubsub-topic
  type: pubsub.v1.topic
  properties:
    topic: stratus-red-team-dm-topic
"#;

    let body = serde_json::json!({
        "name": deployment_name,
        "target": {
            "config": {
                "content": config_content
            }
        }
    });

    let resp = http
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!("Created Deployment Manager deployment '{}'", deployment_name);
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to create deployment '{}' ({}): {}",
            deployment_name,
            status,
            text
        )
    }
}

async fn detonate_impl(
    outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = gcp_token().await?;
    let project = gcp_project().await?;
    let http = reqwest::Client::new();

    let deployment_name = outputs
        .get("deployment_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: deployment_name"))?;

    // First ensure the deployment exists
    let check_url = format!(
        "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/{}/global/deployments/{}",
        project, deployment_name
    );
    let check_resp = http.get(&check_url).bearer_auth(&token).send().await?;
    if check_resp.status().as_u16() == 404 {
        create_deployment(&http, &token, &project, deployment_name).await?;
    }

    // Delete the deployment
    let url = format!(
        "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/{}/global/deployments/{}?deletePolicy=DELETE",
        project, deployment_name
    );

    let resp = http.delete(&url).bearer_auth(&token).send().await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 {
        println!(
            "Deleted Deployment Manager deployment '{}' in project '{}' — all managed resources deleted",
            deployment_name, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to delete deployment '{}' ({}): {}",
            deployment_name,
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

    let deployment_name = outputs
        .get("deployment_name")
        .ok_or_else(|| anyhow::anyhow!("Missing output: deployment_name"))?;

    create_deployment(&http, &token, &project, deployment_name).await?;
    println!("Recreated Deployment Manager deployment '{}'", deployment_name);

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
        id: "gcp.impact.deployment-manager-delete",
        friendly_name: "Delete GCP Deployment Manager Deployment",
        description: "Deletes a GCP Deployment Manager deployment, causing all managed resources within it to be deleted — simulating an attacker destroying cloud infrastructure.",
        detection: "GCP Audit Log: deploymentmanager.deployments.delete. Cloud Security Command Center: Deployment deletion alert.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
