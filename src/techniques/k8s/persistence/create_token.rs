use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use kube::api::PostParams;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const NAMESPACE: &str = "default";
const SA_NAME: &str = "stratus-red-team-sa";
const SECRET_NAME: &str = "stratus-red-team-token";

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.", e))?;

    // Create a ServiceAccount
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), NAMESPACE);
    let sa = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(SA_NAME.to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    match sa_api.create(&PostParams::default(), &sa).await {
        Ok(_) => println!("Created ServiceAccount '{}/{}'", NAMESPACE, SA_NAME),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            println!("ServiceAccount '{}/{}' already exists", NAMESPACE, SA_NAME)
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to create ServiceAccount: {}", e)),
    }

    // Create a long-lived token Secret bound to the SA
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), NAMESPACE);
    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert(
        "kubernetes.io/service-account.name".to_string(),
        SA_NAME.to_string(),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(SECRET_NAME.to_string()),
            namespace: Some(NAMESPACE.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        type_: Some("kubernetes.io/service-account-token".to_string()),
        ..Default::default()
    };

    secret_api
        .create(&PostParams::default(), &secret)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create token secret: {}", e))?;

    println!(
        "Created service account token secret '{}/{}' — \
         Kubernetes will populate a long-lived JWT token that an attacker can use for persistent access",
        NAMESPACE, SECRET_NAME
    );

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
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}", e))?;

    let secret_api: Api<Secret> = Api::namespaced(client.clone(), NAMESPACE);
    if let Err(e) = secret_api.delete(SECRET_NAME, &Default::default()).await {
        eprintln!("Warning: failed to delete secret: {}", e);
    } else {
        println!("Deleted secret '{}/{}'", NAMESPACE, SECRET_NAME);
    }

    let sa_api: Api<ServiceAccount> = Api::namespaced(client, NAMESPACE);
    if let Err(e) = sa_api.delete(SA_NAME, &Default::default()).await {
        eprintln!("Warning: failed to delete service account: {}", e);
    } else {
        println!("Deleted service account '{}/{}'", NAMESPACE, SA_NAME);
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
        id: "k8s.persistence.create-token",
        friendly_name: "Create Long-Lived Kubernetes Service Account Token",
        description: "Creates a ServiceAccount and a kubernetes.io/service-account-token Secret, generating a long-lived JWT token that persists beyond the default 1-hour bound token lifetime.",
        detection: "Kubernetes audit log: create secrets of type kubernetes.io/service-account-token. Falco: Long-lived service account token created.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
