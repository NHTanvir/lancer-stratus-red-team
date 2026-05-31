use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::certificates::v1::{CertificateSigningRequest, CertificateSigningRequestSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const CSR_NAME: &str = "stratus-red-team-attacker-csr";

/// Generate a minimal self-signed CSR DER encoded in PEM (base64)
/// In a real scenario this would use rcgen or openssl to generate a proper CSR.
/// Here we create a placeholder CSR request body that demonstrates the technique.
fn placeholder_csr_pem() -> String {
    // A real implementation would use `rcgen::generate_simple_self_signed` or similar.
    // For compilation purposes, we return a note and bail at runtime if needed.
    "PLACEHOLDER_CSR_DATA_WOULD_BE_BASE64_ENCODED_DER".to_string()
}

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}. Ensure KUBECONFIG is set.", e))?;

    // In production, generate a real RSA key + CSR using rcgen or openssl bindings.
    // For this simulation, we demonstrate the API call structure.
    let csr_pem = placeholder_csr_pem();
    let csr_bytes = csr_pem.into_bytes();

    let csr_api: Api<CertificateSigningRequest> = Api::all(client.clone());

    let csr = CertificateSigningRequest {
        metadata: ObjectMeta {
            name: Some(CSR_NAME.to_string()),
            ..Default::default()
        },
        spec: CertificateSigningRequestSpec {
            request: k8s_openapi::ByteString(csr_bytes),
            signer_name: "kubernetes.io/kube-apiserver-client".to_string(),
            usages: Some(vec![
                "client auth".to_string(),
                "digital signature".to_string(),
                "key encipherment".to_string(),
            ]),
            // groups/username for the new attacker user
            extra: None,
            groups: None,
            uid: None,
            username: None,
            expiration_seconds: Some(86400),
        },
        status: None,
    };

    csr_api
        .create(&Default::default(), &csr)
        .await
        .map_err(|e| anyhow::anyhow!(
            "Failed to create CertificateSigningRequest: {}. \
             Note: in production, generate a real RSA key and CSR DER bytes.",
            e
        ))?;

    println!(
        "Created CertificateSigningRequest '{}' for attacker user — \
         if approved, attacker obtains a client certificate for persistent cluster access",
        CSR_NAME
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

    let csr_api: Api<CertificateSigningRequest> = Api::all(client);
    csr_api
        .delete(CSR_NAME, &Default::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete CSR: {}", e))?;

    println!("Deleted CertificateSigningRequest '{}'", CSR_NAME);
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
        id: "k8s.persistence.create-client-certificate",
        friendly_name: "Create Kubernetes Client Certificate via CSR",
        description: "Creates a Kubernetes CertificateSigningRequest for an attacker-controlled user, which if approved provides a client certificate for persistent API server authentication.",
        detection: "Kubernetes audit log: create certificatesigningrequests by unexpected identity. Monitor for CSR approval events.",
        platform: Platform::Kubernetes,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
