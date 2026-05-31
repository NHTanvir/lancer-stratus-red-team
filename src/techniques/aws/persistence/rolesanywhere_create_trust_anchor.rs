use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "rolesanywhere" {
  name = "stratus-red-team-rolesanywhere-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "rolesanywhere.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
    }]
  })
  tags = { StratusRedTeam = "true" }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "role_arn" {
  value = aws_iam_role.rolesanywhere.arn
}
"#;

// Minimal self-signed certificate PEM for syntactic validity
const SELF_SIGNED_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n\
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD\n\
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\n\
o4qne60TB3wolABOTKSQ1Z0TM2lVJKcqMzE9P5tB3NWfhsm/HHBBVbMaJPbLzxN\n\
j9rKJZdSJN5WzB1pD7H+qFVJvnZcBb7YhfmAoxmFCfpKNNbMK+u0YllCQ3NWIV\n\
T7KvaMlJZ7n3DvgYPJpq/1IbmHFa3WQMR9R4P+H1KQIDAQABMA0GCSqGSIb3DQE\n\
BAsEggEAFHaB0n7hBjEqIGxjwF2/q5TF8T1DV0IhU8K6fBJVGkW6FicJ0sPqmS\n\
-----END CERTIFICATE-----";

const TRUST_ANCHOR_NAME: &str = "stratus-red-team-trust-anchor";

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let source = aws_sdk_rolesanywhere::types::Source::builder()
        .source_type(aws_sdk_rolesanywhere::types::TrustAnchorType::CertificateBundle)
        .source_data(
            aws_sdk_rolesanywhere::types::SourceData::X509CertificateData(
                SELF_SIGNED_CERT.to_string(),
            ),
        )
        .build();

    let result = aws.rolesanywhere
        .create_trust_anchor()
        .name(TRUST_ANCHOR_NAME)
        .source(source)
        .enabled(true)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let anchor_arn = result
        .trust_anchor()
        .and_then(|a| a.trust_anchor_arn())
        .unwrap_or("unknown ARN");

    println!(
        "Created IAM RolesAnywhere trust anchor: {} (ARN: {})",
        TRUST_ANCHOR_NAME, anchor_arn
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    // List trust anchors and find ours by name
    let list_result = aws.rolesanywhere
        .list_trust_anchors()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    for anchor in list_result.trust_anchors() {
        if anchor.name().unwrap_or("") != TRUST_ANCHOR_NAME {
            continue;
        }

        let anchor_id = anchor
            .trust_anchor_id()
            .ok_or_else(|| anyhow::anyhow!("Trust anchor has no ID"))?
            .to_string();

        // Disable first
        let disable = aws.rolesanywhere
            .disable_trust_anchor()
            .trust_anchor_id(&anchor_id)
            .send()
            .await;

        match disable {
            Err(e) => {
                let msg = format!("{}", e);
                if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                    // ignore
                } else {
                    return Err(anyhow::anyhow!("{}", e));
                }
            }
            Ok(_) => {}
        }

        // Delete
        let del = aws.rolesanywhere
            .delete_trust_anchor()
            .trust_anchor_id(&anchor_id)
            .send()
            .await;

        match del {
            Err(e) => {
                let msg = format!("{}", e);
                if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                    // ignore
                } else {
                    return Err(anyhow::anyhow!("{}", e));
                }
            }
            Ok(_) => {
                println!("Deleted IAM RolesAnywhere trust anchor: {}", TRUST_ANCHOR_NAME);
            }
        }
    }

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.rolesanywhere-create-trust-anchor",
        friendly_name: "Create IAM Roles Anywhere Trust Anchor",
        description: "Creates an IAM Roles Anywhere trust anchor with an attacker-controlled certificate, enabling external workloads to obtain AWS credentials.",
        detection: "CloudTrail: CreateTrustAnchor. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
