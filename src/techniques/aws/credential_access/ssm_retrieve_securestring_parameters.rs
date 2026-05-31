use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "aws_ssm_parameter" "secret" {
  count  = 5
  name   = "/stratus-red-team/${random_string.suffix.result}/secret-${count.index}"
  type   = "SecureString"
  value  = "supersecretvalue-${count.index}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "parameter_path" {
  value = "/stratus-red-team/${random_string.suffix.result}"
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let path = outputs
        .get("parameter_path")
        .ok_or_else(|| anyhow::anyhow!("missing output: parameter_path"))?;

    let resp = aws
        .ssm
        .get_parameters_by_path()
        .path(path)
        .recursive(true)
        .with_decryption(true)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Retrieved {} SSM SecureString parameters from path {}",
        resp.parameters().len(),
        path
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.credential-access.ssm-retrieve-securestring-parameters",
        friendly_name: "Retrieve SSM Parameters",
        description: "Retrieves all SSM SecureString parameters under a given path with decryption enabled. An attacker with ssm:GetParametersByPath can dump secrets stored as SecureString parameters.",
        detection: "CloudTrail: GetParametersByPath with WithDecryption=true.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
