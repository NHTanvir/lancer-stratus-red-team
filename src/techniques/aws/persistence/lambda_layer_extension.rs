use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/dummy.zip"
  source {
    content  = "def handler(event, context): return 'ok'"
    filename = "index.py"
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "stratus-red-team-lambda-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "target" {
  function_name    = "stratus-red-team-${random_string.suffix.result}"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "function_name" {
  value = aws_lambda_function.target.function_name
}

output "function_arn" {
  value = aws_lambda_function.target.arn
}
"#;

// Minimal valid ZIP (empty archive — 22 bytes end-of-central-directory record only)
const EMPTY_ZIP: &[u8] = &[
    0x50, 0x4b, 0x05, 0x06, // End of central directory signature
    0x00, 0x00,             // Disk number
    0x00, 0x00,             // Start disk
    0x00, 0x00,             // Entries on disk
    0x00, 0x00,             // Total entries
    0x00, 0x00, 0x00, 0x00, // Central directory size
    0x00, 0x00, 0x00, 0x00, // Central directory offset
    0x00, 0x00,             // Comment length
];

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let function_name = outputs.get("function_name").ok_or_else(|| anyhow::anyhow!("Missing output: function_name"))?;

    let layer_name = format!("stratus-red-team-layer-{}", uuid::Uuid::new_v4().simple());

    // Publish a new layer version with minimal ZIP content
    let layer_result = aws.lambda
        .publish_layer_version()
        .layer_name(&layer_name)
        .content(
            aws_sdk_lambda::types::LayerVersionContentInput::builder()
                .zip_file(aws_sdk_lambda::primitives::Blob::new(EMPTY_ZIP.to_vec()))
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let layer_arn = layer_result
        .layer_version_arn()
        .ok_or_else(|| anyhow::anyhow!("No layer version ARN returned"))?
        .to_string();

    let layer_version = layer_result.version();

    println!("Published Lambda layer: {} (version {})", layer_arn, layer_version);

    // Update function configuration to add the layer
    aws.lambda
        .update_function_configuration()
        .function_name(function_name)
        .layers(&layer_arn)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Added malicious layer {} to Lambda function: {}",
        layer_arn, function_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let function_name = outputs.get("function_name").ok_or_else(|| anyhow::anyhow!("Missing output: function_name"))?;

    // Remove all layers from the function by setting an empty list
    aws.lambda
        .update_function_configuration()
        .function_name(function_name)
        .set_layers(Some(vec![]))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Removed all layers from Lambda function: {}", function_name);

    // List and delete all stratus-red-team layers
    let layers_result = aws.lambda
        .list_layers()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    for layer in layers_result.layers() {
        let layer_name = layer.layer_name().unwrap_or("");
        if !layer_name.starts_with("stratus-red-team-layer-") {
            continue;
        }

        // List versions to delete them
        let versions_result = aws.lambda
            .list_layer_versions()
            .layer_name(layer_name)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for version in versions_result.layer_versions() {
            let ver = version.version();
            let del = aws.lambda
                .delete_layer_version()
                .layer_name(layer_name)
                .version_number(ver)
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
                    println!("Deleted Lambda layer: {} version {}", layer_name, ver);
                }
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
        id: "aws.persistence.lambda-layer-extension",
        friendly_name: "Add Malicious Lambda Layer Extension",
        description: "Publishes a malicious Lambda layer and attaches it to an existing function to achieve code execution persistence.",
        detection: "CloudTrail: PublishLayerVersion, UpdateFunctionConfiguration. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
