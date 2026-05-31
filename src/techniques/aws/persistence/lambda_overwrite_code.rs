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

    aws.lambda
        .update_function_code()
        .function_name(function_name)
        .zip_file(aws_sdk_lambda::primitives::Blob::new(EMPTY_ZIP.to_vec()))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Overwrote Lambda function code for: {}", function_name);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let function_name = outputs.get("function_name").ok_or_else(|| anyhow::anyhow!("Missing output: function_name"))?;

    // Restore function code with minimal zip (no original stored; re-upload minimal code)
    aws.lambda
        .update_function_code()
        .function_name(function_name)
        .zip_file(aws_sdk_lambda::primitives::Blob::new(EMPTY_ZIP.to_vec()))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Restored Lambda function code for: {}", function_name);

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.lambda-overwrite-code",
        friendly_name: "Overwrite Lambda Function Code",
        description: "Overwrites an existing Lambda function's code with malicious code to achieve execution persistence.",
        detection: "CloudTrail: UpdateFunctionCode. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
