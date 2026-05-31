use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const MODEL_ID: &str = "amazon.titan-text-express-v1";

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let body = serde_json::json!({
        "inputText": "Hello, this is a red team test from Stratus Red Team Rust clone.",
        "textGenerationConfig": {
            "maxTokenCount": 50
        }
    });

    let body_bytes = serde_json::to_vec(&body)?;

    let resp = aws
        .bedrockruntime
        .invoke_model()
        .model_id(MODEL_ID)
        .content_type("application/json")
        .accept("application/json")
        .body(aws_sdk_bedrockruntime::primitives::Blob::new(body_bytes))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let response_bytes = resp.body().as_ref().to_vec();
    let response_str = String::from_utf8_lossy(&response_bytes);
    println!(
        "Invoked Bedrock model '{}'. Response preview: {}",
        MODEL_ID,
        &response_str[..response_str.len().min(200)]
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.impact.bedrock-invoke-model",
        friendly_name: "Invoke Bedrock Model",
        description: "Invokes an Amazon Bedrock large language model (Titan Text Express) to simulate resource hijacking for AI/ML cost abuse. An attacker with access to Bedrock credentials could invoke expensive models repeatedly, causing significant cost impact.",
        detection: "CloudTrail: InvokeModel in Bedrock.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: None,
        detonate,
        revert: None,
    }
}
