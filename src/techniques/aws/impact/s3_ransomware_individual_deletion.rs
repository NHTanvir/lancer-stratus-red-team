use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

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

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "target" {
  bucket        = "stratus-red-team-s3-ransom-indiv-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_object" "files" {
  count   = 10
  bucket  = aws_s3_bucket.target.id
  key     = "file-${count.index}.txt"
  content = "test data"
}

output "bucket_name" {
  value = aws_s3_bucket.target.bucket
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    // List all objects
    let list_resp = aws
        .s3
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let keys: Vec<String> = list_resp
        .contents()
        .iter()
        .filter_map(|obj| obj.key().map(|k| k.to_string()))
        .collect();

    if keys.is_empty() {
        println!("No objects found in bucket '{}'.", bucket);
        return Ok(());
    }

    let mut deleted = 0usize;
    for key in &keys {
        aws.s3
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to delete '{}': {}", key, e))?;
        deleted += 1;
        println!("Deleted object: s3://{}/{}", bucket, key);
    }

    println!(
        "Individually deleted {} objects from S3 bucket '{}' ({} separate DeleteObject calls).",
        deleted, bucket, deleted
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.impact.s3-ransomware-individual-deletion",
        friendly_name: "S3 Ransomware: Individual Deletion of S3 Objects",
        description: "Deletes each object in an S3 bucket with a separate DeleteObject API call, simulating ransomware that removes data file-by-file. Generates one CloudTrail event per deleted object, producing a high-volume alert signal.",
        detection: "CloudTrail: Multiple individual DeleteObject calls.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
