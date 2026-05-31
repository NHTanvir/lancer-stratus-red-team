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
  bucket        = "stratus-red-team-s3-ransom-batch-${random_string.suffix.result}"
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

    let objects: Vec<aws_sdk_s3::types::ObjectIdentifier> = list_resp
        .contents()
        .iter()
        .filter_map(|obj| {
            let key = obj.key()?;
            aws_sdk_s3::types::ObjectIdentifier::builder()
                .key(key)
                .build()
                .ok()
        })
        .collect();

    if objects.is_empty() {
        println!("No objects found in bucket '{}'.", bucket);
        return Ok(());
    }

    let count = objects.len();

    aws.s3
        .delete_objects()
        .bucket(bucket)
        .delete(
            aws_sdk_s3::types::Delete::builder()
                .set_objects(Some(objects))
                .quiet(false)
                .build()
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Batch-deleted {} objects from S3 bucket '{}' in a single DeleteObjects call.",
        count, bucket
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.impact.s3-ransomware-batch-deletion",
        friendly_name: "S3 Ransomware: Batch Deletion of S3 Objects",
        description: "Deletes all objects in an S3 bucket using a single batch DeleteObjects API call, simulating ransomware that destroys data in bulk. Generates a single CloudTrail event containing all deleted object keys.",
        detection: "CloudTrail: DeleteObjects with many objects at once.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Impact],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
