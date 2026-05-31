use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, ExpirationStatus, LifecycleExpiration, LifecycleRule,
    LifecycleRuleFilter,
};

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "trail" {
  bucket        = "stratus-red-team-trail-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "stratus" {
  name                          = "stratus-red-team-${random_string.suffix.result}"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = false
  depends_on                    = [aws_s3_bucket_policy.trail]
}

output "bucket_name" {
  value = aws_s3_bucket.trail.bucket
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket_name = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    let filter = LifecycleRuleFilter::builder()
        .prefix("".to_string())
        .build();

    let expiration = LifecycleExpiration::builder().days(1).build();

    let rule = LifecycleRule::builder()
        .id("stratus-red-team-expire")
        .status(ExpirationStatus::Enabled)
        .filter(filter)
        .expiration(expiration)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build LifecycleRule: {}", e))?;

    let config = BucketLifecycleConfiguration::builder()
        .rules(rule)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build BucketLifecycleConfiguration: {}", e))?;

    aws.s3
        .put_bucket_lifecycle_configuration()
        .bucket(bucket_name)
        .lifecycle_configuration(config)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Applied lifecycle rule to S3 bucket {} to expire all objects after 1 day",
        bucket_name
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket_name = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    aws.s3
        .delete_bucket_lifecycle()
        .bucket(bucket_name)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Removed lifecycle configuration from S3 bucket {}",
        bucket_name
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.defense-evasion.cloudtrail-lifecycle-rule",
        friendly_name: "CloudTrail Logs Impairment Through S3 Lifecycle Rule",
        description: "Applies an aggressive S3 lifecycle rule to the CloudTrail log bucket to expire all objects after 1 day. This causes CloudTrail logs to be automatically deleted, impairing forensic investigation.",
        detection: "CloudTrail: PutBucketLifecycle on the CloudTrail S3 bucket.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
