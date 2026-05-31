use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

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

output "trail_name" {
  value = aws_cloudtrail.stratus.name
}

output "trail_arn" {
  value = aws_cloudtrail.stratus.arn
}

output "bucket_name" {
  value = aws_s3_bucket.trail.bucket
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let trail_arn = outputs
        .get("trail_arn")
        .ok_or_else(|| anyhow::anyhow!("missing output: trail_arn"))?;

    aws.cloudtrail
        .delete_trail()
        .name(trail_arn)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Deleted CloudTrail trail: {}", trail_arn);

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let trail_name = outputs
        .get("trail_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: trail_name"))?;
    let bucket_name = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    let result = aws
        .cloudtrail
        .create_trail()
        .name(trail_name)
        .s3_bucket_name(bucket_name)
        .send()
        .await;

    match result {
        Ok(_) => println!("Recreated CloudTrail trail: {}", trail_name),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("TrailAlreadyExists") {
                println!("Trail {} already exists — skipping recreation", trail_name);
            } else {
                return Err(anyhow::anyhow!("{}", e));
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
        id: "aws.defense-evasion.cloudtrail-delete",
        friendly_name: "Delete CloudTrail Trail",
        description: "Deletes a CloudTrail trail to disable audit logging and impair defenses. This prevents CloudTrail from recording API activity in the affected region.",
        detection: "CloudTrail: DeleteTrail.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
