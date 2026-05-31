use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use aws_sdk_cloudtrail::types::{EventSelector, ReadWriteType};

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
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let trail_name = outputs
        .get("trail_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: trail_name"))?;

    aws.cloudtrail
        .put_event_selectors()
        .trail_name(trail_name)
        .event_selectors(
            EventSelector::builder()
                .read_write_type(ReadWriteType::All)
                .include_management_events(false)
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Updated event selectors on trail {} to exclude management events",
        trail_name
    );

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

    aws.cloudtrail
        .put_event_selectors()
        .trail_name(trail_name)
        .event_selectors(
            EventSelector::builder()
                .read_write_type(ReadWriteType::All)
                .include_management_events(true)
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Restored event selectors on trail {} to include management events",
        trail_name
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.defense-evasion.cloudtrail-event-selectors",
        friendly_name: "Disable CloudTrail Logging Through Event Selectors",
        description: "Modifies CloudTrail event selectors to exclude management events, effectively disabling logging of control-plane API calls while leaving the trail active.",
        detection: "CloudTrail: PutEventSelectors with IncludeManagementEvents=false.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::DefenseEvasion],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
