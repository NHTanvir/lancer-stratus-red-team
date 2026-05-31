use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TAG_KEY: &str = "stratus-red-team-instance";
const TAG_VALUE: &str = "unusual-instance";

async fn detonate_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let resp = aws
        .ec2
        .run_instances()
        .image_id("resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")
        .instance_type(aws_sdk_ec2::types::InstanceType::P32xlarge)
        .min_count(1)
        .max_count(1)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key(TAG_KEY)
                        .value(TAG_VALUE)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let instance_id = resp
        .instances()
        .first()
        .and_then(|i| i.instance_id())
        .unwrap_or("unknown");

    println!(
        "Launched unusual GPU instance (p3.2xlarge) with ID: {}. Tagged as '{}'='{}'.",
        instance_id, TAG_KEY, TAG_VALUE
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

async fn revert_impl(_outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;

    let describe_resp = aws
        .ec2
        .describe_instances()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(format!("tag:{}", TAG_KEY))
                .values(TAG_VALUE)
                .build(),
        )
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("instance-state-name")
                .values("pending")
                .values("running")
                .values("stopping")
                .values("stopped")
                .build(),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let instance_ids: Vec<String> = describe_resp
        .reservations()
        .iter()
        .flat_map(|r| r.instances())
        .filter_map(|i| i.instance_id())
        .map(|s| s.to_string())
        .collect();

    if instance_ids.is_empty() {
        println!("No stratus-red-team unusual instances found to terminate.");
        return Ok(());
    }

    let mut req = aws.ec2.terminate_instances();
    for id in &instance_ids {
        req = req.instance_ids(id);
    }
    req.send().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Terminated unusual instances: {:?}", instance_ids);

    Ok(())
}

fn revert(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(revert_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.execution.ec2-launch-unusual-instances",
        friendly_name: "Launch Unusual EC2 Instances",
        description: "Launches an unusual GPU EC2 instance type (p3.2xlarge) to simulate an attacker spinning up high-powered instances for crypto-mining or AI/ML workloads.",
        detection: "CloudTrail: RunInstances with unusual instance type (p3.2xlarge, p4d, etc.).",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::Execution],
        is_idempotent: false,
        is_slow: true,
        prerequisite_tf: None,
        detonate,
        revert: Some(revert),
    }
}
