use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;

use crate::platform::Platform;
use crate::providers::CloudProviders;
use crate::tactic::MitreTactic;
use crate::technique::{AttackTechnique, BoxFuture};

const TERRAFORM: &str = r#"
resource "aws_secretsmanager_secret" "secret" {
  count                   = 5
  name                    = "stratus-red-team-secret-${count.index}-${random_string.suffix.result}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret" {
  count         = 5
  secret_id     = aws_secretsmanager_secret.secret[count.index].id
  secret_string = "supersecret-password-${count.index}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "secret_arns" {
  value = join(",", [for s in aws_secretsmanager_secret.secret : s.arn])
}
"#;

async fn detonate_impl(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> Result<()> {
    let aws = providers.aws().await?;
    let arns: Vec<String> = outputs
        .get("secret_arns")
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_default();

    if arns.is_empty() {
        anyhow::bail!("missing output: secret_arns");
    }

    let resp = aws
        .secretsmanager
        .batch_get_secret_value()
        .set_secret_id_list(Some(arns))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Retrieved {} secrets via BatchGetSecretValue", resp.secret_values().len());

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.credential-access.secretsmanager-batch-retrieve-secrets",
        friendly_name: "Retrieve a High Number of Secrets Manager Secrets (Batch)",
        description: "Retrieves a batch of Secrets Manager secrets in a single API call using BatchGetSecretValue. This can be used by an attacker to mass-harvest secrets with fewer API calls than individual GetSecretValue requests.",
        detection: "CloudTrail: BatchGetSecretValue.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
