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

    let secrets_resp = aws
        .secretsmanager
        .list_secrets()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut retrieved = 0usize;
    for secret in secrets_resp.secret_list() {
        let name = secret.name().unwrap_or("");
        if name.starts_with("stratus-red-team-secret-") {
            let _ = aws
                .secretsmanager
                .get_secret_value()
                .secret_id(name)
                .send()
                .await;
            retrieved += 1;
        }
    }

    println!(
        "Listed all secrets and retrieved {} stratus-red-team secrets via GetSecretValue",
        retrieved
    );

    Ok(())
}

fn detonate(outputs: HashMap<String, String>, providers: Arc<CloudProviders>) -> BoxFuture<Result<()>> {
    Box::pin(detonate_impl(outputs, providers))
}

inventory::submit! {
    AttackTechnique {
        id: "aws.credential-access.secretsmanager-retrieve-secrets",
        friendly_name: "Retrieve a High Number of Secrets Manager Secrets",
        description: "Lists all Secrets Manager secrets and then individually retrieves each one using GetSecretValue. Simulates an attacker enumerating and dumping all secrets in the account.",
        detection: "CloudTrail: ListSecrets, GetSecretValue.",
        platform: Platform::Aws,
        mitre_tactics: &[MitreTactic::CredentialAccess],
        is_idempotent: true,
        is_slow: false,
        prerequisite_tf: Some(TERRAFORM),
        detonate,
        revert: None,
    }
}
