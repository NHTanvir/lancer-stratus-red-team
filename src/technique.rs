use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::platform::Platform;
use crate::tactic::MitreTactic;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub type DetonateFn =
    fn(HashMap<String, String>, Arc<crate::providers::CloudProviders>) -> BoxFuture<anyhow::Result<()>>;

pub type RevertFn =
    fn(HashMap<String, String>, Arc<crate::providers::CloudProviders>) -> BoxFuture<anyhow::Result<()>>;

pub struct AttackTechnique {
    pub id: &'static str,
    pub friendly_name: &'static str,
    pub description: &'static str,
    pub detection: &'static str,
    pub platform: Platform,
    pub mitre_tactics: &'static [MitreTactic],
    pub is_idempotent: bool,
    pub is_slow: bool,
    /// Embedded Terraform HCL for prerequisite infrastructure.
    /// None means no infrastructure is required before detonation.
    pub prerequisite_tf: Option<&'static str>,
    pub detonate: DetonateFn,
    pub revert: Option<RevertFn>,
}

inventory::collect!(AttackTechnique);

impl AttackTechnique {
    pub fn platform_display(&self) -> &str {
        match self.platform {
            Platform::Aws => "AWS",
            Platform::Azure => "Azure",
            Platform::Gcp => "GCP",
            Platform::Kubernetes => "Kubernetes",
            Platform::Eks => "EKS",
            Platform::EntraId => "EntraID",
        }
    }

    pub fn tactics_display(&self) -> String {
        self.mitre_tactics
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
