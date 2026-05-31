pub mod terraform;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tracing::info;

use crate::providers::CloudProviders;
use crate::state::{
    AttackTechniqueState, TechniqueStateFile, delete_state, load_state, save_state,
};
use crate::technique::AttackTechnique;

pub async fn warmup(technique: &'static AttackTechnique, providers: Arc<CloudProviders>) -> Result<()> {
    let mut state = load_state(technique.id)?;

    match state.state {
        AttackTechniqueState::Warm | AttackTechniqueState::Detonated => {
            info!("{} is already warm — skipping warmup", technique.id);
            return Ok(());
        }
        AttackTechniqueState::Cold => {}
    }

    if let Some(tf) = technique.prerequisite_tf {
        info!("Writing Terraform prerequisites for {}", technique.id);
        let working_dir = terraform::write_tf(technique.id, tf)?;

        info!("Running terraform init for {}", technique.id);
        terraform::terraform_init(&working_dir)
            .await
            .context("terraform init failed")?;

        info!("Running terraform apply for {}", technique.id);
        terraform::terraform_apply(&working_dir)
            .await
            .context("terraform apply failed")?;

        let outputs = terraform::terraform_output(&working_dir).await?;
        state.terraform_outputs = outputs;
    }

    state.state = AttackTechniqueState::Warm;
    state.warmup_at = Some(chrono::Utc::now());
    save_state(technique.id, &state)?;
    info!("{} is now WARM", technique.id);
    Ok(())
}

pub async fn detonate(technique: &'static AttackTechnique, providers: Arc<CloudProviders>, force: bool) -> Result<()> {
    let state = load_state(technique.id)?;

    match state.state {
        AttackTechniqueState::Cold => {
            if force {
                info!("Force-detonating {} without warmup", technique.id);
            } else {
                bail!(
                    "{} is COLD — run warmup first (or use --force)",
                    technique.id
                );
            }
        }
        AttackTechniqueState::Detonated if !technique.is_idempotent => {
            bail!(
                "{} is already DETONATED. Run revert first, or use --force.",
                technique.id
            );
        }
        _ => {}
    }

    info!("Detonating {}", technique.id);
    (technique.detonate)(state.terraform_outputs.clone(), Arc::clone(&providers))
        .await
        .with_context(|| format!("detonate failed for {}", technique.id))?;

    let mut state = state;
    state.state = AttackTechniqueState::Detonated;
    state.detonate_at = Some(chrono::Utc::now());
    save_state(technique.id, &state)?;
    info!("{} is now DETONATED", technique.id);
    Ok(())
}

pub async fn revert(technique: &'static AttackTechnique, providers: Arc<CloudProviders>) -> Result<()> {
    let state = load_state(technique.id)?;

    match state.state {
        AttackTechniqueState::Cold => {
            bail!("{} is COLD — nothing to revert", technique.id);
        }
        AttackTechniqueState::Warm => {
            bail!("{} was not detonated — nothing to revert", technique.id);
        }
        AttackTechniqueState::Detonated => {}
    }

    let revert_fn = technique
        .revert
        .ok_or_else(|| anyhow::anyhow!("{} has no revert function", technique.id))?;

    info!("Reverting {}", technique.id);
    revert_fn(state.terraform_outputs.clone(), Arc::clone(&providers))
        .await
        .with_context(|| format!("revert failed for {}", technique.id))?;

    let mut state = state;
    state.state = AttackTechniqueState::Warm;
    save_state(technique.id, &state)?;
    info!("{} reverted — now WARM", technique.id);
    Ok(())
}

pub async fn cleanup(technique: &'static AttackTechnique, providers: Arc<CloudProviders>) -> Result<()> {
    let state = load_state(technique.id)?;

    match state.state {
        AttackTechniqueState::Cold => {
            info!("{} is already COLD — nothing to clean up", technique.id);
            return Ok(());
        }
        AttackTechniqueState::Detonated => {
            if technique.revert.is_some() {
                info!("Auto-reverting {} before cleanup", technique.id);
                revert(technique, Arc::clone(&providers)).await?;
            }
        }
        AttackTechniqueState::Warm => {}
    }

    if technique.prerequisite_tf.is_some() {
        let working_dir = crate::state::state_dir(technique.id)?;
        if working_dir.join("main.tf").exists() {
            info!("Running terraform destroy for {}", technique.id);
            terraform::terraform_destroy(&working_dir)
                .await
                .context("terraform destroy failed")?;
        }
    }

    delete_state(technique.id)?;
    info!("{} cleaned up — now COLD", technique.id);
    Ok(())
}

pub fn status(technique_id: &str) -> Result<TechniqueStateFile> {
    load_state(technique_id)
}
