use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackTechniqueState {
    Cold,
    Warm,
    Detonated,
}

impl std::fmt::Display for AttackTechniqueState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackTechniqueState::Cold => write!(f, "COLD"),
            AttackTechniqueState::Warm => write!(f, "WARM"),
            AttackTechniqueState::Detonated => write!(f, "DETONATED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueStateFile {
    pub state: AttackTechniqueState,
    pub warmup_at: Option<DateTime<Utc>>,
    pub detonate_at: Option<DateTime<Utc>>,
    /// Outputs from terraform apply — passed to detonate/revert.
    pub terraform_outputs: HashMap<String, String>,
}

impl Default for TechniqueStateFile {
    fn default() -> Self {
        Self {
            state: AttackTechniqueState::Cold,
            warmup_at: None,
            detonate_at: None,
            terraform_outputs: HashMap::new(),
        }
    }
}

pub fn state_dir(technique_id: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(".stratus-red-team").join(technique_id))
}

pub fn state_file_path(technique_id: &str) -> Result<PathBuf> {
    Ok(state_dir(technique_id)?.join("state.json"))
}

pub fn load_state(technique_id: &str) -> Result<TechniqueStateFile> {
    let path = state_file_path(technique_id)?;
    if !path.exists() {
        return Ok(TechniqueStateFile::default());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading state file {}", path.display()))?;
    let state: TechniqueStateFile = serde_json::from_str(&content)
        .with_context(|| format!("parsing state file {}", path.display()))?;
    Ok(state)
}

pub fn save_state(technique_id: &str, state: &TechniqueStateFile) -> Result<()> {
    let dir = state_dir(technique_id)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let path = dir.join("state.json");
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content)
        .with_context(|| format!("writing state file {}", path.display()))?;
    Ok(())
}

pub fn delete_state(technique_id: &str) -> Result<()> {
    let path = state_file_path(technique_id)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}
