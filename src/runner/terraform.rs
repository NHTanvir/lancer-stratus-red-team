use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tracing::{debug, info};

async fn run_terraform(args: &[&str], working_dir: &Path) -> Result<String> {
    debug!("terraform {:?} in {}", args, working_dir.display());
    let output = Command::new("terraform")
        .args(args)
        .current_dir(working_dir)
        .env("TF_IN_AUTOMATION", "1")
        .output()
        .await
        .context("failed to spawn terraform — is it in PATH?")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        bail!(
            "terraform {} failed (exit {}):\nstdout: {}\nstderr: {}",
            args[0],
            output.status,
            stdout,
            stderr
        );
    }
    Ok(stdout)
}

pub async fn terraform_init(working_dir: &Path) -> Result<()> {
    info!("terraform init in {}", working_dir.display());
    run_terraform(&["init", "-upgrade", "-input=false"], working_dir).await?;
    Ok(())
}

pub async fn terraform_apply(working_dir: &Path) -> Result<()> {
    info!("terraform apply in {}", working_dir.display());
    run_terraform(
        &["apply", "-auto-approve", "-input=false"],
        working_dir,
    )
    .await?;
    Ok(())
}

pub async fn terraform_output(working_dir: &Path) -> Result<HashMap<String, String>> {
    let raw = run_terraform(&["output", "-json"], working_dir).await?;
    if raw.trim().is_empty() || raw.trim() == "{}" {
        return Ok(HashMap::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .context("parsing terraform output JSON")?;

    let mut outputs = HashMap::new();
    if let serde_json::Value::Object(map) = parsed {
        for (key, val) in map {
            let value_str = if let Some(obj) = val.as_object() {
                if let Some(v) = obj.get("value") {
                    match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string().trim_matches('"').to_string(),
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            };
            outputs.insert(key, value_str);
        }
    }
    Ok(outputs)
}

pub async fn terraform_destroy(working_dir: &Path) -> Result<()> {
    info!("terraform destroy in {}", working_dir.display());
    run_terraform(
        &["destroy", "-auto-approve", "-input=false"],
        working_dir,
    )
    .await?;
    Ok(())
}

/// Write TF code to the technique's working dir and return the dir path.
pub fn write_tf(technique_id: &str, tf_code: &str) -> Result<std::path::PathBuf> {
    let dir = crate::state::state_dir(technique_id)?;
    std::fs::create_dir_all(&dir)?;
    let tf_path = dir.join("main.tf");
    std::fs::write(&tf_path, tf_code)
        .with_context(|| format!("writing {}", tf_path.display()))?;
    Ok(dir)
}
