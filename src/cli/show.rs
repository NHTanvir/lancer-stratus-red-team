use clap::Args;
use colored::Colorize;

use crate::registry::find_technique;
use crate::state::load_state;

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Technique ID (e.g. aws.persistence.iam-backdoor-user)
    pub id: String,
}

pub fn run(args: &ShowArgs) {
    let t = match find_technique(&args.id) {
        Some(t) => t,
        None => {
            eprintln!("{}: technique '{}' not found", "error".red(), args.id);
            return;
        }
    };

    let state = load_state(t.id)
        .map(|s| s.state.to_string())
        .unwrap_or_else(|_| "COLD".to_string());

    println!("{}", "═".repeat(80));
    println!("  {} {}", "ID:".bold(), t.id.cyan());
    println!("  {} {}", "Name:".bold(), t.friendly_name);
    println!("  {} {}", "Platform:".bold(), t.platform_display());
    println!("  {} {}", "Tactics:".bold(), t.tactics_display());
    println!("  {} {}", "State:".bold(), state);
    println!("  {} {}", "Idempotent:".bold(), t.is_idempotent);
    println!("  {} {}", "Slow:".bold(), t.is_slow);
    println!("{}", "═".repeat(80));
    println!("\n{}\n{}", "DESCRIPTION".bold().underline(), t.description);
    println!("\n{}\n{}", "DETECTION".bold().underline(), t.detection);
    if t.prerequisite_tf.is_some() {
        println!("\n{}", "Has Terraform prerequisites.".yellow());
    }
}
