use clap::Args;
use colored::Colorize;

use crate::registry::find_technique;

#[derive(Args, Debug)]
pub struct RevertArgs {
    /// Technique ID(s) to revert
    pub ids: Vec<String>,
}

pub async fn run(args: &RevertArgs, providers: std::sync::Arc<crate::providers::CloudProviders>) {
    for id in &args.ids {
        let t = match find_technique(id) {
            Some(t) => t,
            None => {
                eprintln!("{}: technique '{}' not found", "error".red(), id);
                continue;
            }
        };
        println!("{} Reverting {}…", "→".cyan(), id);
        match crate::runner::revert(t, std::sync::Arc::clone(&providers)).await {
            Ok(()) => println!("{} {} reverted", "✓".green(), id),
            Err(e) => eprintln!("{} Revert failed for {}: {:#}", "✗".red(), id, e),
        }
    }
}
