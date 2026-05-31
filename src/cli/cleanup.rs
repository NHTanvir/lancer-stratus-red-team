use clap::Args;
use colored::Colorize;

use crate::registry::find_technique;

#[derive(Args, Debug)]
pub struct CleanupArgs {
    /// Technique ID(s) to clean up
    pub ids: Vec<String>,
}

pub async fn run(args: &CleanupArgs, providers: std::sync::Arc<crate::providers::CloudProviders>) {
    for id in &args.ids {
        let t = match find_technique(id) {
            Some(t) => t,
            None => {
                eprintln!("{}: technique '{}' not found", "error".red(), id);
                continue;
            }
        };
        println!("{} Cleaning up {}…", "→".cyan(), id);
        match crate::runner::cleanup(t, std::sync::Arc::clone(&providers)).await {
            Ok(()) => println!("{} {} cleaned up (COLD)", "✓".green(), id),
            Err(e) => eprintln!("{} Cleanup failed for {}: {:#}", "✗".red(), id, e),
        }
    }
}
