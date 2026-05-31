use clap::Args;
use colored::Colorize;

use crate::registry::find_technique;

#[derive(Args, Debug)]
pub struct WarmupArgs {
    /// Technique ID(s) to warm up
    pub ids: Vec<String>,
}

pub async fn run(args: &WarmupArgs, providers: std::sync::Arc<crate::providers::CloudProviders>) {
    for id in &args.ids {
        let t = match find_technique(id) {
            Some(t) => t,
            None => {
                eprintln!("{}: technique '{}' not found", "error".red(), id);
                continue;
            }
        };
        println!("{} Warming up {}…", "→".cyan(), id);
        match crate::runner::warmup(t, std::sync::Arc::clone(&providers)).await {
            Ok(()) => println!("{} {} is WARM", "✓".green(), id),
            Err(e) => eprintln!("{} Failed to warm up {}: {:#}", "✗".red(), id, e),
        }
    }
}
