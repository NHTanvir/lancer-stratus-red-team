use clap::Args;
use colored::Colorize;

use crate::registry::find_technique;

#[derive(Args, Debug)]
pub struct DetonateArgs {
    /// Technique ID(s) to detonate
    pub ids: Vec<String>,
    /// Auto-warmup if technique is cold
    #[arg(long, short)]
    pub warmup: bool,
    /// Detonate even if already detonated (for idempotent techniques)
    #[arg(long)]
    pub force: bool,
    /// Do not prompt for sandbox confirmation
    #[arg(long, short = 'y')]
    pub no_confirm: bool,
}

pub async fn run(args: &DetonateArgs, providers: std::sync::Arc<crate::providers::CloudProviders>) {
    if !args.no_confirm {
        eprintln!(
            "{} You are about to run LIVE attack techniques against cloud infrastructure.",
            "WARNING:".yellow().bold()
        );
        eprintln!("         Ensure you are targeting a SANDBOX account.");
        eprint!("         Proceed? [y/N] ");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        if input.trim().to_lowercase() != "y" {
            println!("Aborted.");
            return;
        }
    }

    for id in &args.ids {
        let t = match find_technique(id) {
            Some(t) => t,
            None => {
                eprintln!("{}: technique '{}' not found", "error".red(), id);
                continue;
            }
        };

        if args.warmup {
            println!("{} Warming up {}…", "→".cyan(), id);
            if let Err(e) = crate::runner::warmup(t, std::sync::Arc::clone(&providers)).await {
                eprintln!("{} Warmup failed for {}: {:#}", "✗".red(), id, e);
                continue;
            }
        }

        println!("{} Detonating {}…", "→".red(), id);
        match crate::runner::detonate(t, std::sync::Arc::clone(&providers), args.force).await {
            Ok(()) => println!("{} {} DETONATED", "✓".green(), id),
            Err(e) => eprintln!("{} Detonation failed for {}: {:#}", "✗".red(), id, e),
        }
    }
}
