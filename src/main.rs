use std::sync::Arc;
use clap::Parser;
use lancer_stratus_red_team::cli::{Cli, Commands};
use lancer_stratus_red_team::providers::CloudProviders;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let providers = Arc::new(CloudProviders::new());

    match &cli.command {
        Commands::List(args) => lancer_stratus_red_team::cli::list::run(args),
        Commands::Show(args) => lancer_stratus_red_team::cli::show::run(args),
        Commands::Status(args) => lancer_stratus_red_team::cli::status::run(args),
        Commands::Warmup(args) => {
            lancer_stratus_red_team::cli::warmup::run(args, Arc::clone(&providers)).await
        }
        Commands::Detonate(args) => {
            lancer_stratus_red_team::cli::detonate::run(args, Arc::clone(&providers)).await
        }
        Commands::Revert(args) => {
            lancer_stratus_red_team::cli::revert::run(args, Arc::clone(&providers)).await
        }
        Commands::Cleanup(args) => {
            lancer_stratus_red_team::cli::cleanup::run(args, Arc::clone(&providers)).await
        }
    }

    Ok(())
}
