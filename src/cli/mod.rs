pub mod cleanup;
pub mod detonate;
pub mod list;
pub mod revert;
pub mod show;
pub mod status;
pub mod warmup;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-stratus-red-team",
    version,
    about = "Rust clone of Stratus Red Team — cloud adversary emulation (MITRE ATT&CK Cloud)",
    long_about = "Sandbox-only. Cleanup is non-negotiable; every technique reverses itself.\nUpstream: https://github.com/DataDog/stratus-red-team"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List available attack techniques
    List(list::ListArgs),
    /// Show details of a technique
    Show(show::ShowArgs),
    /// Warm up prerequisite infrastructure for technique(s)
    Warmup(warmup::WarmupArgs),
    /// Detonate technique(s) — run the actual attack
    Detonate(detonate::DetonateArgs),
    /// Revert technique(s) — undo detonate side-effects
    Revert(revert::RevertArgs),
    /// Clean up all prerequisite infrastructure (terraform destroy)
    Cleanup(cleanup::CleanupArgs),
    /// Show current state of technique(s)
    Status(status::StatusArgs),
}
