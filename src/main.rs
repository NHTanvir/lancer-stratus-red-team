//! lancer-stratus-red-team
//! Rust clone of stratus-red-team. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-stratus-red-team", version, about = "Rust clone of stratus-red-team")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-stratus-red-team - scaffold ready. Implement per plan.md.");
    Ok(())
}
