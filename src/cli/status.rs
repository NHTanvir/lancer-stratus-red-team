use clap::Args;
use colored::Colorize;

use crate::registry::{all_techniques, find_technique};
use crate::state::{AttackTechniqueState, load_state};

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Specific technique ID(s); omit to show all non-COLD techniques
    pub ids: Vec<String>,
    /// Show all techniques including COLD
    #[arg(long, short)]
    pub all: bool,
}

pub fn run(args: &StatusArgs) {
    let techniques: Vec<_> = if args.ids.is_empty() {
        all_techniques()
    } else {
        args.ids
            .iter()
            .filter_map(|id| {
                let t = find_technique(id);
                if t.is_none() {
                    eprintln!("{}: technique '{}' not found", "error".red(), id);
                }
                t
            })
            .collect()
    };

    println!(
        "{:<55} {:<12} {}",
        "ID".bold(),
        "PLATFORM".bold(),
        "STATE".bold()
    );
    println!("{}", "-".repeat(80));

    for t in &techniques {
        let state = load_state(t.id)
            .unwrap_or_default();

        if !args.all && state.state == AttackTechniqueState::Cold && args.ids.is_empty() {
            continue;
        }

        let state_str = match state.state {
            AttackTechniqueState::Cold => "COLD".dimmed().to_string(),
            AttackTechniqueState::Warm => "WARM".yellow().to_string(),
            AttackTechniqueState::Detonated => "DETONATED".red().bold().to_string(),
        };
        println!("{:<55} {:<12} {}", t.id, t.platform_display(), state_str);
    }
}
