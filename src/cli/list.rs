use clap::Args;
use colored::Colorize;

use crate::platform::Platform;
use crate::registry::all_techniques;
use crate::state::load_state;

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by platform (aws, azure, gcp, kubernetes, eks, entraid)
    #[arg(long, short)]
    pub platform: Option<String>,
    /// Filter by MITRE tactic keyword
    #[arg(long, short)]
    pub tactic: Option<String>,
}

pub fn run(args: &ListArgs) {
    let mut techniques = all_techniques();

    if let Some(ref plat) = args.platform {
        let p: Platform = match plat.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {}", "error".red(), e);
                return;
            }
        };
        techniques.retain(|t| t.platform == p);
    }

    if let Some(ref tactic_kw) = args.tactic {
        let kw = tactic_kw.to_lowercase();
        techniques.retain(|t| {
            t.mitre_tactics
                .iter()
                .any(|ta| ta.as_str().to_lowercase().contains(&kw))
        });
    }

    if techniques.is_empty() {
        println!("No techniques found.");
        return;
    }

    println!(
        "{:<55} {:<12} {:<30} {}",
        "ID".bold(),
        "PLATFORM".bold(),
        "TACTICS".bold(),
        "NAME".bold()
    );
    println!("{}", "-".repeat(120));

    for t in &techniques {
        let state_str = match load_state(t.id) {
            Ok(s) => match s.state {
                crate::state::AttackTechniqueState::Cold => "COLD".dimmed().to_string(),
                crate::state::AttackTechniqueState::Warm => "WARM".yellow().to_string(),
                crate::state::AttackTechniqueState::Detonated => "DETONATED".red().to_string(),
            },
            Err(_) => "COLD".dimmed().to_string(),
        };
        println!(
            "{:<55} {:<12} {:<30} {}  [{}]",
            t.id,
            t.platform_display(),
            t.tactics_display(),
            t.friendly_name,
            state_str,
        );
    }
    println!("\n{} technique(s) listed.", techniques.len());
}
