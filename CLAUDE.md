# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-stratus-red-team` — A Rust clone of the `stratus-red-team` attack simulation tool, built as part of the Lancer ecosystem: a complete 2026 AI-era bug bounty toolkit. It enables red teamers and bug bounty hunters to detonate and revert cloud attack techniques (AWS, Azure, GCP, Kubernetes, EKS, Entra ID) in a controlled, repeatable way. Currently in active development as a scaffold with implementation tracked in the local `plan.md`.

## Architecture

- `src/main.rs` — Binary entry point; bootstraps the CLI and async Tokio runtime.
- `src/lib.rs` — Library crate root; re-exports public modules.
- `src/cli/` — CLI surface built with `clap`; subcommands: `detonate`, `revert`, `cleanup`, `warmup`, `list`, `show`, `status`.
- `src/technique.rs` — Core `Technique` trait definition shared across all attack modules.
- `src/tactic.rs` — MITRE ATT&CK tactic taxonomy types.
- `src/registry.rs` — Distributed static technique registration via the `inventory` crate.
- `src/state.rs` — Per-technique run state persistence (warm/detonated/reverted).
- `src/platform.rs` — Platform detection and capability checks.
- `src/providers/` — Cloud provider auth helpers: `aws.rs`, `mod.rs`.
- `src/runner/` — Execution engine: `mod.rs`, `terraform.rs` (Terraform-backed techniques).
- `src/techniques/` — Concrete attack technique implementations grouped by platform: `aws/`, `azure/`, `gcp/`, `k8s/`, `eks/`, `entra_id/`.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- All async code runs on Tokio (`tokio = { version = "1", features = ["full"] }`); use `async`/`await` throughout.
- Library code lives in `src/lib.rs`; binary entry point in `src/main.rs`.
- New attack techniques go under `src/techniques/<platform>/` and must be registered via the `inventory` static registry.
- Cloud SDK calls use the official `aws-sdk-*` crates (version 1) with `aws-config` behaviour-version-latest; Kubernetes operations use the `kube` crate.
- Logging uses `tracing` + `tracing-subscriber` with `RUST_LOG` env-filter; prefer `tracing::info!/warn!/error!` over `println!`.
- Serialisation uses `serde` + `serde_json`; structs that cross API boundaries must `#[derive(Serialize, Deserialize)]`.

## Build / test / run

```
build.bat                   # Windows → build\lancer-stratus-red-team.exe
build-windows.bat           # Windows packaged dist → dist\lancer-stratus-red-team-windows-x86_64\bin\...
./build-linux.sh            # Linux/macOS → build/lancer-stratus-red-team
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

Requirements: Rust/Cargo (rustup.rs), and on Windows the Visual C++ Build Tools 2019/2022.

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
