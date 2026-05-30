# RESEARCH DOSSIER: Stratus Red Team

> Part of the Lancer ecosystem. A Rust clone of Datadog's Stratus Red Team — cloud adversary emulation (MITRE ATT&CK Cloud). Build with Claude Code.
> Upstream: github.com/DataDog/stratus-red-team (Go, 99 techniques across AWS/Azure/GCP/K8s/EKS/Entra ID).
>
> SANDBOX ONLY. Cleanup is non-negotiable; every technique must reverse itself.

## Feature Parity Mandate

**`lancer-stratus-red-team` MUST ship with 100% feature parity to the upstream `stratus-red-team` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `stratus-red-team --help` (and the long-form man page / docs) must work in `lancer-stratus-red-team --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-stratus-red-team` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-stratus-red-team --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Stratus Red Team is **adversary emulation**: it deploys cloud infrastructure, runs a single specific MITRE ATT&CK technique against it, and tears down. The point is generating detection signal so blue teams can validate their CloudTrail/GuardDuty/SIEM rules. **103 techniques** across AWS (51), Azure (11), GCP (24), Kubernetes (8), EKS (2), Entra ID (7) as of v2.32.1 (May 2026). Written in Go (1.23+). Backed by Terraform (≥1.5, currently pinned at 1.3.10 in upstream) for prerequisite infra. Each technique declares its MITRE ATT&CK tactic, requires a sandbox cloud account, and follows a strict `warm → detonate → revert → cleanup` lifecycle.

> Note: counts above reflect the *current* live catalogue on `stratus-red-team.cloud`. The historical breakdown below (43 AWS / 25 GCP / 99 total) was accurate at an earlier point in 2024 and is kept verbatim further down for parity-test continuity. When porting, generate the registry against the *current* list, not the historical one.

## Internal architecture

```
v2/
  cmd/stratus/main.go         # cobra root
  cmd/stratus/...             # subcommands: list, show, warmup, detonate, revert, cleanup, status
  pkg/stratus/
    attack_technique.go       # AttackTechnique struct + interface
    attack_technique_state.go # state enum
    framework.go              # core types: Platform, Tactic
    platform.go               # cloud platform constants
    providers.go              # AWS/Azure/GCP/K8s SDK factory
    registry.go               # global technique registry
    runner/runner.go          # lifecycle engine
    runner/state.go           # state persistence (filesystem or S3 backend)
    runner/terraform.go       # terraform-exec wrapper
  internal/attacktechniques/
    aws/
      credential-access/
        ec2-get-password-data/
          main.go             # technique impl
          main.tf             # Terraform prereq infra
        ec2-steal-instance-credentials/
        secretsmanager-batch-retrieve-secrets/
        ...
      defense-evasion/
      discovery/
      execution/
      exfiltration/
      impact/
      initial-access/
      lateral-movement/
      persistence/
      privilege-escalation/
    azure/...
    gcp/...
    k8s/...
    eks/...
    entra-id/...
```

**AttackTechnique struct (Go):**
```go
type AttackTechnique struct {
    ID                          string
    FriendlyName                string
    Description                 string
    Detection                   string  // markdown: how to detect
    Platform                    Platform
    MitreAttackTactics          []mitreattack.Tactic
    IsIdempotent                bool
    IsSlow                      bool
    PrerequisitesTerraformCode  []byte  // embedded with //go:embed
    Detonate                    func(map[string]string, providers.CloudProviders) error
    Revert                      func(map[string]string, providers.CloudProviders) error  // optional
}
```

Each technique calls `stratus.GetRegistry().RegisterAttackTechnique(&AttackTechnique{...})` in an `init()` function. Registration is **side-effect import**: `main.go` blank-imports the entire `attacktechniques/` tree.

**Lifecycle (runner.go):**
1. **WarmUp** — `terraform init` + `terraform apply` for the technique's `main.tf`. Outputs become inputs to `Detonate`.
2. **Detonate** — call `technique.Detonate(outputs, providers)`. This is the actual attack — e.g., `iam.CreateAccessKey()` for `iam-backdoor-user`.
3. **Revert** — undo *detonate* changes (e.g., delete the backdoored access key). Leaves prereq infra intact for re-detonation.
4. **CleanUp** — `terraform destroy`. Tears down everything.

**State machine:**
```
COLD ─ warmup ─> WARM ─ detonate ─> DETONATED
                              ↑                ↓ revert
                              └────────────────┘
WARM ─ cleanup ─> COLD
```

**State persistence:** default `FileSystemStateManager` writes JSON to `~/.stratus-red-team/{technique-id}/state.json`. Optional `S3Backend` writes Terraform state + Stratus state to an S3 bucket — required for team usage / CI.

## Complete technique catalog (verified from stratus-red-team.cloud)

### AWS (43 techniques)

**Initial Access (1):** `aws.initial-access.console-login-without-mfa`

**Credential Access (5):** `aws.credential-access.ec2-get-password-data` (T1552), `aws.credential-access.ec2-steal-instance-credentials` (T1552.005), `aws.credential-access.secretsmanager-batch-retrieve-secrets` (T1555.006), `aws.credential-access.secretsmanager-retrieve-secrets` (T1555.006), `aws.credential-access.ssm-retrieve-securestring-parameters` (T1552.001)

**Defense Evasion (7):** `aws.defense-evasion.cloudtrail-delete` (T1562.008), `cloudtrail-event-selectors`, `cloudtrail-lifecycle-rule`, `cloudtrail-stop`, `dns-delete-logs`, `organizations-leave`, `vpc-remove-flow-logs`

**Discovery (3):** `aws.discovery.ec2-download-user-data` (T1538), `ec2-enumerate-from-instance` (T1580), `ses-enumerate`

**Execution (5):** `ec2-launch-unusual-instances`, `ec2-user-data` (T1059), `sagemaker-update-lifecycle-config`, `ssm-send-command` (T1651), `ssm-start-session` (T1651)

**Exfiltration (5):** `ec2-security-group-open-port-22-ingress` (T1567), `ec2-share-ami` (T1537), `ec2-share-ebs-snapshot` (T1537), `rds-share-snapshot` (T1537), `s3-backdoor-bucket-policy` (T1567)

**Impact (4):** `bedrock-invoke-model`, `s3-ransomware-batch-deletion` (T1485), `s3-ransomware-client-side-encryption` (T1486), `s3-ransomware-individual-deletion` (T1485)

**Lateral Movement (2):** `ec2-instance-connect`, `ec2-serial-console-send-ssh-public-key`

**Persistence (9):** `iam-backdoor-role` (T1098.001), `iam-backdoor-user`, `iam-create-admin-user` (T1136.003), `iam-create-backdoor-role`, `iam-create-user-login-profile`, `lambda-backdoor-function` (T1546), `lambda-layer-extension` (T1574), `lambda-overwrite-code` (T1546), `rolesanywhere-create-trust-anchor`, `sts-federation-token` (T1078.004)

**Privilege Escalation (1):** `iam-update-user-login-profile` (T1098.001)

### Azure (11)

**Execution (2):** `vm-custom-script-extension`, `vm-run-command` (T1059)

**Exfiltration (3):** `disk-export`, `storage-public-access`, `storage-sas-export`

**Impact (3):** `blob-ransomware-client-encryption-scope` (T1486), `blob-ransomware-individual-file-deletion` (T1485), `resource-lock`

**Persistence (2):** `backdoor-managed-identity-fic` (T1098.003), `create-bastion-shareable-link`

**Privilege Escalation (1):** `root-user-access-administrator` (T1078.004)

### GCP (25)

Credential Access, Defense Evasion (7), Discovery, Execution, Exfiltration (3 — share-compute-disk/image/snapshot, T1537), Impact (4), Initial Access, Lateral Movement, Persistence (5), Privilege Escalation (1 — `gcp.privilege-escalation.impersonate-service-accounts`).

### Entra ID (7)

All in Persistence category, mostly T1098-mapped: `backdoor-application`, `backdoor-application-fic` (federated identity credential), `backdoor-application-sp`, `guest-user`, `hidden-au`, `new-application`, `restricted-au`.

### EKS (2)

`eks.lateral-movement.create-access-entry` (T1078), `eks.persistence.backdoor-aws-auth-configmap` (T1098).

### Kubernetes (8)

**Credential Access (2):** `dump-secrets` (T1552.007), `steal-serviceaccount-token` (T1552.007)

**Persistence (3):** `create-admin-clusterrole` (T1098.001), `create-client-certificate`, `create-token`

**Privilege Escalation (3):** `hostpath-volume` (T1611), `nodes-proxy`, `privileged-pod` (T1611)

## MITRE ATT&CK Cloud Matrix coverage (relevant IDs)

- **T1078** Valid Accounts (T1078.001 Default, T1078.003 Local, T1078.004 Cloud) — Stratus: any persistence creating creds
- **T1098** Account Manipulation (.001 Add Cloud Creds, .003 Add Office365 Global Admin, .004 SSH key, .005 Device Reg) — heavy Stratus coverage
- **T1530** Data from Cloud Storage Object — `s3-backdoor-bucket-policy`, `storage-public-access`
- **T1538** Cloud Service Dashboard — `ec2-download-user-data`
- **T1552** Unsecured Creds (.001 In Files, .005 Cloud Instance Metadata API, .006 Group Policy Preferences, .007 Container API) — heavy
- **T1562** Impair Defenses (.008 Disable Cloud Logs) — all `defense-evasion.*cloudtrail*` techniques
- **T1567** Exfiltration Over Web Service — `s3-backdoor`, `ec2-security-group-open-port-22`
- **T1611** Escape to Host — Kubernetes `hostpath-volume`, `privileged-pod`
- **T1537** Transfer Data to Cloud Account — `*-share-ami`, `*-share-snapshot`, `share-compute-*`
- **T1485/T1486** Data Destruction / Encryption for Impact — ransomware techniques

**Mapping technique → API calls:** every Stratus technique has a `Detection:` markdown field documenting:
- CloudTrail event name (e.g., `CreateAccessKey`)
- Source IP / user identity patterns
- Recommended Sigma/EQL rule snippet

For the Rust clone, embed these as `static DETECTION_RULES: phf::Map<&str, DetectionRule>` for offline reference.

## Complete CLI surface (parity contract — verified against v2.32.1)

The upstream `stratus` binary (alias `stratus-red-team` in some distributions) exposes exactly these cobra subcommands. `lancer-stratus-red-team --cli` MUST mirror every one byte-for-byte.

### Subcommands

| Subcommand | Purpose |
|------------|---------|
| `stratus list` | Print all registered techniques (filterable). |
| `stratus show <technique-id>` | Print full detail (description, MITRE tactic, detection markdown, prereq Terraform). |
| `stratus status` | Show current state (COLD/WARM/DETONATED) for every technique with on-disk state. |
| `stratus warmup <id...>` | Run `terraform init` + `terraform apply` for the technique(s). Idempotent. |
| `stratus detonate <id...>` | Run the technique's `Detonate` function. Auto-warmups if `--no-warmup` not set. |
| `stratus revert <id...>` | Run `Revert` (undo detonate side effects). Leaves prereq infra alive. |
| `stratus cleanup <id...>` | Run `terraform destroy`. Returns technique to COLD. |
| `stratus completion <bash\|zsh\|fish\|powershell>` | Emit shell completion script. |
| `stratus version` | Print version, commit, build date. |
| `stratus help [command]` | Cobra-generated help. |

### Flags (per-subcommand)

| Flag | Subcommands | Purpose |
|------|-------------|---------|
| `--platform <aws\|azure\|gcp\|kubernetes\|eks\|entra-id>` | list, status | Filter by cloud platform. Repeatable. |
| `--mitre-attack-tactic <tactic>` | list | Filter by MITRE ATT&CK tactic name (e.g. `credential-access`, `persistence`). |
| `--tactic <tactic>` | list | Alias for `--mitre-attack-tactic`. |
| `--severity <low\|medium\|high\|critical>` | list, status | Filter by Stratus's per-technique severity hint. |
| `--output <table\|json>` | list, status, show | Output format. JSON for piping into jq / SIEM. |
| `-o` | list, status, show | Short form of `--output`. |
| `--force` | detonate, revert, cleanup | Skip the "this is a destructive action — are you sure?" confirmation. |
| `--no-warmup` | detonate | Refuse to auto-warmup if the technique is COLD; fail loudly instead. |
| `--cleanup` | detonate | After detonating, immediately run revert + cleanup (one-shot mode). |
| `--all` | status, cleanup | Apply to every technique with on-disk state. |
| `--config <path>` | (global) | Path to YAML config file (default `~/.stratus-red-team/config.yaml` or `$STRATUS_CONFIG_PATH`). |
| `--state-backend <filesystem\|s3>` | (global) | Override the default `filesystem` state backend. |
| `--s3-bucket <name>` | (global) | When `--state-backend=s3`, the bucket name. |
| `--s3-key-prefix <prefix>` | (global) | Optional key prefix inside the bucket. |
| `--verbose / -v` | (global) | Verbose logging. |
| `--quiet / -q` | (global) | Suppress non-error output. |
| `--help / -h` | (every) | Help. |

### Environment variables

| Var | Meaning |
|-----|---------|
| `STRATUS_HOME` | Override default `~/.stratus-red-team/` working directory. |
| `STRATUS_CONFIG_PATH` | Override default config file location. |
| `STRATUS_REGION` | Default AWS region for techniques that do not pin one. |
| `STRATUS_OUTPUT` | Default `--output` value (table/json). |
| `AWS_PROFILE`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, … | Standard AWS SDK env vars (Stratus inherits). |
| `AZURE_*`, `ARM_*` | Azure SDK + Terraform AzureRM provider env vars. |
| `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT` | GCP auth. |
| `KUBECONFIG` | Kubernetes context. |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Entra ID Graph auth. |

### YAML config file (added v2.30.0, March 2025)

`~/.stratus-red-team/config.yaml` (overridable with `--config` or `$STRATUS_CONFIG_PATH`):

```yaml
output: json
state_backend: s3
s3_bucket: my-stratus-state
s3_key_prefix: team-purple/
detonation_id: "{{ .User }}-{{ .Date }}-{{ .Technique }}"  # template (v2.32.0)
aws:
  region: us-east-1
  profile: stratus-sandbox
azure:
  subscription_id: 00000000-...
gcp:
  project: stratus-sandbox-123
kubernetes:
  context: kind-stratus
  pod_annotations:                       # v2.32.0
    purpose: "purple-team"
  resource_labels:                       # v2.32.0 — stage = warmup|detonation
    team: detection
```

`detonation_id` is a Go-template string interpolated at detonate time and surfaced as `stratus.detonation_id` in cloud audit logs (tag/label on every created resource). The Rust port MUST use the `tinytemplate` or `minijinja` crate to honor the same `{{ .Var }}` syntax bit-for-bit.

### Programmatic / library API (added v2.31.0)

Upstream exposes a Go library (`github.com/datadog/stratus-red-team/v2/pkg/stratus`) so other tools can drive techniques without shelling out. The Rust port mirrors this with a public `lancer_stratus_red_team_core` crate (re-exported from the workspace root) exposing:

- `runner::Runner::new(StateManager, TerraformManager, CloudProviders, Config)`
- pluggable `StateManager` trait (filesystem + S3 + in-memory test backend)
- pluggable `TerraformManager` trait (real binary subprocess + mock for unit tests)
- `runner.warmup(id) / detonate(id) / revert(id) / cleanup(id)` returning typed `Result<DetonationOutputs, RunnerError>`

## Expanded technique catalogue deltas (post-2024)

The historical AWS-43 / GCP-25 / total-99 numbers documented earlier in this file are the legacy v2.x figures. Between v2.28 → v2.32.1 the live catalogue moved to **AWS 51 / Azure 11 / GCP 24 / EKS 2 / K8s 8 / Entra ID 7 = 103**. Net additions to port:

**AWS (+8 net)** — additional Bedrock, SES, SageMaker, Roles Anywhere, EC2 Instance Connect, and S3 ransomware family techniques (already partially listed above — verify exact IDs against `pkg/internal/attacktechniques/aws/**` at the v2.32.1 tag).

**GCP additions** (must be in the catalog):
- `gcp.execution.vertex-ai-workbench-startup-script` — inject malicious script into Vertex AI Workbench instance (v2.32.0).
- `gcp.impact.gcs-ransomware-individual-deletion` (v2.32.0).
- `gcp.impact.gcs-ransomware-client-side-encryption` (v2.32.0).
- `gcp.defense-evasion.organizations-leave` — attempt to remove project from org (v2.31.0).
- `gcp.defense-evasion.delete-dns-logging-policy`, `delete-log-sink`, `disable-log-sink`, `disable-audit-logs`, `reduce-log-retention`, `vpc-disable-flow-logs` (v2.31.0).
- `gcp.discovery.gce-instance-metadata-compute-api` (v2.31.0).
- `gcp.impact.create-gpu-vm`, `gcp.impact.create-multi-zone-instances` — crypto-mining-style abuse.

**Azure additions:**
- `azure.persistence.backdoor-managed-identity-fic` — backdoor Managed Identity with Federated Identity Credential (v2.31.0). Already mentioned but reconfirm subcategory.

**Entra ID additions:**
- `entra-id.persistence.backdoor-application-fic` — Federated Identity Credential backdoor on Entra application (v2.31.0).
- `entra-id.privilege-escalation.root-user-access-administrator` — elevate to User Access Administrator at root scope (v2.29.0).
- `entra-id.persistence.restricted-au` — Restricted Management Administrative Unit sticky backdoor (Microsoft-recommended-against-now feature abused for persistence).

## State machine (canonical — v2.32.1)

```
              ┌──────────────────────────────────────────────┐
              │                                              │
              │              ┌──── revert ─┐                 │
              ▼              │             │                 │
            COLD ── warmup ──┴──> WARM ────┴──> DETONATED ───┘
              ▲                    │
              │                    └─── cleanup ──> COLD
              └─── cleanup ────────────────────────  (force from any state)
```

- `warmup` is idempotent on a WARM technique (no-op + log).
- `detonate` from COLD auto-warmups unless `--no-warmup`.
- `revert` from DETONATED returns to WARM (prereq infra still up — re-detonate cheap).
- `cleanup` from any state runs `terraform destroy` and returns to COLD; with `--force` it ignores missing state.
- `--all` on `cleanup` iterates every directory under `$STRATUS_HOME` with a `state.json`.

## Filter & severity model

Each technique declares a `Severity` (`Low|Medium|High|Critical`) in addition to its tactic. The filter flags compose with AND semantics:

```
stratus list --platform aws --tactic persistence --severity high
stratus list --platform gcp --platform azure --tactic exfiltration --output json
```

Rust port: encode tactics as an enum, severities as enum, filters as a `TechniqueFilter` struct with `matches(&AttackTechnique) -> bool`.

## Engineering hard parts

**Cleanup idempotency:** `Revert` and `CleanUp` must succeed when called twice (e.g., after a failed run). Pattern: every delete wrapped in "if not found, ignore." Terraform handles this for prereqs, but custom Detonate side effects (e.g., a created IAM user) must be tracked in the outputs map so Revert can find them.

**State file management:** `~/.stratus-red-team/{technique-id}/` contains:
- `terraform.tfstate` (managed by terraform)
- `.terraform/` (init artifacts)
- `state.json` — Stratus's own state (current AttackTechniqueState, last warmup ts, detonate outputs)

For Rust clone: keep filesystem layout identical to allow tool interop. Use `serde_json` for state.json. For Terraform, **shell out to terraform binary** via `tokio::process::Command` (Hashicorp's terraform-exec library has no idiomatic Rust equivalent). Alternative: use OpenTofu binary.

**Terraform code embedding:** Go uses `//go:embed`. Rust equivalent: `include_str!("main.tf")` in each technique module. Write to a temp dir at warmup.

**Provider abstraction:** `providers.CloudProviders` struct holds lazy clients for AWS, Azure, GCP, K8s. In Rust:
```rust
struct CloudProviders {
    aws: OnceCell<AwsConfig>,
    azure: OnceCell<AzureCredential>,
    gcp: OnceCell<GcpAuth>,
    k8s: OnceCell<kube::Client>,
}
```

**Registry pattern:** Stratus uses `init()` blank imports. Rust analogue: `inventory` crate.
```rust
inventory::submit! {
    AttackTechnique {
        id: "aws.persistence.iam-backdoor-user",
        friendly_name: "Backdoor IAM User",
        ...
        detonate: detonate_iam_backdoor_user,
        revert: Some(revert_iam_backdoor_user),
    }
}
```

## Rust library mapping

```toml
[dependencies]
# AWS
aws-config = "1.8"
aws-sdk-iam = "1.109"
aws-sdk-sts = "1.85"
aws-sdk-ec2 = "1.150"
aws-sdk-s3 = "1.133"
aws-sdk-lambda = "1.100"
aws-sdk-secretsmanager = "1.85"
aws-sdk-ssm = "1.85"
aws-sdk-cloudtrail = "1.90"
aws-sdk-rds = "1.110"
aws-sdk-route53 = "1.85"
aws-sdk-ses = "1.85"
aws-sdk-organizations = "1.85"
aws-sdk-rolesanywhere = "1.85"
aws-sdk-bedrock = "1.85"
aws-sdk-bedrockruntime = "1.85"
aws-sdk-sagemaker = "1.85"
aws-sdk-ec2instanceconnect = "1.85"

# Azure
azure_identity = "0.21"
azure_mgmt_compute = "0.21"
azure_mgmt_storage = "0.21"
azure_mgmt_authorization = "0.21"
azure_mgmt_keyvault = "0.21"
graph-rs-sdk = "2"        # for Entra ID / Graph API

# GCP
google-cloud-iam = "0.5"
google-cloud-compute = "0.5"
google-cloud-storage = "0.20"
google-cloud-secretmanager = "0.5"

# Kubernetes
kube = { version = "3.1", features = ["runtime", "derive"] }
k8s-openapi = { version = "0.27", features = ["latest"] }

# Process / terraform
tokio = { version = "1.40", features = ["full", "process"] }

# Registry + state
inventory = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# CLI
clap = { version = "4.5", features = ["derive"] }
indicatif = "0.17"
colored = "2"

# Filesystem
dirs = "5"

# MITRE ATT&CK helpers
phf = { version = "0.11", features = ["macros"] }  # const maps
```

## SDK-specific gotchas

- **Detonate must produce CloudTrail signal:** every call must hit a real endpoint, not a stub. Use the actual SDK. Do not retry quietly — let the failed event surface.
- **Region selection:** most prereqs are us-east-1; some require multi-region. Allow `STRATUS_REGION` env var.
- **IAM eventual consistency:** after `CreateUser` you may need a 5-10s delay before `CreateAccessKey` succeeds. Stratus uses `helpers.WaitForAndCheck...`. Rust port: `tokio::time::sleep(Duration::from_secs(10)).await` with retry.
- **EC2 InstanceConnect:** `send_ssh_public_key()` is an IAM action `ec2-instance-connect:SendSSHPublicKey`. Requires VPC + running instance from Terraform.
- **Kubernetes:** `kube::Client::try_default()` reads kubeconfig or in-cluster service account. Detonations need `cluster-admin` to dump secrets — sandbox cluster only.
- **Entra ID:** Microsoft Graph SDK (`graph-rs-sdk`) is third-party; track upstream Microsoft's official Rust SDK if it appears.

## 2024-2026 state

- v2.x (2024) added Entra ID platform — major release. Federated Identity Credential (FIC) backdoors are the new hot persistence vector.
- Bedrock invocation technique (`aws.impact.bedrock-invoke-model`) added 2024 — covers GenAI cost abuse.
- Multiple `rolesanywhere` techniques added — IAM Roles Anywhere is increasingly used and abused.
- Active Datadog Security Labs research feeds new techniques quarterly.

> **2026-05-30 deep-research update** (verified against upstream `DataDog/stratus-red-team` v2.32.1, live `stratus-red-team.cloud` catalogue, and the public releases page):
> - Catalogue moved from **99 → 103 techniques** (AWS 43 → 51, GCP 25 → 24 [net of refactors], Azure/EKS/K8s/Entra ID unchanged). Update the parity matrix accordingly.
> - **v2.28.0** (2025-03-04) — Terraform pinned to 1.3.10; large internal refactor of `pkg/internal/attacktechniques/`.
> - **v2.29.0** (2025-03-09) — `entra-id.privilege-escalation.root-user-access-administrator`.
> - **v2.30.0** (2025-03-26) — YAML config file support (`~/.stratus-red-team/config.yaml`, `$STRATUS_CONFIG_PATH`).
> - **v2.31.0** (2025-04-14) — Programmatic API: pluggable `StateManager`, `TerraformManager`, custom cloud credentials, custom Terraform binary path. S3 state backend exposed as first-class flag. Adds Azure Managed Identity FIC backdoor, Entra ID FIC backdoor, six GCP defense-evasion / log-tampering techniques, GCP project-leave, GCE Compute-API metadata discovery.
> - **v2.32.0** (2025-05-20) — Vertex AI Workbench startup script (GCP), two GCS ransomware techniques. Kubernetes resources now labeled with `stratus.stage=warmup|detonation`. Pod annotations honored from config. Warmup leftover files auto-cleaned on failure. `detonation_id` becomes a Go-template string interpolated per detonation.
> - **v2.32.1** (2025-05-20) — Binary size halved (≈ -50%); config-file detonation-id templating polish.
> - **CLI surface** is fully enumerated in the new `## Complete CLI surface` section above; every flag, every subcommand, every env var, the YAML schema, and the canonical state-machine diagram are now captured for parity-test pinning.
> - Active issues on GitHub (May 2026) hint at upcoming AWS EventBridge / EKS Pod Identity / Azure Logic App techniques — keep the registry open-ended (no fixed-size arrays).

## Validation environment

- **Mandatory sandbox account** — never run against prod. Stratus enforces nothing; the clone *must* warn loudly on detonate.
- **kind cluster** for k8s techniques: `kind create cluster --config sandbox-kind.yaml`.
- **Azure free trial subscription**.
- **GCP isolated project**.
- **Terraform** binary in PATH (≥1.5.0) or OpenTofu.

## Real-world authorized usage

Stratus is a **purple team** tool, not a bug-bounty tool. Use cases:
- Validate that your SIEM detects `cloudtrail-stop`.
- Verify GuardDuty `Persistence:IAMUser/AnomalousBehavior` fires.
- Test SOC playbooks.

For bug bounty: ill-suited (every detonate generates infra cost + noisy logs). However, **read-only techniques** (e.g., `ssm-retrieve-securestring-parameters`) demonstrate IAM-permission impact in a clean way that bug-bounty triagers like.

## AI augmentation ideas

- **Detection rule generator:** for each technique, LLM produces a Sigma/EQL/KQL rule tailored to the user's SIEM.
- **Coverage gap analysis:** ingest the user's existing detection rules, find techniques without coverage, recommend new rules.
- **Threat narrative:** chain N techniques and ask LLM to write a believable "APT operating in your environment" story for tabletop exercises.
- **Custom technique scaffolder:** given a natural-language description of an attack, LLM generates the Rust technique skeleton + Terraform.

## Implementation phases (12 weeks)

| Week | Deliverable |
|------|-------------|
| 1 | Repo skeleton, `AttackTechnique` trait, inventory registration, CLI scaffolding (clap), state machine enum |
| 2 | Filesystem state manager, Terraform subprocess wrapper, lifecycle runner (warm/detonate/revert/cleanup) |
| 3 | AWS provider factory, first 5 AWS persistence techniques (iam-backdoor-user, iam-create-admin-user, lambda-backdoor-function, lambda-overwrite-code, iam-create-user-login-profile) |
| 4 | AWS credential-access (5 techniques) |
| 5 | AWS defense-evasion (7 techniques) |
| 6 | AWS execution + exfiltration (10 techniques) |
| 7 | AWS impact (ransomware) + lateral-movement (6 techniques) |
| 8 | AWS discovery + privilege-escalation + remaining (10 techniques) — AWS complete |
| 9 | Azure provider + 11 Azure techniques |
| 10 | GCP provider + 15 highest-value GCP techniques |
| 11 | Kubernetes + EKS techniques (10 total) |
| 12 | S3 backend state manager, OCSF/JSON output, detection-rule export, Entra ID stretch goal |

---

## GUI (Lancer-standard pattern)

`lancer-stratus-red-team` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-stratus-red-team-cli` companion binary), but the **plain `lancer-stratus-red-team` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-stratus-red-team/`, `%APPDATA%\lancer-stratus-red-team\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-stratus-red-team-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-stratus-red-team.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-stratus-red-team.exe` (double-click opens the GUI window).
- Linux: `build/lancer-stratus-red-team` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-stratus-red-team` (bundled into `lancer-stratus-red-team.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-stratus-red-team/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-stratus-red-team.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-stratus-red-team-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-stratus-red-team
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-stratus-red-team.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-stratus-red-team-windows-x86_64\bin\lancer-stratus-red-team.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-stratus-red-team`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
