#![allow(missing_docs, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aios_integration::composition::ServiceComposition;
use aios_integration::composition_engine::default_aios_composition;
use aios_integration::orchestrator::Orchestrator;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aios-system",
    about = "AIOS system orchestrator — typed scaffold for the 17-crate boot sequence",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the default boot sequence in topological order.
    Boot,
    /// Validate an external JSON `ServiceComposition` file.
    Validate {
        /// Path to the JSON composition file.
        composition_file: PathBuf,
    },
    /// Alias for boot — emit only the topological order of service IDs.
    Topo,
    /// List all services with crate names and binding endpoints.
    Services,
    /// Print scaffold health status for every service.
    HealthCheck,
    /// Run one AIOS service slot under systemd's supervision.
    RunService {
        /// Unit/service name, such as `aios-policy-kernel` or `aios-policy`.
        service_id: String,
        /// AIOS configuration file consumed by the service slot.
        #[arg(long, default_value = "/etc/aios/config.toml")]
        config: PathBuf,
        /// Directory where the service runner writes readiness state.
        #[arg(long, default_value = "/var/lib/aios/state")]
        state_dir: PathBuf,
        /// Validate and write state, then exit. Used by tests and oneshot units.
        #[arg(long)]
        once: bool,
    },
}

const SERVICE_ALIASES: &[(&str, &str)] = &[
    ("aios-policy-kernel", "aios-policy"),
    ("aios-evidence-log", "aios-evidence"),
    ("aios-fs-daemon", "aios-fs"),
    ("aios-vault-broker", "aios-vault"),
    ("aios-recovery-watchdog", "aios-recovery"),
    ("aios-sandbox-composer", "aios-sandbox"),
    ("aios-sgr-daemon", "aios-sgr"),
    ("aios-cognitive-core", "aios-cognitive"),
    ("aios-network-daemon", "aios-network"),
    ("aios-hardware-daemon", "aios-hardware"),
];

const EXTRA_SERVICE_IDS: &[&str] = &[
    "aios-autonomous",
    "aios-container",
    "aios-fleet",
    "aios-hardening",
    "aios-marketplace",
    "aios-terminal",
];

fn normalize_service_id(input: &str) -> Option<String> {
    let unit_name = input.strip_suffix(".service").unwrap_or(input);

    for (alias, canonical) in SERVICE_ALIASES {
        if unit_name == *alias {
            return Some((*canonical).to_string());
        }
    }

    let comp = default_aios_composition();
    if comp
        .services
        .iter()
        .any(|svc| svc.service_id == unit_name || svc.crate_name == unit_name)
    {
        return Some(unit_name.to_string());
    }

    if EXTRA_SERVICE_IDS.contains(&unit_name) {
        return Some(unit_name.to_string());
    }

    None
}

fn state_file_name(service_id: &str) -> String {
    service_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_service_state(
    requested_id: &str,
    canonical_id: &str,
    config: &Path,
    state_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(state_dir)?;

    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let state_path = state_dir.join(format!("{}.json", state_file_name(requested_id)));
    let state = serde_json::json!({
        "requested_service_id": requested_id,
        "canonical_service_id": canonical_id,
        "config": config.display().to_string(),
        "status": "scaffold-ready",
        "started_at_unix": started_at_unix,
    });

    std::fs::write(&state_path, serde_json::to_vec_pretty(&state)?)?;
    Ok(state_path)
}

fn run_service_slot(
    service_id: &str,
    config: &Path,
    state_dir: &Path,
    once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical_id = normalize_service_id(service_id)
        .ok_or_else(|| format!("unknown AIOS service slot: {service_id}"))?;
    let state_path = write_service_state(service_id, &canonical_id, config, state_dir)?;

    println!(
        "aios-system service runner active: requested={service_id} canonical={canonical_id} state={}",
        state_path.display()
    );

    if once {
        return Ok(());
    }

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Boot => {
            let orch = Orchestrator::from_default_composition()?;
            let order = orch.boot_order().await;
            let comp = default_aios_composition();
            for (i, id) in order.iter().enumerate() {
                let svc = comp
                    .services
                    .iter()
                    .find(|s| &s.service_id == id)
                    .expect("service not in default composition — invariant violated");
                println!(
                    "[{i}] {id} (crate={crate}, endpoint={endpoint})",
                    crate = svc.crate_name,
                    endpoint = svc.binding_endpoint
                );
            }
        }
        Command::Validate { composition_file } => {
            let json = std::fs::read_to_string(&composition_file)?;
            let comp: ServiceComposition = serde_json::from_str(&json)?;
            let engine = aios_integration::composition_engine::CompositionEngine::new();
            let order = engine.validate(&comp).await?;
            println!("validation passed — topological order:");
            for (i, id) in order.iter().enumerate() {
                println!("  [{i}] {id}");
            }
        }
        Command::Topo => {
            let orch = Orchestrator::from_default_composition()?;
            let order = orch.boot_order().await;
            for id in &order {
                println!("{id}");
            }
        }
        Command::Services => {
            let comp = default_aios_composition();
            println!("{} services in default composition:\n", comp.services.len());
            for svc in &comp.services {
                println!(
                    "  {id}  crate={crate}  endpoint={endpoint}",
                    id = svc.service_id,
                    crate = svc.crate_name,
                    endpoint = svc.binding_endpoint
                );
            }
        }
        Command::HealthCheck => {
            let orch = Orchestrator::from_default_composition()?;
            let summaries = orch.health_summary().await;
            for s in &summaries {
                println!("{id}: scaffold-ready", id = s.service_id);
            }
        }
        Command::RunService {
            service_id,
            config,
            state_dir,
            once,
        } => run_service_slot(&service_id, &config, &state_dir, once)?,
    }

    Ok(())
}
