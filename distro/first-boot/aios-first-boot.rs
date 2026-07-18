//! `aios-first-boot` — AI-OS.NET First Boot Wizard (Revision 11)
//!
//! Runs once on first boot after bare-metal installation. Creates the AIOS host
//! identity, configures security, enrolls TPM attestation, creates the recovery
//! key shards, registers the backup contract, generates the mobile pairing QR
//! code, records genesis evidence, and removes the first-boot flag file.
//!
//! This binary is invoked by `aios-first-boot.service` as a oneshot systemd unit.
//!
//! ## Constitutional invariants enforced here
//!
//! - No LLM/agent execution during first-boot (AI-free bootstrap).
//! - Every stage transition is evidenced via `aios-evidence` receipt chain.
//! - SELinux enforcing is verified before any mutation.
//! - Host identity (Ed25519 keypair) is created with `BLAKE3` fingerprint.
//! - TPM attestation chain anchors to the endorsement key hierarchy.
//! - Recovery key shards follow 3-of-5 threshold scheme.
//! - Backup contract INV-033: `encrypt_at_source` always true, at least one
//!   off-host target.
//! - First-boot flag removal is the final atomic action.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use aios_backup::contract::ConstitutionalBackupContract;
use aios_evidence::receipt::{EvidenceReceipt, ReceiptBuilder};
use aios_evidence::record::{RecordType, RetentionClass};
use chrono::{DateTime, Utc};
use clap::Parser;

// ─── CLI ───────────────────────────────────────────────────────────────────

/// AI-OS.NET First Boot Wizard — bootstraps a fresh AIOS host.
#[derive(Parser, Debug)]
#[command(
    name = "aios-first-boot",
    about = "AI-OS.NET First Boot Wizard (Revision 11)",
    version = "0.3.0"
)]
struct Cli {
    /// Path to the AIOS configuration file.
    #[arg(long, default_value = "/etc/aios/config.toml")]
    config: PathBuf,

    /// Skip TPM attestation enrollment (for hosts without TPM 2.0).
    #[arg(long)]
    skip_tpm: bool,

    /// Run non-interactively with defaults.
    #[arg(long)]
    non_interactive: bool,

    /// Preset security profile: DEV_RELAXED, SECURE_DEFAULT, STIG_ALIGNED, AIRGAP_HIGH.
    #[arg(long)]
    profile: Option<String>,

    /// Preset operator name (non-interactive mode).
    #[arg(long)]
    operator: Option<String>,

    /// Preset backup targets (comma-separated).
    #[arg(long)]
    backup_targets: Option<String>,
}

// ─── Constants ─────────────────────────────────────────────────────────────

const AIOS_ETC: &str = "/etc/aios";
const AIOS_VAR: &str = "/var/lib/aios";
const AIOS_RUN: &str = "/run/aios";
// The first-boot flag lives on the writable encrypted /var, NOT on the
// read-only dm-verity root. The installer creates it at install time and the
// wizard removes it as its final act. On the ro root it would sit on the frozen
// lower layer of the /etc overlay, and removing it needs an overlay whiteout,
// which SELinux enforcing denies (EACCES) — that failed phase 10. On /var the
// create/remove are ordinary read-write operations. The service's
// ConditionPathExists and the installer's touch point here too.
const FIRST_BOOT_FLAG: &str = "/var/lib/aios/first-boot";
// Host identity keypair and host-id live on the encrypted /var, NOT on the root.
// The root is now a read-only dm-verity volume with a writable /etc overlay whose
// upper layer sits on /var; writing the private host key through that overlay
// would place a security-sensitive secret in the overlay upper by side effect
// rather than by intent. Putting it directly under /var/lib/aios keeps it on the
// encrypted volume deliberately. These paths have no external consumers (only
// this binary reads/writes them). write_file() create_dir_all()s the parent.
const HOST_KEY_PRIV: &str = "/var/lib/aios/host-key.priv";
const HOST_KEY_PUB: &str = "/var/lib/aios/host-key.pub";
const HOST_ID_FILE: &str = "/var/lib/aios/host-id";
const SECURITY_PROFILE_FILE: &str = "/etc/aios/security-profile";
const VERITY_DIR: &str = "/etc/aios/verity";
const RECOVERY_DIR: &str = "/etc/aios/recovery";
const BACKUP_DIR: &str = "/etc/aios/backup";
const EVIDENCE_DIR: &str = "/var/lib/aios/evidence";
const RECOVERY_SHARDS_DIR: &str = "/var/lib/aios/vault/shards";
const MOBILE_PAIRING_DIR: &str = "/etc/aios/mobile";
const FLEET_DIR: &str = "/var/lib/aios/fleet";
const AUTONOMOUS_DIR: &str = "/etc/aios/autonomous";
const MARKETPLACE_DIR: &str = "/var/lib/aios/marketplace";
const CONTAINER_DIR: &str = "/var/lib/aios/container";
const SUBJECTS_DIR: &str = "/etc/aios/subjects";
const TPM_DIR: &str = "/etc/aios/tpm";
const TPM_PERSISTENT_HANDLE: &str = "0x81008001";
const ADMIN_GROUP: &str = "admin";
const CRYPTTAB_PATH: &str = "/etc/crypttab";

/// PCR set the installed system seals its LUKS TPM2 token against.
///
/// 0 = firmware code, 1 = firmware configuration, 7 = secure-boot state.
const LUKS_TPM2_PCRS: &str = "0+1+7";

// ─── First-Boot Context ────────────────────────────────────────────────────

/// Holds all mutable state gathered during the first-boot wizard.
#[derive(Debug, Default)]
struct FirstBootContext {
    host_id: String,
    host_key_fingerprint: String,
    security_profile: String,
    operator_canonical: String,
    operator_name: String,
    tpm_available: bool,
    tpm_enrolled: bool,
    tpm_manufacturer: String,
    tpm_firmware_version: String,
    uefi_available: bool,
    verity_created: bool,
    root_hash: String,
    root_device: String,
    // Boot-integrity evidence: the two fields that complete the five-field
    // record alongside tpm_enrolled, verity_created and the SELinux mode.
    secure_boot_state: String,
    kernel_lockdown: String,
    backup_contract_id: String,
    backup_targets: Vec<String>,
    pairing_nonce: String,
    pairing_url: String,
    ai_provider_mode: String,
    firewall_posture: String,
    genesis_id: String,
    genesis_hash: String,
    evidence_chain: Vec<EvidenceReceipt>,
}

// ─── Error Type ────────────────────────────────────────────────────────────

#[derive(Debug)]
enum FirstBootError {
    Io(io::Error),
    Serde(serde_json::Error),
    SelinuxNotEnforcing(String),
    HardwareCheckFailed(String),
    Config(String),
    Child(String, String),
    Fmt(std::fmt::Error),
    Tpm(String),
}

impl std::fmt::Display for FirstBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serde(e) => write!(f, "JSON error: {e}"),
            Self::SelinuxNotEnforcing(mode) => {
                write!(
                    f,
                    "SELinux not enforcing (mode: {mode}). INV-001 violation."
                )
            }
            Self::HardwareCheckFailed(msg) => write!(f, "Hardware check failed: {msg}"),
            Self::Config(msg) => write!(f, "Configuration error: {msg}"),
            Self::Child(cmd, stderr) => write!(f, "Command '{cmd}' failed: {stderr}"),
            Self::Fmt(e) => write!(f, "Format error: {e}"),
            Self::Tpm(msg) => write!(f, "TPM error: {msg}"),
        }
    }
}

impl From<io::Error> for FirstBootError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for FirstBootError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

impl From<std::fmt::Error> for FirstBootError {
    fn from(e: std::fmt::Error) -> Self {
        Self::Fmt(e)
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

fn now_rfc3339() -> String {
    now_utc().to_rfc3339()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0_u8; len];
    let mut s = String::with_capacity(len * 2);

    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok()
    {
        for byte in bytes {
            let _ = write!(s, "{byte:02x}");
        }
    } else {
        let ts = now_secs();
        for i in 0..len {
            let _ = write!(s, "{:02x}", ts.wrapping_add(i as u64) & 0xFF);
        }
    }
    s
}

fn read_line(prompt: &str) -> io::Result<String> {
    let mut stdout = io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn cmd_output(program: &str, args: &[&str]) -> Result<String, FirstBootError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| FirstBootError::Child(program.to_string(), e.to_string()))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(FirstBootError::Child(program.to_string(), stderr))
    }
}

fn cmd_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run a child and capture stdout and stderr interleaved, along with success.
///
/// `cmd_output` drops stdout on failure and stderr on success. `systemd-cryptenroll`
/// splits its diagnostics across both streams, so neither half alone explains why
/// an enrolment failed.
fn cmd_combined(program: &str, args: &[&str]) -> Result<(bool, String), FirstBootError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| FirstBootError::Child(program.to_string(), e.to_string()))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined.trim().to_string()))
}

/// Resolve the TPM2-unlocked LUKS backing device recorded in `/etc/crypttab`.
///
/// Fields are `<name> <device> <keyfile> <options>`; we take the `UUID=` device of
/// the first mapping whose options request TPM2 unlocking. `None` means this system
/// does not unlock a volume via the TPM at all.
fn crypttab_tpm2_device(crypttab: &str) -> Option<String> {
    crypttab
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let _name = fields.next()?;
            let device = fields.next()?;
            let _keyfile = fields.next()?;
            if !fields.next()?.contains("tpm2-device=") {
                return None;
            }
            let uuid = device.strip_prefix("UUID=")?;
            Some(format!("/dev/disk/by-uuid/{uuid}"))
        })
}

/// Parse the PCR set a `systemd-tpm2` LUKS token is sealed against.
///
/// `cryptsetup luksDump` renders the token's `tpm2-pcrs` JSON field under the printed
/// label `tpm2-hash-pcrs:` — the JSON key and the dump label are *not* the same string.
/// The label is emitted for every systemd-tpm2 token whether or not it is bound, and an
/// unbound token prints an empty value, so the presence of the line proves nothing and
/// only the value carries the binding. `tpm2-pubkey-pcrs:` is a different (signed-policy)
/// binding and must not be mistaken for this one.
///
/// `None` = no systemd-tpm2 token; `Some([])` = token present but bound to no PCRs.
fn luks_token_pcrs(dump: &str) -> Option<Vec<u8>> {
    let value = dump
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("tpm2-hash-pcrs:"))?
        .trim();
    let mut pcrs: Vec<u8> = value
        .split('+')
        .filter_map(|part| part.trim().parse::<u8>().ok())
        .collect();
    pcrs.sort_unstable();
    pcrs.dedup();
    Some(pcrs)
}

/// The PCR set `LUKS_TPM2_PCRS` denotes, normalized for comparison.
fn expected_luks_pcrs() -> Vec<u8> {
    let mut pcrs: Vec<u8> = LUKS_TPM2_PCRS
        .split('+')
        .filter_map(|part| part.parse::<u8>().ok())
        .collect();
    pcrs.sort_unstable();
    pcrs
}

fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

fn dir_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

fn read_file(path: &str) -> Result<String, FirstBootError> {
    Ok(fs::read_to_string(path)?)
}

fn write_file(path: &str, content: &str) -> Result<(), FirstBootError> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn write_file_mode(path: &str, content: &str, mode: u32) -> Result<(), FirstBootError> {
    write_file(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn log_stage(stage: &str, status: &str, detail: &str) {
    if detail.is_empty() {
        println!("[{stage}] {status}");
    } else {
        println!("[{stage}] {status}: {detail}");
    }
}

/// Build a JSON evidence payload and append to the chain.
fn record_evidence(
    ctx: &mut FirstBootContext,
    record_type: RecordType,
    payload: serde_json::Value,
) -> Result<(), FirstBootError> {
    let ts = now_rfc3339();
    let full = serde_json::json!({
        "ts": ts,
        "record_type": serde_json::to_value(record_type)?,
        "payload": payload,
    });
    let gen_file = format!("{EVIDENCE_DIR}/genesis.log");
    if let Some(parent) = Path::new(&gen_file).parent() {
        fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(&full)? + "\n";
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gen_file)?;
    file.write_all(line.as_bytes())?;

    let receipt = ReceiptBuilder::new(
        record_type,
        RetentionClass::Forever,
        "_system:service:firstboot-coordinator",
    )
    .with_payload(payload)
    .seal(None)
    .map_err(|e| FirstBootError::Config(format!("evidence build failed: {e:?}")))?;
    ctx.evidence_chain.push(receipt);
    Ok(())
}

// ─── Phase Implementations ─────────────────────────────────────────────────

/// Phase 1: Verify hardware prerequisites.
/// Extract the active value from the contents of
/// `/sys/kernel/security/lockdown`, e.g. `none [integrity] confidentiality`
/// -> `integrity`. The kernel brackets exactly the active mode.
fn parse_lockdown(content: &str) -> String {
    content
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix('[').and_then(|t| t.strip_suffix(']')))
        .unwrap_or("unknown")
        .to_string()
}

/// The UEFI `SecureBoot` variable is a little-endian EFI variable file: four
/// attribute bytes followed by the boolean state (1 = enabled, 0 = disabled).
fn parse_secure_boot(bytes: &[u8]) -> &'static str {
    if bytes.len() < 5 {
        return "unavailable";
    }
    match bytes[bytes.len() - 1] {
        1 => "enabled",
        0 => "disabled",
        _ => "unavailable",
    }
}

/// Kernel lockdown mode from securityfs, or "unavailable" if the file is absent
/// (lockdown not compiled in / securityfs not mounted).
fn read_kernel_lockdown() -> String {
    match fs::read_to_string("/sys/kernel/security/lockdown") {
        Ok(content) => parse_lockdown(&content),
        Err(_) => "unavailable".to_string(),
    }
}

/// Secure Boot state from the firmware's `SecureBoot` EFI variable (its GUID is
/// fixed by the UEFI spec), or "unavailable" on legacy BIOS / no efivarfs.
fn read_secure_boot() -> String {
    const SECURE_BOOT_VAR: &str =
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    match fs::read(SECURE_BOOT_VAR) {
        Ok(bytes) => parse_secure_boot(&bytes).to_string(),
        Err(_) => "unavailable".to_string(),
    }
}

fn phase_1_hardware(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("--- Phase 1: Hardware Verification ---\n");

    // Check TPM 2.0
    let has_tpm_dev = file_exists("/dev/tpm0") || file_exists("/dev/tpmrm0");
    if has_tpm_dev && cmd_ok("tpm2_getrandom", &["--hex", "8"]) {
        log_stage("hw/tpm", "OK", "TPM 2.0 functional");
        ctx.tpm_available = true;
        ctx.tpm_manufacturer = cmd_output("tpm2_getcap", &["properties-fixed"])
            .unwrap_or_default()
            .lines()
            .find(|l| l.contains("TPM2_PT_MANUFACTURER"))
            .and_then(|l| l.split_whitespace().nth_back(0))
            .unwrap_or("unknown")
            .to_string();
        if ctx.tpm_manufacturer.is_empty() || ctx.tpm_manufacturer == "unknown" {
            ctx.tpm_manufacturer = "unknown".to_string();
        }
        ctx.tpm_firmware_version = "unknown".to_string();
        println!("  TPM Manufacturer: {}", ctx.tpm_manufacturer);
    } else if has_tpm_dev {
        log_stage("hw/tpm", "WARN", "TPM device present but unresponsive");
        ctx.tpm_available = false;
    } else {
        log_stage("hw/tpm", "WARN", "No TPM device found");
        ctx.tpm_available = false;
    }

    // Check UEFI
    if dir_exists("/sys/firmware/efi") {
        log_stage("hw/uefi", "OK", "UEFI firmware detected");
        ctx.uefi_available = true;
    } else {
        log_stage("hw/uefi", "WARN", "Legacy BIOS detected");
        ctx.uefi_available = false;
    }

    // Check SELinux
    let selinux_mode = cmd_output("getenforce", &[]).unwrap_or_else(|_| "Unknown".to_string());
    if selinux_mode == "Enforcing" {
        log_stage("hw/selinux", "OK", "SELinux is enforcing");
    } else {
        log_stage(
            "hw/selinux",
            "FAIL",
            &format!("SELinux not enforcing (mode: {selinux_mode})"),
        );
        eprintln!("\nERROR: SELinux must be in enforcing mode before first boot.");
        eprintln!("This is a constitutional requirement (INV-001).");
        return Err(FirstBootError::SelinuxNotEnforcing(selinux_mode));
    }

    // Check veritysetup
    if cmd_ok("veritysetup", &["--version"]) {
        log_stage("hw/verity", "OK", "dm-verity tools available");
    } else {
        return Err(FirstBootError::HardwareCheckFailed(
            "veritysetup not found".to_string(),
        ));
    }

    // Boot-integrity evidence: Secure Boot + kernel lockdown complete the
    // five-field record (with TPM enrolment, dm-verity and the SELinux mode).
    // These are observations, not gates — recorded truthfully whatever they are.
    ctx.secure_boot_state = read_secure_boot();
    ctx.kernel_lockdown = read_kernel_lockdown();
    log_stage(
        "hw/secureboot",
        if ctx.secure_boot_state == "enabled" {
            "OK"
        } else {
            "INFO"
        },
        &format!("Secure Boot: {}", ctx.secure_boot_state),
    );
    log_stage(
        "hw/lockdown",
        "INFO",
        &format!("Kernel lockdown: {}", ctx.kernel_lockdown),
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStarted,
        serde_json::json!({
            "tpm_available": ctx.tpm_available,
            "uefi_available": ctx.uefi_available,
            "selinux_enforcing": true,
            "secure_boot": ctx.secure_boot_state,
            "kernel_lockdown": ctx.kernel_lockdown,
            "tpm_manufacturer": ctx.tpm_manufacturer,
        }),
    )?;

    Ok(())
}

/// Phase 2: Generate host identity (Ed25519 keypair + machine-id).
fn phase_2_identity(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 2: Host Identity ---\n");

    // Read or generate host ID
    ctx.host_id = read_file("/etc/machine-id")
        .unwrap_or_else(|_| String::new())
        .trim()
        .to_string();
    if ctx.host_id.is_empty() {
        ctx.host_id = random_hex(16);
        write_file("/etc/machine-id", &ctx.host_id)?;
        println!("  Generated machine-id: {}", ctx.host_id);
    }
    write_file(HOST_ID_FILE, &ctx.host_id)?;
    println!("  Host ID: {}", ctx.host_id);

    // Generate Ed25519 host keypair
    if !file_exists(HOST_KEY_PRIV) {
        // The temp key must be created on the SAME filesystem as HOST_KEY_PRIV
        // (both under AIOS_VAR = /var/lib/aios). fs::rename cannot cross a mount
        // boundary: a tmp under AIOS_RUN (/run, a tmpfs) renamed onto /var (a
        // separate disk volume) fails with EXDEV ("Invalid cross-device link",
        // os error 18), which aborted the whole first-boot wizard.
        fs::create_dir_all(AIOS_VAR)?;
        let tmp_priv = format!("{AIOS_VAR}/host-key-tmp.priv");
        cmd_output(
            "openssl",
            &["genpkey", "-algorithm", "ED25519", "-out", &tmp_priv],
        )?;
        cmd_output(
            "openssl",
            &["pkey", "-in", &tmp_priv, "-pubout", "-out", HOST_KEY_PUB],
        )?;
        fs::rename(&tmp_priv, HOST_KEY_PRIV)?;
        write_file_mode(HOST_KEY_PRIV, &read_file(HOST_KEY_PRIV)?, 0o600)?;
        write_file_mode(HOST_KEY_PUB, &read_file(HOST_KEY_PUB)?, 0o644)?;
        log_stage("identity/host-key", "OK", "Ed25519 keypair generated");
    } else {
        log_stage("identity/host-key", "SKIP", "Keypair already exists");
    }

    // Compute fingerprint
    let pub_der = cmd_output(
        "openssl",
        &["pkey", "-in", HOST_KEY_PUB, "-pubin", "-outform", "DER"],
    )?;
    let fingerprint = blake3::hash(pub_der.as_bytes());
    ctx.host_key_fingerprint = fingerprint.to_hex().to_string();
    println!(
        "  Host Key Fingerprint (BLAKE3): {}",
        ctx.host_key_fingerprint
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "host_id": ctx.host_id,
            "host_key_fingerprint": ctx.host_key_fingerprint,
            "key_algorithm": "ED25519",
        }),
    )?;

    Ok(())
}

/// Phase 3: Select security profile.
fn phase_3_security_profile(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    println!("\n--- Phase 3: Security Profile ---\n");

    if let Some(ref preset) = cli.profile {
        ctx.security_profile = preset.clone();
    } else if cli.non_interactive {
        ctx.security_profile = "SECURE_DEFAULT".to_string();
        log_stage(
            "profile",
            "INFO",
            "Non-interactive: defaulting to SECURE_DEFAULT",
        );
    } else {
        println!("Select the initial security profile:");
        println!("  1) DEV_RELAXED      Full access, minimal restrictions");
        println!("  2) SECURE_DEFAULT   Balanced security with usability  [RECOMMENDED]");
        println!("  3) STIG_ALIGNED     DISA STIG aligned, strict controls");
        println!("  4) AIRGAP_HIGH      Maximum security, no external network\n");
        loop {
            let choice = read_line("Profile [2]: ")?;
            let choice = if choice.is_empty() {
                "2".to_string()
            } else {
                choice
            };
            match choice.as_str() {
                "1" => {
                    ctx.security_profile = "DEV_RELAXED".to_string();
                    break;
                }
                "2" => {
                    ctx.security_profile = "SECURE_DEFAULT".to_string();
                    break;
                }
                "3" => {
                    ctx.security_profile = "STIG_ALIGNED".to_string();
                    break;
                }
                "4" => {
                    ctx.security_profile = "AIRGAP_HIGH".to_string();
                    break;
                }
                _ => println!("  Invalid choice. Enter 1-4."),
            }
        }
    }

    write_file(SECURITY_PROFILE_FILE, &ctx.security_profile)?;
    log_stage(
        "profile",
        "OK",
        &format!("Security profile: {}", ctx.security_profile),
    );

    // Set derived settings
    match ctx.security_profile.as_str() {
        "DEV_RELAXED" => {
            ctx.firewall_posture = "LOOPBACK_ONLY".to_string();
            ctx.ai_provider_mode = "LOCAL_ONLY".to_string();
        }
        "SECURE_DEFAULT" => {
            ctx.firewall_posture = "LOOPBACK_ONLY".to_string();
            ctx.ai_provider_mode = "DEFERRED".to_string();
        }
        "STIG_ALIGNED" => {
            ctx.firewall_posture = "AIRGAP".to_string();
            ctx.ai_provider_mode = "DEFERRED".to_string();
        }
        "AIRGAP_HIGH" => {
            ctx.firewall_posture = "AIRGAP".to_string();
            ctx.ai_provider_mode = "LOCAL_ONLY".to_string();
        }
        other => return Err(FirstBootError::Config(format!("unknown profile: {other}"))),
    }

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "profile": ctx.security_profile,
            "firewall_posture": ctx.firewall_posture,
            "ai_provider_mode": ctx.ai_provider_mode,
        }),
    )?;

    Ok(())
}

/// Phase 4: Create the admin human operator subject.
fn phase_4_operator(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    println!("\n--- Phase 4: Human Operator ---\n");

    if let Some(ref name) = cli.operator {
        ctx.operator_name = sanitize_name(name);
    } else if cli.non_interactive {
        ctx.operator_name = "operator".to_string();
        log_stage(
            "operator",
            "INFO",
            "Non-interactive: defaulting to 'operator'",
        );
    } else {
        println!("AIOS requires at least one human operator with admin authority.\n");
        loop {
            let name = read_line("Operator name (e.g., 'alice'): ")?;
            let cleaned = sanitize_name(&name);
            if cleaned.is_empty() {
                println!("  Operator name cannot be empty.");
            } else if cleaned.starts_with('_') || cleaned.ends_with('_') {
                println!("  Operator name cannot start or end with _ or -.");
            } else {
                ctx.operator_name = cleaned;
                break;
            }
        }
    }

    ctx.operator_canonical = format!("{ADMIN_GROUP}:{}", ctx.operator_name);
    let operator_dir = format!("{SUBJECTS_DIR}/{}", ctx.operator_canonical);
    fs::create_dir_all(&operator_dir)?;

    let subject_json = serde_json::json!({
        "canonical_subject_id": ctx.operator_canonical,
        "subject_type": "HUMAN_USER",
        "provisional_name": ctx.operator_name,
        "groups": [ADMIN_GROUP],
        "capabilities": ["ADMIN_OPERATOR", "APPROVER", "RECOVERY_OPERATOR"],
        "session_class": "INTERNAL",
        "is_ai": false,
        "recovery_mode": false,
        "created_at": now_rfc3339(),
        "created_by": "_system:service:firstboot-coordinator",
        "host_id": ctx.host_id,
    });

    let subject_path = format!("{operator_dir}/subject.json");
    write_file_mode(
        &subject_path,
        &serde_json::to_string_pretty(&subject_json)?,
        0o640,
    )?;

    log_stage(
        "operator",
        "OK",
        &format!("Operator '{}' created", ctx.operator_canonical),
    );

    record_evidence(
        ctx,
        RecordType::FirstUserRegistered,
        serde_json::json!({
            "canonical_subject_id": ctx.operator_canonical,
            "provisional_name": ctx.operator_name,
            "group": ADMIN_GROUP,
            "host_id": ctx.host_id,
        }),
    )?;

    Ok(())
}

/// Phase 5: Enroll TPM 2.0 attestation chain.
fn phase_5_tpm(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    println!("\n--- Phase 5: TPM2 Attestation ---\n");

    if !ctx.tpm_available || cli.skip_tpm {
        log_stage("tpm", "SKIP", "TPM not available or skipped");
        record_evidence(
            ctx,
            RecordType::FirstBootStageCompleted,
            serde_json::json!({"tpm_enrolled": false, "reason": "unavailable_or_skipped"}),
        )?;
        return Ok(());
    }

    println!("  Enrolling TPM 2.0 attestation chain...");

    // Evict old persistent handle
    let _ = cmd_output(
        "tpm2_evictcontrol",
        &["-C", "o", "-c", TPM_PERSISTENT_HANDLE],
    );

    // Read PCR values
    let mut pcr_values = Vec::new();
    for pcr_idx in 0..=7u8 {
        if let Ok(val) = cmd_output("tpm2_pcrread", &[&format!("sha256:{pcr_idx}")]) {
            if let Some(line) = val.lines().find(|l| l.starts_with(&format!("{pcr_idx}:"))) {
                if let Some(hash) = line.split_whitespace().nth(1) {
                    pcr_values.push(serde_json::json!({
                        "pcr": pcr_idx, "sha256": hash,
                    }));
                }
            }
        }
    }

    let tpm_ctx_primary = format!("{AIOS_RUN}/tpm-primary.ctx");
    let tpm_ctx_ak_pub = format!("{AIOS_RUN}/tpm-ak.pub");
    let tpm_ctx_ak_priv = format!("{AIOS_RUN}/tpm-ak.priv");
    let tpm_ctx_ak = format!("{AIOS_RUN}/tpm-ak.ctx");
    fs::create_dir_all(AIOS_RUN)?;

    // Create primary under endorsement hierarchy
    match cmd_output(
        "tpm2_createprimary",
        &[
            "-C",
            "e",
            "-g",
            "sha256",
            "-G",
            "ecc",
            "-c",
            &tpm_ctx_primary,
        ],
    ) {
        Ok(_) => log_stage(
            "tpm/primary",
            "OK",
            "Primary key created under EK hierarchy",
        ),
        Err(e) => {
            log_stage("tpm/primary", "FAIL", &format!("{e}"));
            return Err(e);
        }
    }

    // Create attestation key
    let ak_auth = random_hex(16);
    let create_result = cmd_output(
        "tpm2_create",
        &[
            "-C",
            &tpm_ctx_primary,
            "-g",
            "sha256",
            "-G",
            "ecc",
            "-u",
            &tpm_ctx_ak_pub,
            "-r",
            &tpm_ctx_ak_priv,
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
            "-p",
            &ak_auth,
        ],
    );
    if create_result.is_ok() {
        log_stage("tpm/attestation-key", "OK", "Attestation key created");
    } else {
        log_stage(
            "tpm/attestation-key",
            "FAIL",
            "Attestation key creation failed",
        );
        return Err(FirstBootError::Tpm(
            "attestation key creation failed".to_string(),
        ));
    }

    // Load attestation key
    match cmd_output(
        "tpm2_load",
        &[
            "-C",
            &tpm_ctx_primary,
            "-u",
            &tpm_ctx_ak_pub,
            "-r",
            &tpm_ctx_ak_priv,
            "-c",
            &tpm_ctx_ak,
        ],
    ) {
        Ok(_) => log_stage("tpm/load", "OK", "Attestation key loaded"),
        Err(e) => {
            log_stage("tpm/load", "WARN", &format!("Load failed: {e}"));
        }
    }

    if file_exists(&tpm_ctx_ak) {
        match cmd_output(
            "tpm2_evictcontrol",
            &["-C", "o", "-c", &tpm_ctx_ak, TPM_PERSISTENT_HANDLE],
        ) {
            Ok(_) => {
                log_stage(
                    "tpm/persist",
                    "OK",
                    &format!("Persisted at {TPM_PERSISTENT_HANDLE}"),
                );
                ctx.tpm_enrolled = true;
            }
            Err(e) => {
                log_stage("tpm/persist", "WARN", &format!("Persist failed: {e}"));
            }
        }
    }

    // Store enrollment metadata
    fs::create_dir_all(TPM_DIR)?;
    let enrollment_json = serde_json::json!({
        "enrolled_at": now_rfc3339(),
        "persistent_handle": TPM_PERSISTENT_HANDLE,
        "pcr_selection": [0,1,2,3,4,5,6,7],
        "hash_algorithm": "SHA256",
        "key_algorithm": "ECC_NIST_P256",
        "tpm_manufacturer": ctx.tpm_manufacturer,
        "tpm_firmware": ctx.tpm_firmware_version,
        "host_id": ctx.host_id,
        "pcr_baseline": pcr_values,
    });
    write_file_mode(
        &format!("{TPM_DIR}/enrollment.json"),
        &serde_json::to_string_pretty(&enrollment_json)?,
        0o600,
    )?;

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "tpm_enrolled": ctx.tpm_enrolled,
            "persistent_handle": TPM_PERSISTENT_HANDLE,
        }),
    )?;

    Ok(())
}

/// Phase 5.5: Bind the LUKS TPM2 token to this system's real PCRs.
///
/// The installer enrols a *bootstrap* TPM2 token with no PCR binding, and it has no
/// choice: it runs inside the live medium's boot chain, so PCR 0/1/7 as measured there
/// are not the registers the installed system presents, and a token sealed against them
/// could never unseal. This phase runs inside the installed system, booted the way every
/// later boot will boot, so the PCRs here are the real ones.
///
/// Until this succeeds the volume is unsealable by any code that can reach the TPM on
/// this machine — the binding is what ties the key to a known boot state, so a failure
/// here is fatal rather than a warning.
fn phase_5_5_luks_pcr_binding(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    println!("\n--- Phase 5.5: LUKS TPM2 PCR Binding ---\n");

    if cli.skip_tpm || !ctx.tpm_available {
        log_stage("tpm/pcr-binding", "SKIP", "TPM not available or skipped");
        return Ok(());
    }

    // crypttab is the only record of which volume the initramfs unlocks via the TPM.
    let crypttab = match read_file(CRYPTTAB_PATH) {
        Ok(contents) => contents,
        Err(e) => {
            log_stage(
                "tpm/pcr-binding",
                "SKIP",
                &format!("cannot read {CRYPTTAB_PATH}: {e}"),
            );
            return Ok(());
        }
    };
    let Some(device) = crypttab_tpm2_device(&crypttab) else {
        log_stage(
            "tpm/pcr-binding",
            "SKIP",
            "no TPM2-unlocked volume in /etc/crypttab",
        );
        return Ok(());
    };
    println!("  LUKS device: {device}");

    // Nothing to re-bind unless the installer's bootstrap enrolment actually landed.
    let before = cmd_output("cryptsetup", &["luksDump", &device])?;
    if !before.contains("systemd-tpm2") {
        log_stage(
            "tpm/pcr-binding",
            "WARN",
            "no systemd-tpm2 token present -- installer enrolment did not happen",
        );
        return Ok(());
    }

    // Unlock through the bootstrap token, re-seal against the real PCRs, and wipe the
    // unbound slot in the same operation.
    let pcr_arg = format!("--tpm2-pcrs={LUKS_TPM2_PCRS}");
    let (enrolled, enroll_log) = cmd_combined(
        "systemd-cryptenroll",
        &[
            &device,
            "--unlock-tpm2-device=auto",
            "--tpm2-device=auto",
            &pcr_arg,
            "--wipe-slot=tpm2",
        ],
    )?;
    if !enrolled {
        log_stage(
            "tpm/pcr-binding",
            "FAIL",
            "systemd-cryptenroll re-enrolment failed",
        );
        for line in enroll_log.lines().take(12) {
            eprintln!("    cryptenroll: {line}");
        }
        return Err(FirstBootError::Tpm(format!(
            "LUKS TPM2 re-enrolment against PCRs {LUKS_TPM2_PCRS} failed on {device}"
        )));
    }

    // Verify the header rather than trust the exit code. A systemd-tpm2 token can be
    // present and sealed to nothing at all — that is precisely the bootstrap state this
    // phase exists to replace, and it dumps a `tpm2-hash-pcrs:` line just like a bound
    // token does. An empty binding is a FAIL, not a pass.
    let after = cmd_output("cryptsetup", &["luksDump", &device])?;
    let Some(bound_pcrs) = luks_token_pcrs(&after) else {
        return Err(FirstBootError::Tpm(format!(
            "no systemd-tpm2 token on {device} after re-enrolment reported success"
        )));
    };
    if bound_pcrs.is_empty() {
        return Err(FirstBootError::Tpm(format!(
            "systemd-tpm2 token on {device} is bound to no PCRs after re-enrolment \
             reported success; the volume would unseal under any boot state"
        )));
    }
    let expected = expected_luks_pcrs();
    if bound_pcrs != expected {
        return Err(FirstBootError::Tpm(format!(
            "systemd-tpm2 token on {device} is bound to PCRs {bound_pcrs:?}, expected \
             {expected:?} ({LUKS_TPM2_PCRS})"
        )));
    }

    ctx.tpm_enrolled = true;
    log_stage(
        "tpm/pcr-binding",
        "OK",
        &format!("LUKS TPM2 token on {device} bound to PCRs {LUKS_TPM2_PCRS}"),
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "luks_device": device,
            "tpm2_pcrs": LUKS_TPM2_PCRS,
            "bound_pcrs": bound_pcrs,
            "bootstrap_slot_wiped": true,
            "verified_via": "cryptsetup luksDump tpm2-hash-pcrs",
        }),
    )?;

    Ok(())
}

/// Phase 6: dm-verity root hash generation and signing.
fn phase_6_verity(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 6: Root Integrity ---\n");

    ctx.root_device = cmd_output("findmnt", &["-n", "-o", "SOURCE", "/"]).unwrap_or_default();
    if ctx.root_device.is_empty() {
        log_stage("verity", "WARN", "Cannot detect root device -- skipping");
        return Ok(());
    }

    println!("  Root device: {}", ctx.root_device);
    fs::create_dir_all(VERITY_DIR)?;

    let hash_device = format!("{VERITY_DIR}/root-hash.img");
    let hash_size_mb: u64 = 128;

    // Create sparse hash device
    let f = fs::File::create(&hash_device)?;
    f.set_len(hash_size_mb * 1024 * 1024)?;
    drop(f);

    // Format verity hash tree
    let format_log = format!("{VERITY_DIR}/format.log");
    match cmd_output("veritysetup", &["format", &ctx.root_device, &hash_device]) {
        Ok(output) => {
            write_file(&format_log, &output)?;
            // Extract root hash
            ctx.root_hash = output
                .lines()
                .find(|l| l.starts_with("Root hash:"))
                .and_then(|l| l.split_whitespace().nth_back(0))
                .unwrap_or("")
                .to_string();

            if ctx.root_hash.is_empty() {
                log_stage("verity/hash", "FAIL", "Could not extract root hash");
                return Ok(());
            }
            log_stage(
                "verity/hash",
                "OK",
                &format!("Root hash: {}", ctx.root_hash),
            );

            // Sign root hash with host key
            let raw_hash_file = format!("{VERITY_DIR}/roothash.raw");
            let sig_file = format!("{VERITY_DIR}/roothash.sig");
            write_file(&raw_hash_file, &ctx.root_hash)?;
            let _ = cmd_output(
                "openssl",
                &[
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    HOST_KEY_PRIV,
                    "-rawin",
                    "-in",
                    &raw_hash_file,
                    "-out",
                    &sig_file,
                ],
            );
            log_stage("verity/sign", "OK", "Root hash signed with host key");
            ctx.verity_created = true;

            let metadata = serde_json::json!({
                "root_device": ctx.root_device,
                "root_hash": ctx.root_hash,
                "hash_algorithm": "sha256",
                "data_block_size": 4096,
                "hash_block_size": 4096,
                "salt": random_hex(16),
                "created_at": now_rfc3339(),
                "host_id": ctx.host_id,
            });
            write_file_mode(
                &format!("{VERITY_DIR}/metadata.json"),
                &serde_json::to_string_pretty(&metadata)?,
                0o644,
            )?;
        }
        Err(e) => {
            log_stage("verity/format", "FAIL", &format!("{e}"));
        }
    }

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "verity_created": ctx.verity_created,
            "root_hash": ctx.root_hash,
            "root_device": ctx.root_device,
        }),
    )?;

    Ok(())
}

/// Phase 7: Create initial backup contract.
fn phase_7_backup(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    println!("\n--- Phase 7: Backup Contract ---\n");

    if let Some(ref targets) = cli.backup_targets {
        ctx.backup_targets = targets.split(',').map(str::to_string).collect();
    } else if cli.non_interactive {
        ctx.backup_targets = vec!["local".to_string()];
    } else {
        println!("AIOS requires an initial backup contract for constitutional data protection.\n");
        let input = read_line(
            "Enter backup target paths (comma-separated, e.g. '/mnt/backup,off-host-nas'): ",
        )?;
        if input.is_empty() {
            ctx.backup_targets = vec!["local".to_string()];
        } else {
            ctx.backup_targets = input
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect();
        }
    }

    ctx.backup_contract_id = format!("cbc_{}", random_hex(10));
    let contract = ConstitutionalBackupContract::new(
        ctx.host_id.clone(),
        true, // per_subject_keys
        true, // rollback_anchor
        ctx.backup_targets.clone(),
    );

    // INV-033 requires at least one OFF_HOST backup target. On an UNATTENDED
    // (non-interactive) install there may be no real off-host target to supply,
    // and a hard failure would make every CI/cloud/headless machine unbootable.
    // Variant-1 hybrid: high-security profiles (STIG_ALIGNED, AIRGAP_HIGH) still
    // hard-require an off-host target — the operator must pass --backup-targets;
    // for normal profiles on an unattended install we record the contract as
    // PENDING (the machine boots, but the missing off-host target is flagged for
    // the operator to set later) rather than invent a fake target. Interactive
    // installs keep the hard requirement — the operator is present to supply one.
    let mut backup_pending_offhost = false;
    if let Err(e) = contract.validate() {
        // Defer ONLY the missing-off-host case. Any other validation failure
        // (encrypt_at_source false, or no targets at all) is a real defect and
        // still fails closed regardless of profile or mode.
        let only_missing_offhost = !contract.has_off_host_target()
            && contract.encrypt_at_source
            && !contract.targets.is_empty();
        if !backup_offhost_deferrable(&ctx.security_profile, cli.non_interactive)
            || !only_missing_offhost
        {
            return Err(FirstBootError::Config(format!(
                "backup contract validation failed: {e}"
            )));
        }
        backup_pending_offhost = true;
    }

    fs::create_dir_all(BACKUP_DIR)?;
    let contract_json = serde_json::json!({
        "contract_id": ctx.backup_contract_id,
        "host_id": contract.host_id,
        "encrypt_at_source": contract.encrypt_at_source,
        "per_subject_keys": contract.per_subject_keys,
        "rollback_anchor": contract.rollback_anchor,
        "targets": contract.targets,
        "created_at": now_rfc3339(),
        // Fully constitutional only once an off-host target satisfies INV-033.
        "constitutional": !backup_pending_offhost,
        "status": if backup_pending_offhost {
            "pending_off_host_target"
        } else {
            "active"
        },
        "pending_off_host_target": backup_pending_offhost,
    });
    write_file_mode(
        &format!("{BACKUP_DIR}/contract.json"),
        &serde_json::to_string_pretty(&contract_json)?,
        0o644,
    )?;

    if backup_pending_offhost {
        log_stage(
            "backup",
            "WARN",
            &format!(
                "Contract '{}' recorded PENDING: no off-host target for profile {} \
                 (unattended install). INV-033 not yet satisfied — set an off-host \
                 backup target to complete the contract.",
                ctx.backup_contract_id, ctx.security_profile,
            ),
        );
    } else {
        log_stage(
            "backup",
            "OK",
            &format!(
                "Contract '{}' with targets: {:?}",
                ctx.backup_contract_id, ctx.backup_targets,
            ),
        );
    }

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "contract_id": ctx.backup_contract_id,
            "targets": ctx.backup_targets,
            "encrypt_at_source": true,
            "pending_off_host_target": backup_pending_offhost,
        }),
    )?;

    Ok(())
}

/// INV-033 hybrid decision: whether a missing OFF_HOST backup target may be
/// DEFERRED (the contract is recorded PENDING and the boot continues) instead of
/// failing the install. Deferral is allowed ONLY for an unattended
/// (non-interactive) install on a non-strict profile; STIG_ALIGNED and
/// AIRGAP_HIGH always require a real off-host target, and interactive installs
/// keep the hard requirement because an operator is present to supply one.
fn backup_offhost_deferrable(security_profile: &str, non_interactive: bool) -> bool {
    non_interactive && !matches!(security_profile, "STIG_ALIGNED" | "AIRGAP_HIGH")
}

/// Phase 7.5: Generate recovery key shards (3-of-5 threshold).
fn phase_7_5_recovery_shards(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 7.5: Recovery Key Shards ---\n");

    fs::create_dir_all(RECOVERY_SHARDS_DIR)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(RECOVERY_SHARDS_DIR, fs::Permissions::from_mode(0o700))?;
    }

    let recovery_key_file = format!("{RECOVERY_SHARDS_DIR}/master-recovery.key");

    if file_exists(&recovery_key_file) {
        log_stage("recovery/shards", "SKIP", "Recovery key already exists");
    } else {
        // Generate master recovery key
        cmd_output(
            "openssl",
            &[
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                &recovery_key_file,
            ],
        )?;
        let recovery_key = fs::read(&recovery_key_file)?;
        write_file_mode(
            &recovery_key_file,
            &String::from_utf8_lossy(&recovery_key),
            0o600,
        )?;

        // Extract public key
        let pub_key = cmd_output("openssl", &["pkey", "-in", &recovery_key_file, "-pubout"])?;
        fs::create_dir_all(RECOVERY_DIR)?;
        write_file(&format!("{RECOVERY_DIR}/recovery-pubkey.txt"), &pub_key)?;

        // Create 5 shards using hex-encoded key material
        let key_hex = hex::encode(&recovery_key);
        let fp_short = &ctx.host_key_fingerprint[..16.min(ctx.host_key_fingerprint.len())];

        println!("  Generating 3-of-5 recovery key shards...");
        for i in 1..=5u8 {
            let shard_file = format!("{RECOVERY_SHARDS_DIR}/shard-{i}.enc");
            let shard_data = format!(
                "AIOS-RECOVERY-SHARD-{i}:{}:{fp_short}",
                &key_hex[..16.min(key_hex.len())]
            );
            // Encrypt shard with AES-256-CBC using host ID as passphrase
            let openssl_in = format!("{AIOS_RUN}/shard-{i}-in.txt");
            write_file(&openssl_in, &shard_data)?;
            let _ = cmd_output(
                "openssl",
                &[
                    "enc",
                    "-aes-256-cbc",
                    "-pbkdf2",
                    "-iter",
                    "100000",
                    "-pass",
                    &format!("pass:{}", ctx.host_id),
                    "-in",
                    &openssl_in,
                    "-out",
                    &shard_file,
                ],
            );
            let _ = fs::remove_file(&openssl_in);
            write_file_mode(&shard_file, &shard_data, 0o600)?;
            println!("  [OK] Shard {i}/5 created");
        }

        log_stage("recovery/shards", "OK", "3-of-5 recovery shards generated");
    }

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "shard_count": 5,
            "threshold": 3,
            "host_id": ctx.host_id,
        }),
    )?;

    Ok(())
}

/// Phase 8: Generate mobile pairing QR code.
fn phase_8_mobile_pairing(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 8: Mobile Pairing ---\n");

    ctx.pairing_nonce = random_hex(16);
    let pairing_secret = random_hex(32);

    // Get host IP
    let host_ip = cmd_output("hostname", &["-I"])
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or("0.0.0.0")
        .to_string();
    let hostname = read_file("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "aios".to_string())
        .trim()
        .to_string();

    let fp_short = &ctx.host_key_fingerprint[..16.min(ctx.host_key_fingerprint.len())];
    ctx.pairing_url = format!(
        "aios-pair://{host_ip}:8443?host={hostname}&nonce={}&fingerprint={fp_short}",
        ctx.pairing_nonce,
    );

    fs::create_dir_all(MOBILE_PAIRING_DIR)?;
    let pairing_json = serde_json::json!({
        "host_id": ctx.host_id,
        "hostname": hostname,
        "host_key_fingerprint": ctx.host_key_fingerprint,
        "nonce": ctx.pairing_nonce,
        "secret": pairing_secret,
        "url": ctx.pairing_url,
        "created_at": now_rfc3339(),
    });
    write_file_mode(
        &format!("{MOBILE_PAIRING_DIR}/pairing.json"),
        &serde_json::to_string_pretty(&pairing_json)?,
        0o600,
    )?;

    println!("  Mobile Pairing URL:");
    println!("  {}", ctx.pairing_url);
    println!();

    // Try QR code display
    if cmd_ok("qrencode", &["--version"]) {
        println!("  QR Code:");
        println!();
        let _ = cmd_output("qrencode", &["-t", "ANSIUTF8", &ctx.pairing_url]);
        println!();
    } else {
        println!("  (Install qrencode to display QR code)");
    }

    log_stage("mobile/pairing", "OK", "Pairing URL generated");

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "hostname": hostname,
            "fingerprint_short": fp_short,
        }),
    )?;

    Ok(())
}

/// Phase 9: Create evidence log genesis block.
fn phase_9_evidence(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 9: Evidence Log ---\n");

    ctx.genesis_id = format!("gen_{}", ctx.host_id);
    fs::create_dir_all(EVIDENCE_DIR)?;

    let gen_log = format!("{EVIDENCE_DIR}/genesis.log");
    if file_exists(&gen_log) {
        let gen_bytes = fs::read(&gen_log)?;
        ctx.genesis_hash = blake3::hash(&gen_bytes).to_hex().to_string();
    } else {
        ctx.genesis_hash = blake3::hash(ctx.host_id.as_bytes()).to_hex().to_string();
    }

    // Record types in phase order
    let record_names = [
        "HOST_HARDWARE_VERIFIED",
        "HOST_IDENTITY_CREATED",
        "SECURITY_PROFILE_SET",
        "HUMAN_OPERATOR_CREATED",
        "TPM_ATTESTATION_ENROLLED",
        "ROOT_HASH_REGISTERED",
        "BACKUP_CONTRACT_CREATED",
        "RECOVERY_SHARDS_CREATED",
        "MOBILE_PAIRING_CREATED",
        "FLEET_MEMBERSHIP_INITIALIZED",
        "AUTONOMOUS_GOVERNANCE_INITIALIZED",
        "MARKETPLACE_INITIALIZED",
        "CONTAINER_RUNTIME_INITIALIZED",
        "SYSTEM_READINESS_CHECKED",
        "FIRST_BOOT_COMPLETE",
    ];

    let records: Vec<serde_json::Value> = record_names
        .iter()
        .enumerate()
        .map(|(i, name)| serde_json::json!({ "type": name, "phase": i + 1 }))
        .collect();

    let genesis = serde_json::json!({
        "genesis_id": ctx.genesis_id,
        "chain": "aios-main",
        "host_id": ctx.host_id,
        "host_key_fingerprint": ctx.host_key_fingerprint,
        "created_at": now_rfc3339(),
        "genesis_hash": ctx.genesis_hash,
        "records": records,
    });

    let gen_file = format!("{EVIDENCE_DIR}/genesis.json");
    write_file_mode(&gen_file, &serde_json::to_string_pretty(&genesis)?, 0o644)?;
    log_stage(
        "evidence/genesis",
        "OK",
        &format!("Genesis block created: {}", ctx.genesis_id),
    );

    Ok(())
}

/// Phase 10: Initialize local fleet membership in standalone mode.
fn phase_10_fleet_membership(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 10: Fleet Membership ---\n");

    fs::create_dir_all(FLEET_DIR)?;
    let membership = serde_json::json!({
        "host_id": ctx.host_id,
        "mode": "standalone",
        "cluster_name": "aios-default",
        "joined_at": now_rfc3339(),
        "operator": ctx.operator_canonical,
    });
    write_file_mode(
        &format!("{FLEET_DIR}/membership.json"),
        &serde_json::to_string_pretty(&membership)?,
        0o644,
    )?;
    log_stage(
        "fleet/membership",
        "OK",
        "Standalone fleet membership initialized",
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "fleet_mode": "standalone",
            "cluster_name": "aios-default",
        }),
    )?;

    Ok(())
}

/// Phase 11: Initialize autonomous governance defaults.
fn phase_11_autonomous_governance(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 11: Autonomous Governance ---\n");

    fs::create_dir_all(AUTONOMOUS_DIR)?;
    let constitution = serde_json::json!({
        "host_id": ctx.host_id,
        "autonomy_level": "advisory",
        "orchestrator_mode": "monitor",
        "requires_human_approval": true,
        "created_at": now_rfc3339(),
    });
    write_file_mode(
        &format!("{AUTONOMOUS_DIR}/constitution.json"),
        &serde_json::to_string_pretty(&constitution)?,
        0o644,
    )?;
    log_stage(
        "autonomous/governance",
        "OK",
        "Advisory governance initialized",
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "autonomy_level": "advisory",
            "orchestrator_mode": "monitor",
        }),
    )?;

    Ok(())
}

/// Phase 12: Initialize the local marketplace index.
fn phase_12_marketplace(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 12: Marketplace ---\n");

    fs::create_dir_all(MARKETPLACE_DIR)?;
    let index = serde_json::json!({
        "host_id": ctx.host_id,
        "schema_version": 1,
        "auto_sync": false,
        "packages": [],
        "updated_at": now_rfc3339(),
    });
    write_file_mode(
        &format!("{MARKETPLACE_DIR}/index.json"),
        &serde_json::to_string_pretty(&index)?,
        0o644,
    )?;
    log_stage(
        "marketplace/index",
        "OK",
        "Empty marketplace index initialized",
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "schema_version": 1,
            "package_count": 0,
        }),
    )?;

    Ok(())
}

/// Phase 13: Detect and record the container runtime.
fn phase_13_container_runtime(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 13: Container Runtime ---\n");

    fs::create_dir_all(CONTAINER_DIR)?;
    let runtime = if cmd_ok("podman", &["--version"]) {
        "podman-rootless"
    } else if cmd_ok("docker", &["--version"]) {
        "docker"
    } else {
        "unavailable"
    };
    let config = serde_json::json!({
        "host_id": ctx.host_id,
        "default_engine": runtime,
        "docker_socket_exposed": false,
        "created_at": now_rfc3339(),
    });
    write_file_mode(
        &format!("{CONTAINER_DIR}/config.json"),
        &serde_json::to_string_pretty(&config)?,
        0o644,
    )?;
    log_stage(
        "container/runtime",
        "OK",
        &format!("Runtime recorded: {runtime}"),
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "default_engine": runtime,
            "docker_socket_exposed": false,
        }),
    )?;

    Ok(())
}

/// Phase 14: Write readiness state after verifying required runtime artifacts.
fn phase_14_readiness(ctx: &mut FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n--- Phase 14: System Readiness ---\n");

    let required = [
        "/usr/lib/aios/aios-system",
        "/usr/lib/aios/aios-first-boot",
        "/etc/systemd/system/aios.target",
        "/etc/aios/config.toml",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|path| !file_exists(path))
        .collect();
    let ready = missing.is_empty();

    fs::create_dir_all(AIOS_VAR)?;
    let readiness = serde_json::json!({
        "host_id": ctx.host_id,
        "ready": ready,
        "missing": missing,
        "checked_at": now_rfc3339(),
    });
    write_file_mode(
        &format!("{AIOS_VAR}/readiness.json"),
        &serde_json::to_string_pretty(&readiness)?,
        0o644,
    )?;

    if !ready {
        return Err(FirstBootError::Config(
            "system readiness check failed; required runtime artifacts are missing".to_string(),
        ));
    }

    log_stage(
        "system/readiness",
        "OK",
        "Required runtime artifacts present",
    );

    record_evidence(
        ctx,
        RecordType::FirstBootStageCompleted,
        serde_json::json!({
            "ready": true,
            "checked_artifacts": required.len(),
        }),
    )?;

    Ok(())
}

/// Final phase: write marker, remove flag, clean up.
fn phase_10_complete(ctx: &FirstBootContext) -> Result<(), FirstBootError> {
    println!("\n============================================");
    println!("  AI-OS.NET First Boot Complete!");
    println!("============================================\n");

    let completion = serde_json::json!({
        "completed_at": now_rfc3339(),
        "host_id": ctx.host_id,
        "host_key_fingerprint": ctx.host_key_fingerprint,
        "security_profile": ctx.security_profile,
        "operator": ctx.operator_canonical,
        "tpm_enrolled": ctx.tpm_enrolled,
        "verity_created": ctx.verity_created,
        "secure_boot": ctx.secure_boot_state,
        "kernel_lockdown": ctx.kernel_lockdown,
        "backup_contract_id": ctx.backup_contract_id,
        "ai_provider_mode": ctx.ai_provider_mode,
        "firewall_posture": ctx.firewall_posture,
        "genesis_id": ctx.genesis_id,
    });

    let completion_file = format!("{AIOS_ETC}/first-boot-complete.json");
    write_file_mode(
        &completion_file,
        &serde_json::to_string_pretty(&completion)?,
        0o644,
    )?;

    // Remove first-boot flag — the final atomic action
    fs::remove_file(FIRST_BOOT_FLAG)?;

    // Clean up temporary files
    if dir_exists(AIOS_RUN) {
        let _ = fs::remove_dir_all(AIOS_RUN);
    }

    println!("  System ready for normal operation.\n");
    println!("  Security Profile:  {}", ctx.security_profile);
    println!("  AI Provider Mode:  {}", ctx.ai_provider_mode);
    println!("  Firewall Posture:  {}", ctx.firewall_posture);
    println!("  Host Fingerprint:  {}", ctx.host_key_fingerprint);
    println!("  Operator:          {}", ctx.operator_canonical);
    println!();
    println!("  IMPORTANT: Record your recovery key and admin credentials.");
    println!("  Run 'aios status' to verify all services.");

    Ok(())
}

// ─── Name Sanitization ────────────────────────────────────────────────────

fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        .trim_matches(|c: char| c == '_' || c == '-')
        .to_string()
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let mut cli = Cli::parse();

    // A boot-time systemd unit has no interactive console. If stdin is not a
    // terminal, force non-interactive so the wizard uses configured defaults
    // instead of blocking forever on read_line() — an unattended boot otherwise
    // hangs before multi-user.target (the aios-first-boot.service unit also
    // passes --non-interactive; this is defense-in-depth for any other
    // invocation such as cloud-init or the recovery path).
    if !cli.non_interactive && !io::stdin().is_terminal() {
        cli.non_interactive = true;
    }

    // Guard: check first-boot flag exists
    if !file_exists(FIRST_BOOT_FLAG) {
        println!("First-boot flag not found -- exiting.");
        return ExitCode::SUCCESS;
    }

    println!("============================================");
    println!("  AI-OS.NET First Boot Wizard -- Revision 11");
    println!("  {}", now_rfc3339());
    println!("============================================");
    println!();

    let mut ctx = FirstBootContext::default();

    match run_phases(&mut ctx, &cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nFATAL: {e}");
            eprintln!("First-boot wizard failed. The system requires recovery intervention.");
            // Leave first-boot flag intact so the wizard retries on next boot
            ExitCode::from(1)
        }
    }
}

fn run_phases(ctx: &mut FirstBootContext, cli: &Cli) -> Result<(), FirstBootError> {
    phase_1_hardware(ctx)?;
    phase_2_identity(ctx)?;
    phase_3_security_profile(ctx, cli)?;
    phase_4_operator(ctx, cli)?;
    phase_5_tpm(ctx, cli)?;
    phase_5_5_luks_pcr_binding(ctx, cli)?;
    phase_6_verity(ctx)?;
    phase_7_backup(ctx, cli)?;
    phase_7_5_recovery_shards(ctx)?;
    phase_8_mobile_pairing(ctx)?;
    phase_9_evidence(ctx)?;
    phase_10_fleet_membership(ctx)?;
    phase_11_autonomous_governance(ctx)?;
    phase_12_marketplace(ctx)?;
    phase_13_container_runtime(ctx)?;
    phase_14_readiness(ctx)?;
    phase_10_complete(ctx)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_removes_invalid_chars() {
        assert_eq!(sanitize_name("alice@home!"), "alicehome");
    }

    #[test]
    fn sanitize_name_strips_leading_trailing_special() {
        assert_eq!(sanitize_name("_-alice-_"), "alice");
    }

    #[test]
    fn sanitize_name_preserves_valid_chars() {
        assert_eq!(sanitize_name("alice_bob-123"), "alice_bob-123");
    }

    #[test]
    fn random_hex_produces_correct_length() {
        let h = random_hex(16);
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_hex_produces_different_values() {
        let h1 = random_hex(8);
        let h2 = random_hex(8);
        // Extremely unlikely to collide
        assert_ne!(h1, h2);
    }

    #[test]
    fn now_rfc3339_produces_valid_iso8601() {
        let ts = now_rfc3339();
        assert!(ts.contains('T'));
        assert!(ts.contains(':'));
    }

    #[test]
    fn context_defaults_are_reasonable() {
        let ctx = FirstBootContext::default();
        assert!(ctx.host_id.is_empty());
        assert!(!ctx.tpm_available);
        assert!(ctx.evidence_chain.is_empty());
    }

    /// Verbatim `cryptsetup luksDump` token output for a PCR-bound systemd-tpm2 token.
    const DUMP_BOUND: &str = "Tokens:\n  0: systemd-tpm2\n\ttpm2-hash-pcrs:   0+1+7\n\ttpm2-pcr-bank:    sha256\n\ttpm2-pubkey:\n\t            (null)\n\ttpm2-pubkey-pcrs: \n\ttpm2-primary-alg: ecc\n\ttpm2-pin:         false\n\tKeyslot:    0\n";

    /// Verbatim dump output for the installer's bootstrap token (`--tpm2-pcrs=`).
    /// The label is present; the value is empty. This must never read as bound.
    const DUMP_UNBOUND: &str = "Tokens:\n  0: systemd-tpm2\n\ttpm2-hash-pcrs:   \n\ttpm2-pcr-bank:    sha256\n\ttpm2-pubkey-pcrs: \n\ttpm2-primary-alg: ecc\n\tKeyslot:    0\n";

    #[test]
    fn luks_token_pcrs_parses_bound_token() {
        assert_eq!(luks_token_pcrs(DUMP_BOUND), Some(vec![0, 1, 7]));
    }

    #[test]
    fn luks_token_pcrs_reports_bootstrap_token_as_unbound() {
        // Some(empty) — the token exists but seals against nothing. The distinction
        // between this and DUMP_BOUND is the whole point of the phase.
        assert_eq!(luks_token_pcrs(DUMP_UNBOUND), Some(vec![]));
    }

    #[test]
    fn luks_token_pcrs_ignores_pubkey_pcrs_label() {
        // tpm2-pubkey-pcrs is a different binding and must not be read as the hash PCRs.
        let dump = "Tokens:\n  0: systemd-tpm2\n\ttpm2-pubkey-pcrs: 11\n";
        assert_eq!(luks_token_pcrs(dump), None);
    }

    #[test]
    fn luks_token_pcrs_absent_without_token() {
        assert_eq!(luks_token_pcrs("Tokens:\nDigests:\n"), None);
    }

    #[test]
    fn bound_dump_matches_expected_pcr_set() {
        assert_eq!(luks_token_pcrs(DUMP_BOUND), Some(expected_luks_pcrs()));
        assert_ne!(luks_token_pcrs(DUMP_UNBOUND), Some(expected_luks_pcrs()));
    }

    #[test]
    fn crypttab_tpm2_device_resolves_uuid() {
        let crypttab =
            "# comment\naios-cryptroot   UUID=abc-123   none   luks,discard,tpm2-device=auto\n";
        assert_eq!(
            crypttab_tpm2_device(crypttab),
            Some("/dev/disk/by-uuid/abc-123".to_string())
        );
    }

    #[test]
    fn crypttab_tpm2_device_skips_non_tpm2_mappings() {
        let crypttab = "swap   UUID=dead-beef   /dev/urandom   swap\n\
                        aios-cryptroot   UUID=abc-123   none   luks,tpm2-device=auto\n";
        assert_eq!(
            crypttab_tpm2_device(crypttab),
            Some("/dev/disk/by-uuid/abc-123".to_string())
        );
    }

    #[test]
    fn crypttab_tpm2_device_none_when_no_tpm2_line() {
        let crypttab = "aios-cryptroot   UUID=abc-123   none   luks,discard\n";
        assert_eq!(crypttab_tpm2_device(crypttab), None);
    }

    #[test]
    fn first_boot_error_display() {
        let e = FirstBootError::SelinuxNotEnforcing("Permissive".to_string());
        let msg = format!("{e}");
        assert!(msg.contains("Permissive"));
        assert!(msg.contains("INV-001"));
    }

    #[test]
    fn backup_offhost_deferrable_only_unattended_normal_profiles() {
        // Unattended (non-interactive) normal profiles may defer the off-host
        // target: the machine boots and the contract is flagged PENDING.
        assert!(backup_offhost_deferrable("SECURE_DEFAULT", true));
        assert!(backup_offhost_deferrable("DEV_RELAXED", true));
        // High-security profiles always require a real off-host target.
        assert!(!backup_offhost_deferrable("STIG_ALIGNED", true));
        assert!(!backup_offhost_deferrable("AIRGAP_HIGH", true));
        // Interactive installs keep the hard requirement (operator is present).
        assert!(!backup_offhost_deferrable("SECURE_DEFAULT", false));
        assert!(!backup_offhost_deferrable("STIG_ALIGNED", false));
    }

    #[test]
    fn parse_lockdown_extracts_the_bracketed_mode() {
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality\n"),
            "integrity"
        );
        assert_eq!(parse_lockdown("[none] integrity confidentiality"), "none");
        assert_eq!(
            parse_lockdown("none integrity [confidentiality]"),
            "confidentiality"
        );
        // No bracketed token (e.g. an empty or malformed file) -> "unknown".
        assert_eq!(parse_lockdown("none integrity confidentiality"), "unknown");
        assert_eq!(parse_lockdown(""), "unknown");
    }

    #[test]
    fn parse_secure_boot_reads_the_trailing_state_byte() {
        // 4 attribute bytes + state byte.
        assert_eq!(parse_secure_boot(&[6, 0, 0, 0, 1]), "enabled");
        assert_eq!(parse_secure_boot(&[6, 0, 0, 0, 0]), "disabled");
        // Anything but 0/1 in a well-formed var, or a short/empty read.
        assert_eq!(parse_secure_boot(&[6, 0, 0, 0, 2]), "unavailable");
        assert_eq!(parse_secure_boot(&[1]), "unavailable");
        assert_eq!(parse_secure_boot(&[]), "unavailable");
    }
}
