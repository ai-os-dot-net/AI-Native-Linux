//! `aios-hardening` — centralized hardening audit scanner for AI-OS.NET Rev.8.
//!
//! Implements S16.3 hardening audit scanner with probe-based posture checks
//! across boot chain, SELinux MAC, systemd service hardening, and
//! cryptographic posture domains.
//!
//! ## Architecture
//!
//! ```text
//! HardeningScanner
//!   ├── BootChainProbe     (TPM PCR, Secure Boot, kernel lockdown)
//!   ├── MacProbe           (SELinux enforcing, policy version, AVC denials)
//!   ├── ServiceProbe       (systemd hardening score)
//!   └── CryptoProbe        (FIPS mode, algorithm compliance)
//! ```
//!
//! ## Constitutional invariants
//!
//! - **No `unsafe`, no `unwrap`/`expect`/`panic`** in production code.
//! - All enums are closed (`EnumIter` + `EnumCount` + `SCREAMING_SNAKE_CASE` serde).
//! - Zero `unwrap`/`expect`/`panic` outside test blocks.

#![forbid(unsafe_code)]

/// Closed hardening vocabulary enums (standards, severity, probe classes, statuses).
pub mod enums;
/// Hardening error taxonomy.
pub mod error;
/// Posture probe implementations (boot, MAC, service, crypto).
pub mod probes;
/// Centralized hardening scanner with probe registry and result aggregation.
pub mod scanner;

pub use enums::{HardeningProbeStatus, HardeningStandard, ProbeClass, ProbeSeverity};
pub use error::HardeningError;
pub use probes::{
    BootChainProbe, BootChainResult, CryptoProbe, CryptoResult, MacProbe, MacResult, ServiceProbe,
    ServiceResult,
};
pub use scanner::{HardeningScanResult, HardeningScanner, ProbeResult};

/// Default Rust crate code version.
pub const DEFAULT_CODE_VERSION: &str = "0.1.0-Rev8";
