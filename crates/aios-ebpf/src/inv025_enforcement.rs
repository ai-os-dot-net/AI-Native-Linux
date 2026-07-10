//! INV-025 constitutional enforcement for eBPF program management (Rev.6).
//!
//! # The rule
//!
//! **AI_SUBJECT must NEVER load, attach, or detach eBPF programs.**
//!
//! Only `SYSTEM_SERVICE` or `HUMAN_OPERATOR` subjects may manage eBPF programs.
//! An AI subject may REQUEST a specific pre-vetted, signed, drop-only eBPF
//! template, but the actual load/attach operation must be performed by a
//! system service.
//!
//! # Subject taxonomy
//!
//! ```text
//! AI_SUBJECT_SIGNAL   = element in [1, 2, 3]  # positional, unordered
//! RUNTIME_SUBJECT     = element in [4, 5]
//! HUMAN_SUBJECT       = element in [6, 7]
//! ```
//!
//! # Template constraints
//!
//! - Templates must be in the `AiosVerified` registry with full Ed25519 signature chain.
//! - Drop-only templates only (packet drop, syscall deny) — templates may not
//!   exfiltrate data, modify kernel state, or spawn processes.

use serde::{Deserialize, Serialize};

use crate::enums::{EbpfAuthorRole, EbpfProgramState};
use crate::error::{EbpfError, EbpfResult};

/// Subject classification for eBPF operation authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfSubject {
    /// An AI model or agent attempting to manage eBPF — always forbidden.
    AiSubject,
    /// A system service (e.g., `aios-ebpf-daemon`) — allowed to manage eBPF.
    SystemService,
    /// A human operator — allowed to manage eBPF.
    HumanOperator,
}

impl EbpfSubject {
    /// Returns `true` if this subject is permitted to manage eBPF programs.
    #[must_use]
    pub fn can_manage_ebpf(&self) -> bool {
        matches!(self, Self::SystemService | Self::HumanOperator)
    }
}

/// An Ed25519 signature in the eBPF program signature chain.
///
/// Each entry in the signature chain signs the BLAKE3 hash of the BPF bytecode,
/// chaining from the signer (AIOS maintainer, third-party) through to the
/// operator who approved deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfSignature {
    /// The public key that produced this signature (32 bytes, Ed25519).
    pub public_key: [u8; 32],
    /// The Ed25519 signature bytes over the program's BLAKE3 hash.
    pub signature_bytes: Vec<u8>,
}

/// INV-025 constitutional check: reject AI subjects from managing eBPF.
///
/// Called before every `load`, `attach`, and `detach` operation. If the subject
/// is an AI, returns [`EbpfError::AiAuthorRejected`] with details about the
/// attempted operation.
///
/// # Errors
///
/// Returns [`EbpfError::AiAuthorRejected`] if `subject` is [`EbpfSubject::AiSubject`].
pub fn enforce_inv025(subject: EbpfSubject, operation: &str, program_id: &str) -> EbpfResult<()> {
    if matches!(subject, EbpfSubject::AiSubject) {
        return Err(EbpfError::AiAuthorRejected {
            subject: "ai_subject".to_owned(),
            operation: operation.to_owned(),
            program_id: program_id.to_owned(),
        });
    }
    Ok(())
}

/// Check that a program's author role is not [`EbpfAuthorRole::AiProposedNever`].
///
/// This is a hard registration-time check: a program with `AiProposedNever`
/// role is a sentinel that MUST never be registered. Attempting to register one
/// returns [`EbpfError::AiAuthorRejected`].
///
/// # Errors
///
/// Returns [`EbpfError::AiAuthorRejected`] if `author` is [`EbpfAuthorRole::AiProposedNever`].
pub fn enforce_ai_author_role(author: EbpfAuthorRole, program_id: &str) -> EbpfResult<()> {
    if author == EbpfAuthorRole::AiProposedNever {
        return Err(EbpfError::AiAuthorRejected {
            subject: "ai_proposed".to_owned(),
            operation: "register".to_owned(),
            program_id: program_id.to_owned(),
        });
    }
    Ok(())
}

/// Verify that a program has at least one valid Ed25519 signature in its chain.
///
/// An empty signature chain is an automatic rejection. This is a structural
/// check — actual cryptographic verification of each signature against the
/// program hash is done by the registry at load time.
///
/// # Errors
///
/// Returns [`EbpfError::SignatureInvalid`] if the chain is empty.
pub fn enforce_signature_chain_present(
    signatures: &[EbpfSignature],
    program_id: &str,
) -> EbpfResult<()> {
    if signatures.is_empty() {
        return Err(EbpfError::SignatureInvalid {
            program_id: program_id.to_owned(),
            detail: "signature chain is empty; at least one Ed25519 signature required".to_owned(),
        });
    }
    Ok(())
}

/// Enforce that a BPF program is in a state that permits a given operation.
///
/// State machine transitions:
/// - `load`  : allowed from `Registered`
/// - `attach`: allowed from `Loaded`
/// - `detach`: allowed from `Attached`, `Running`
/// - `run`   : allowed from `Attached`
///
/// # Errors
///
/// Returns [`EbpfError::InvalidState`] if the current state does not permit the operation.
pub fn enforce_valid_state_transition(
    current_state: EbpfProgramState,
    operation: &str,
    program_id: &str,
) -> EbpfResult<()> {
    let permitted = match operation {
        "load" => current_state == EbpfProgramState::Registered,
        "attach" => current_state == EbpfProgramState::Loaded,
        "detach" => {
            current_state == EbpfProgramState::Attached
                || current_state == EbpfProgramState::Running
        }
        "run" => current_state == EbpfProgramState::Attached,
        _ => false,
    };

    if !permitted {
        return Err(EbpfError::InvalidState {
            program_id: program_id.to_owned(),
            current_state: format!("{current_state:?}"),
            attempted: operation.to_owned(),
        });
    }
    Ok(())
}

/// Check that a template program is drop-only (packet drop, syscall deny) as
/// required by INV-025 for AI-requested templates.
///
/// Returns `true` if the template description indicates a drop-only policy.
/// This is a heuristic check on the program description string, not a BPF
/// verifier-level analysis.
#[must_use]
pub fn is_drop_only_template(description: &str) -> bool {
    let lower = description.to_lowercase();
    lower.contains("drop")
        || lower.contains("deny")
        || lower.contains("block")
        || lower.contains("discard")
        || lower.contains("reject")
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn make_signature() -> EbpfSignature {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key: [u8; 32] = verifying_key.to_bytes();
        let test_hash: [u8; 32] = [0x42; 32];
        let sig = signing_key.sign(&test_hash);
        EbpfSignature {
            public_key,
            signature_bytes: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn system_service_can_manage_ebpf() {
        assert!(EbpfSubject::SystemService.can_manage_ebpf());
    }

    #[test]
    fn human_operator_can_manage_ebpf() {
        assert!(EbpfSubject::HumanOperator.can_manage_ebpf());
    }

    #[test]
    fn ai_subject_cannot_manage_ebpf() {
        assert!(!EbpfSubject::AiSubject.can_manage_ebpf());
    }

    #[test]
    fn inv025_ai_subject_blocked_from_load() {
        let result = enforce_inv025(EbpfSubject::AiSubject, "load", "01HABC");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("INV-025"));
        assert!(msg.contains("load"));
    }

    #[test]
    fn inv025_ai_subject_blocked_from_attach() {
        let result = enforce_inv025(EbpfSubject::AiSubject, "attach", "01HDEF");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("INV-025"));
        assert!(msg.contains("attach"));
    }

    #[test]
    fn inv025_system_service_allowed_to_load() {
        let result = enforce_inv025(EbpfSubject::SystemService, "load", "01HGHI");
        assert!(result.is_ok());
    }

    #[test]
    fn inv025_system_service_allowed_to_attach() {
        let result = enforce_inv025(EbpfSubject::SystemService, "attach", "01HJKL");
        assert!(result.is_ok());
    }

    #[test]
    fn inv025_human_operator_allowed_to_load() {
        let result = enforce_inv025(EbpfSubject::HumanOperator, "load", "01HMNO");
        assert!(result.is_ok());
    }

    #[test]
    fn inv025_human_operator_allowed_to_attach() {
        let result = enforce_inv025(EbpfSubject::HumanOperator, "attach", "01HPQR");
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_ai_author_role_rejects_ai_proposed_never() {
        let result = enforce_ai_author_role(EbpfAuthorRole::AiProposedNever, "01HSTU");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("INV-025"));
    }

    #[test]
    fn enforce_ai_author_role_accepts_aios_verified() {
        let result = enforce_ai_author_role(EbpfAuthorRole::AiosVerified, "01HVWX");
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_ai_author_role_accepts_third_party_signed() {
        let result = enforce_ai_author_role(EbpfAuthorRole::ThirdPartySigned, "01HYZA");
        assert!(result.is_ok());
    }

    #[test]
    fn inv025_template_must_be_signed() {
        let result = enforce_signature_chain_present(&[], "01HBCD");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"));
        assert!(msg.contains("signature"));
    }

    #[test]
    fn inv025_template_with_signature_passes() {
        let sig = make_signature();
        let result = enforce_signature_chain_present(&[sig], "01HEFG");
        assert!(result.is_ok());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_load_from_registered() {
        let result =
            enforce_valid_state_transition(EbpfProgramState::Registered, "load", "01HTEST");
        assert!(result.is_ok());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_load_from_loaded_rejected() {
        let result = enforce_valid_state_transition(EbpfProgramState::Loaded, "load", "01HTEST");
        assert!(result.is_err());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_attach_from_loaded() {
        let result = enforce_valid_state_transition(EbpfProgramState::Loaded, "attach", "01HTEST");
        assert!(result.is_ok());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_attach_from_registered_rejected() {
        let result =
            enforce_valid_state_transition(EbpfProgramState::Registered, "attach", "01HTEST");
        assert!(result.is_err());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_detach_from_running() {
        let result = enforce_valid_state_transition(EbpfProgramState::Running, "detach", "01HTEST");
        assert!(result.is_ok());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_detach_from_detached_rejected() {
        let result =
            enforce_valid_state_transition(EbpfProgramState::Detached, "detach", "01HTEST");
        assert!(result.is_err());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_run_from_attached() {
        let result = enforce_valid_state_transition(EbpfProgramState::Attached, "run", "01HTEST");
        assert!(result.is_ok());
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_run_from_loaded_rejected() {
        let result = enforce_valid_state_transition(EbpfProgramState::Loaded, "run", "01HTEST");
        assert!(result.is_err());
    }

    #[test]
    fn drop_only_template_detects_drop() {
        assert!(is_drop_only_template(
            "Drop all outbound TCP to 8.8.8.8:443"
        ));
        assert!(is_drop_only_template(
            "deny syscall mount in capsule dev-capsule"
        ));
        assert!(is_drop_only_template("block CAP_SYS_ADMIN"));
        assert!(is_drop_only_template("discard UDP on port 53"));
        assert!(is_drop_only_template("reject inbound TCP SYN"));
    }

    #[test]
    fn drop_only_template_rejects_modifying_operations() {
        assert!(!is_drop_only_template("Modify HTTP headers"));
        assert!(!is_drop_only_template("Spawn shell on connect"));
        assert!(!is_drop_only_template("Log all keystrokes"));
        assert!(!is_drop_only_template("Exfiltrate /etc/shadow"));
    }
}
