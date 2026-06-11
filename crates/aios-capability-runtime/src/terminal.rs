//! OS-RESEARCH: Native AI terminal mode dispatcher — LX / MIX / AI typed-action fabric.
//!
//! ## OS Research Provenance
//!
//! The three-mode terminal architecture draws from decades of OS research on
//! privilege separation and capability-based access control:
//!
//! 1. **LX mode** (pure shell, no AI) — models the classic UNIX terminal
//!    where commands execute directly in the calling process context.
//!    Equivalent to Plan 9's `rio` with `rfork(RFNAMEG)`.
//! 2. **MIX mode** (AI-assisted, human confirms) — models the Multics
//!    "dual control" principle: no single agent (human or AI) can execute
//!    privileged operations alone.  Mirrors the S5.3 Approval Mechanics
//!    consent gate applied to terminal interactions.
//! 3. **AI mode** (autonomous, policy-gated) — models the KeyKOS / EROS
//!    capability model: the AI agent must possess an explicit policy grant
//!    (a capability token) before any command reaches the execution layer.
//!    No ambient authority.
//!
//! ### Mapping to AIOS Architecture
//!
//! | Concept                     | AIOS equivalent                           |
//! |-----------------------------|-------------------------------------------|
//! | Plan 9 `rio` terminal       | [`TerminalMode::Lx`]                      |
//! | Multics dual control        | [`TerminalMode::Mix`] + [`ApprovalStatus`] |
//! | KeyKOS/EROS capability gate | [`TerminalMode::Ai`] + `policy_allows_ai` |
//! | Action proposal             | [`ActionProposal`]                        |
//! | Session multiplexing        | [`TerminalDispatcher`]                    |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-TERM-001 (LX auto-execute):** Proposals in LX mode are
//!   auto-approved and can execute immediately without human intervention.
//! - **INV-TERM-002 (MIX dual control):** Proposals in MIX mode require
//!   explicit human approval before execution.
//! - **INV-TERM-003 (AI policy gate):** Proposals in AI mode are rejected
//!   unless an active policy grant is present.
//! - **INV-TERM-004 (Timeout safety):** Proposals expire after the
//!   configured approval timeout; expired proposals cannot be approved
//!   or executed.
//! - **INV-TERM-005 (Idempotent approval):** Approving an already-approved
//!   proposal is a no-op that returns `false`.
//! - **INV-TERM-006 (Session isolation):** Only active sessions can generate
//!   proposals; closing a session prevents further proposals.
//! - **INV-TERM-007 (Denial is terminal):** A denied proposal cannot be
//!   approved or executed.

#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// TerminalMode — the three native terminal operating modes
// ---------------------------------------------------------------------------

/// Three mutually-exclusive terminal operating modes.
///
/// | Mode  | AI involved? | Human approval? | Policy gate? |
/// |-------|--------------|-----------------|--------------|
/// | `Lx`  | No           | No              | No           |
/// | `Mix`  | Yes          | Yes             | No           |
/// | `Ai`   | Yes          | No              | Yes          |
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalMode {
    /// Pure shell — no AI involvement.  Commands execute in the calling
    /// capsule's direct context without any approval or policy check.
    Lx,
    /// AI-assisted — AI proposes commands; a human operator must explicitly
    /// approve each proposal before it reaches the execution layer.
    /// Mirrors the S5.3 dual-control principle.
    Mix,
    /// Autonomous — AI executes under a policy capability gate.  The AI
    /// agent must possess a valid policy grant for its capsule; proposals
    /// from capsules without the grant are rejected at proposal time.
    Ai,
}

// ---------------------------------------------------------------------------
// ApprovalStatus — the four states of an action proposal
// ---------------------------------------------------------------------------

/// Closed four-state FSM for action proposal lifecycle.
///
/// ```text
/// Pending ──► Approved ──► (execute)
///    │
///    ├────────► Denied      (terminal)
///    │
///    └────────► TimedOut    (terminal)
/// ```
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStatus {
    /// Proposal emitted; awaiting human decision.  Only `Pending`
    /// proposals may transition to `Approved` or `Denied`.
    Pending,
    /// Human operator consented; the proposal may be executed.
    Approved,
    /// Human operator rejected; the proposal cannot be executed.
    /// Terminal state.
    Denied,
    /// The approval window elapsed; the proposal cannot be executed.
    /// Terminal state.
    TimedOut,
}

impl ApprovalStatus {
    /// `true` iff this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Denied | Self::TimedOut)
    }

    /// `true` iff the proposal can transition to `Approved`.
    #[must_use]
    pub const fn is_approvable(self) -> bool {
        matches!(self, Self::Pending)
    }
}

// ---------------------------------------------------------------------------
// TerminalSession — a single terminal session
// ---------------------------------------------------------------------------

/// A terminal session binds a capsule to a [`TerminalMode`] for the
/// duration of interactive use.
///
/// Multiple sessions may exist concurrently (one per capsule); each
/// session is independently governed by its mode's execution rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSession {
    /// Unique session identifier (`term-<N>`).
    pub session_id: String,
    /// The operating mode for this session.
    pub mode: TerminalMode,
    /// The capsule that owns this session.
    pub capsule_id: CapsuleId,
    /// Wall-clock the session was created.
    pub created_at: DateTime<Utc>,
    /// Whether the session is still accepting proposals.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// ActionProposal — an AI-proposed terminal command awaiting disposition
// ---------------------------------------------------------------------------

/// A single proposed terminal command and its approval lifecycle.
///
/// One session may have many proposals in flight; each is independently
/// tracked.  LX-mode proposals are born `Approved`; MIX-mode proposals
/// are born `Pending` and require an explicit [`TerminalDispatcher::approve`]
/// call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionProposal {
    /// Unique proposal identifier (`prop-<N>`).
    pub proposal_id: String,
    /// Back-link to the originating session.
    pub session_id: String,
    /// The shell command string proposed for execution.
    pub command: String,
    /// Current approval state.
    pub status: ApprovalStatus,
    /// Wall-clock the proposal was emitted.
    pub proposed_at: DateTime<Utc>,
    /// Wall-clock after which the proposal is void.
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// TerminalDispatcher — mode-aware command routing engine
// ---------------------------------------------------------------------------

/// Routes terminal commands to the correct execution context based on
/// the session's [`TerminalMode`].
///
/// # Execution matrix
///
/// | Mode | Propose            | Approve           | Execute           |
/// |------|--------------------|-------------------|-------------------|
/// | `Lx` | Auto-approved      | No-op (`false`)   | Immediate         |
/// | `Mix` | `Pending`          | Required          | After `Approved`  |
/// | `Ai`  | Requires policy    | Required          | After `Approved`  |
///
/// # Example
///
/// ```rust
/// # use aios_capability_runtime::terminal::*;
/// # use std::time::Duration;
/// # use aios_capability_runtime::capsule_namespace::CapsuleId;
/// let mut dispatcher = TerminalDispatcher::new(Duration::from_secs(300));
///
/// // LX session — auto-execute.
/// let lx_session = dispatcher.new_session(TerminalMode::Lx, CapsuleId(1));
/// let proposal = dispatcher.propose_action(&lx_session.session_id, "ls -la".into()).unwrap();
/// assert_eq!(proposal.status, ApprovalStatus::Approved);
/// assert!(dispatcher.execute(&proposal.proposal_id).is_ok());
/// ```
#[derive(Debug)]
pub struct TerminalDispatcher {
    sessions: HashMap<String, TerminalSession>,
    proposals: HashMap<String, ActionProposal>,
    approval_timeout: Duration,
    policy_allows_ai: bool,
    next_session_num: u64,
    next_proposal_num: u64,
}

impl TerminalDispatcher {
    /// Create a new dispatcher with the given approval timeout.
    ///
    /// AI mode is initially disallowed; call
    /// [`set_policy_ai_allowed`](Self::set_policy_ai_allowed) to enable it.
    #[must_use]
    pub fn new(approval_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            proposals: HashMap::new(),
            approval_timeout,
            policy_allows_ai: false,
            next_session_num: 0,
            next_proposal_num: 0,
        }
    }

    /// Enable or disable the AI-mode policy grant.
    ///
    /// When `false` (default), proposals from AI-mode sessions are
    /// rejected at proposal time (INV-TERM-003).
    pub fn set_policy_ai_allowed(&mut self, allowed: bool) {
        self.policy_allows_ai = allowed;
    }

    /// Return the current AI policy state.
    #[must_use]
    pub fn is_ai_allowed(&self) -> bool {
        self.policy_allows_ai
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    /// Create a new terminal session for the given capsule.
    ///
    /// Sessions are always created active.  Use
    /// [`close_session`](Self::close_session) to deactivate.
    pub fn new_session(&mut self, mode: TerminalMode, capsule_id: CapsuleId) -> TerminalSession {
        self.next_session_num += 1;
        let session_id = format!("term-{}", self.next_session_num);
        let session = TerminalSession {
            session_id: session_id.clone(),
            mode,
            capsule_id,
            created_at: Utc::now(),
            active: true,
        };
        self.sessions.insert(session_id, session.clone());
        session
    }

    /// Deactivate a session.  Inactive sessions cannot generate proposals.
    ///
    /// Returns `true` if the session existed and was active; `false`
    /// if the session was not found or was already inactive.
    pub fn close_session(&mut self, session_id: &str) -> bool {
        match self.sessions.get_mut(session_id) {
            Some(s) if s.active => {
                s.active = false;
                true
            }
            _ => false,
        }
    }

    /// Reactivate a previously deactivated session.
    ///
    /// Returns `true` if the session existed and was inactive.
    pub fn reopen_session(&mut self, session_id: &str) -> bool {
        match self.sessions.get_mut(session_id) {
            Some(s) if !s.active => {
                s.active = true;
                true
            }
            _ => false,
        }
    }

    /// Number of currently active sessions.
    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.sessions.values().filter(|s| s.active).count()
    }

    /// Total number of sessions (active + inactive).
    #[must_use]
    pub fn total_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Look up a session by id.
    #[must_use]
    pub fn get_session(&self, session_id: &str) -> Option<&TerminalSession> {
        self.sessions.get(session_id)
    }

    // -----------------------------------------------------------------------
    // Proposal lifecycle
    // -----------------------------------------------------------------------

    /// Emit a new action proposal for the given session.
    ///
    /// # Mode-dependent behaviour
    ///
    /// - **LX:** proposal is auto-approved; can execute immediately.
    /// - **MIX:** proposal is `Pending`; requires [`approve`](Self::approve).
    /// - **AI:** proposal is `Pending` only if `policy_allows_ai` is `true`;
    ///   otherwise returns an error (INV-TERM-003).
    ///
    /// # Errors
    ///
    /// - `"session not found"` — `session_id` is unknown.
    /// - `"session is not active"` — the session was closed.
    /// - `"AI mode blocked: no active policy grant"` — AI session without
    ///   policy clearance.
    pub fn propose_action(
        &mut self,
        session_id: &str,
        command: String,
    ) -> Result<ActionProposal, String> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| "session not found".to_string())?;

        if !session.active {
            return Err("session is not active".to_string());
        }

        if matches!(session.mode, TerminalMode::Ai) && !self.policy_allows_ai {
            return Err("AI mode blocked: no active policy grant".to_string());
        }

        self.next_proposal_num += 1;
        let proposal_id = format!("prop-{}", self.next_proposal_num);
        let now = Utc::now();

        let status = if matches!(session.mode, TerminalMode::Lx) {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Pending
        };

        let expires_at = now
            + chrono::Duration::from_std(self.approval_timeout)
                .unwrap_or(chrono::Duration::seconds(300));

        let proposal = ActionProposal {
            proposal_id: proposal_id.clone(),
            session_id: session_id.to_string(),
            command,
            status,
            proposed_at: now,
            expires_at,
        };

        self.proposals.insert(proposal_id, proposal.clone());
        Ok(proposal)
    }

    /// Human operator approves a pending proposal.
    ///
    /// Returns `true` if the proposal transitioned from `Pending` to
    /// `Approved`.  Returns `false` if the proposal is not found, is
    /// not `Pending`, or has expired.
    pub fn approve(&mut self, proposal_id: &str) -> bool {
        let proposal = match self.proposals.get_mut(proposal_id) {
            Some(p) => p,
            None => return false,
        };

        if Utc::now() > proposal.expires_at {
            proposal.status = ApprovalStatus::TimedOut;
            return false;
        }

        if matches!(proposal.status, ApprovalStatus::Pending) {
            proposal.status = ApprovalStatus::Approved;
            true
        } else {
            false
        }
    }

    /// Human operator denies a pending proposal.
    ///
    /// Returns `true` if the proposal transitioned from `Pending` to
    /// `Denied`.  Returns `false` if the proposal is not found, is
    /// not `Pending`, or has expired.
    pub fn deny(&mut self, proposal_id: &str) -> bool {
        let proposal = match self.proposals.get_mut(proposal_id) {
            Some(p) => p,
            None => return false,
        };

        if Utc::now() > proposal.expires_at {
            proposal.status = ApprovalStatus::TimedOut;
            return false;
        }

        if matches!(proposal.status, ApprovalStatus::Pending) {
            proposal.status = ApprovalStatus::Denied;
            true
        } else {
            false
        }
    }

    /// Execute an approved proposal.
    ///
    /// Returns the command execution result on success.
    ///
    /// # Errors
    ///
    /// - `"proposal not found"` — `proposal_id` is unknown.
    /// - `"proposal timed out"` — the approval window elapsed.
    /// - `"proposal not yet approved"` — the proposal is still `Pending`.
    /// - `"proposal was denied"` — the proposal was denied.
    /// - `"proposal timed out"` — the proposal expired.
    pub fn execute(&mut self, proposal_id: &str) -> Result<String, String> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;

        if Utc::now() > proposal.expires_at {
            return Err("proposal timed out".to_string());
        }

        match proposal.status {
            ApprovalStatus::Approved => Ok(format!("executed: {}", proposal.command)),
            ApprovalStatus::Pending => Err("proposal not yet approved".to_string()),
            ApprovalStatus::Denied => Err("proposal was denied".to_string()),
            ApprovalStatus::TimedOut => Err("proposal timed out".to_string()),
        }
    }

    /// Look up a proposal by id.
    #[must_use]
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&ActionProposal> {
        self.proposals.get(proposal_id)
    }

    /// Number of proposals currently tracked.
    #[must_use]
    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }
}

// ===========================================================================
// Tests — INV-TERM-001 through INV-TERM-007
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn new_dispatcher() -> TerminalDispatcher {
        TerminalDispatcher::new(Duration::from_secs(300))
    }

    fn new_dispatcher_zero_timeout() -> TerminalDispatcher {
        TerminalDispatcher::new(Duration::from_secs(0))
    }

    // -----------------------------------------------------------------------
    // INV-TERM-001: LX auto-execute
    // -----------------------------------------------------------------------

    #[test]
    fn lx_mode_auto_approves_proposal() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Lx, CapsuleId(1));
        let proposal = d
            .propose_action(&session.session_id, "echo hello".into())
            .expect("LX proposal should succeed");
        assert_eq!(proposal.status, ApprovalStatus::Approved);
    }

    #[test]
    fn lx_mode_executes_without_approval() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Lx, CapsuleId(1));
        let proposal = d
            .propose_action(&session.session_id, "ls -la".into())
            .expect("LX proposal should succeed");
        let result = d.execute(&proposal.proposal_id).expect("LX execution should succeed");
        assert!(result.contains("ls -la"));
    }

    #[test]
    fn lx_approve_is_noop() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Lx, CapsuleId(1));
        let proposal = d
            .propose_action(&session.session_id, "date".into())
            .expect("LX proposal should succeed");
        // Already Approved — approve() returns false (no transition).
        assert!(!d.approve(&proposal.proposal_id));
    }

    // -----------------------------------------------------------------------
    // INV-TERM-002: MIX dual control
    // -----------------------------------------------------------------------

    #[test]
    fn mix_mode_creates_pending_proposal() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(2));
        let proposal = d
            .propose_action(&session.session_id, "restart nginx".into())
            .expect("MIX proposal should succeed");
        assert_eq!(proposal.status, ApprovalStatus::Pending);
    }

    #[test]
    fn mix_mode_requires_approval_before_execute() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(2));
        let proposal = d
            .propose_action(&session.session_id, "systemctl restart".into())
            .expect("MIX proposal should succeed");

        // Execute before approval should fail.
        assert!(d.execute(&proposal.proposal_id).is_err());

        // Approve then execute.
        assert!(d.approve(&proposal.proposal_id));
        let result = d.execute(&proposal.proposal_id).expect("execution after approval should succeed");
        assert!(result.contains("systemctl restart"));
    }

    #[test]
    fn mix_mode_deny_prevents_execute() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(2));
        let proposal = d
            .propose_action(&session.session_id, "rm -rf /".into())
            .expect("MIX proposal should succeed");

        assert!(d.deny(&proposal.proposal_id));
        // Denied — execute must fail.
        assert!(d.execute(&proposal.proposal_id).is_err());
        // Denied — approve must fail.
        assert!(!d.approve(&proposal.proposal_id));
    }

    // -----------------------------------------------------------------------
    // INV-TERM-003: AI policy gate
    // -----------------------------------------------------------------------

    #[test]
    fn ai_mode_blocked_without_policy() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Ai, CapsuleId(3));
        let result = d.propose_action(&session.session_id, "deploy model".into());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("no active policy grant"));
    }

    #[test]
    fn ai_mode_allowed_with_policy() {
        let mut d = new_dispatcher();
        d.set_policy_ai_allowed(true);
        let session = d.new_session(TerminalMode::Ai, CapsuleId(3));
        let proposal = d
            .propose_action(&session.session_id, "deploy model".into())
            .expect("AI proposal with policy should succeed");
        assert_eq!(proposal.status, ApprovalStatus::Pending);

        // Still requires approval in AI mode.
        assert!(d.approve(&proposal.proposal_id));
        let result = d.execute(&proposal.proposal_id).expect("AI execution should succeed");
        assert!(result.contains("deploy model"));
    }

    #[test]
    fn ai_policy_can_be_toggled() {
        let mut d = new_dispatcher();
        assert!(!d.is_ai_allowed());

        d.set_policy_ai_allowed(true);
        assert!(d.is_ai_allowed());

        let session = d.new_session(TerminalMode::Ai, CapsuleId(3));
        assert!(d.propose_action(&session.session_id, "cmd".into()).is_ok());

        d.set_policy_ai_allowed(false);
        assert!(!d.is_ai_allowed());
        // New proposals from the same session are now blocked.
        assert!(d.propose_action(&session.session_id, "cmd2".into()).is_err());
    }

    // -----------------------------------------------------------------------
    // INV-TERM-004: Timeout safety
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_timeout_prevents_approve() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(1));
        let mut proposal = d
            .propose_action(&session.session_id, "backup db".into())
            .expect("proposal should succeed");

        let pid = proposal.proposal_id.clone();
        proposal.expires_at = Utc::now() - chrono::Duration::seconds(10);
        d.proposals.insert(pid.clone(), proposal);

        assert!(!d.approve(&pid));
        let p = d.get_proposal(&pid).expect("proposal should exist");
        assert_eq!(p.status, ApprovalStatus::TimedOut);
    }

    #[test]
    fn proposal_timeout_prevents_execute() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(1));
        let mut proposal = d
            .propose_action(&session.session_id, "backup db".into())
            .expect("proposal should succeed");

        let pid = proposal.proposal_id.clone();
        assert!(d.approve(&pid));
        proposal.expires_at = Utc::now() - chrono::Duration::seconds(10);
        d.proposals.insert(pid.clone(), proposal);

        let result = d.execute(&pid);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // INV-TERM-006: Session isolation
    // -----------------------------------------------------------------------

    #[test]
    fn closed_session_cannot_propose() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(1));
        let sid = session.session_id.clone();
        assert!(d.close_session(&sid));
        let result = d.propose_action(&sid, "cmd".into());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not active"));
    }

    #[test]
    fn close_nonexistent_session_returns_false() {
        let mut d = new_dispatcher();
        assert!(!d.close_session("nonexistent"));
    }

    #[test]
    fn reopen_restores_session() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(1));
        assert!(d.close_session(&session.session_id));
        assert!(d.reopen_session(&session.session_id));
        assert!(d
            .propose_action(&session.session_id, "cmd".into())
            .is_ok());
    }

    #[test]
    fn active_sessions_count() {
        let mut d = new_dispatcher();
        assert_eq!(d.active_sessions(), 0);

        let s1 = d.new_session(TerminalMode::Lx, CapsuleId(1));
        assert_eq!(d.active_sessions(), 1);

        let _s2 = d.new_session(TerminalMode::Mix, CapsuleId(2));
        assert_eq!(d.active_sessions(), 2);

        d.close_session(&s1.session_id);
        assert_eq!(d.active_sessions(), 1);
        assert_eq!(d.total_sessions(), 2);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn execute_nonexistent_proposal() {
        let mut d = new_dispatcher();
        assert!(d.execute("nonexistent").is_err());
    }

    #[test]
    fn approve_nonexistent_proposal() {
        let mut d = new_dispatcher();
        assert!(!d.approve("nonexistent"));
    }

    #[test]
    fn deny_nonexistent_proposal() {
        let mut d = new_dispatcher();
        assert!(!d.deny("nonexistent"));
    }

    #[test]
    fn double_approve_returns_false() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Mix, CapsuleId(1));
        let proposal = d
            .propose_action(&session.session_id, "cmd".into())
            .expect("proposal should succeed");
        assert!(d.approve(&proposal.proposal_id));
        // Second approve is idempotent — no transition.
        assert!(!d.approve(&proposal.proposal_id));
    }

    #[test]
    fn multiple_sessions_independent() {
        let mut d = new_dispatcher();
        let lx = d.new_session(TerminalMode::Lx, CapsuleId(1));
        let mix = d.new_session(TerminalMode::Mix, CapsuleId(2));

        let lx_prop = d
            .propose_action(&lx.session_id, "lx-cmd".into())
            .expect("LX should succeed");
        let mix_prop = d
            .propose_action(&mix.session_id, "mix-cmd".into())
            .expect("MIX should succeed");

        // LX is auto-approved; MIX is pending.
        assert_eq!(lx_prop.status, ApprovalStatus::Approved);
        assert_eq!(mix_prop.status, ApprovalStatus::Pending);

        // Each operates independently.
        assert!(d.execute(&lx_prop.proposal_id).is_ok());
        assert!(d.execute(&mix_prop.proposal_id).is_err()); // not yet approved

        assert!(d.approve(&mix_prop.proposal_id));
        assert!(d.execute(&mix_prop.proposal_id).is_ok());
    }

    #[test]
    fn proposal_count_tracking() {
        let mut d = new_dispatcher();
        assert_eq!(d.proposal_count(), 0);

        let lx = d.new_session(TerminalMode::Lx, CapsuleId(1));
        let _p1 = d.propose_action(&lx.session_id, "a".into()).unwrap();
        let _p2 = d.propose_action(&lx.session_id, "b".into()).unwrap();
        assert_eq!(d.proposal_count(), 2);

        let mix = d.new_session(TerminalMode::Mix, CapsuleId(2));
        let _p3 = d.propose_action(&mix.session_id, "c".into()).unwrap();
        assert_eq!(d.proposal_count(), 3);
    }

    #[test]
    fn approval_status_terminal_check() {
        assert!(!ApprovalStatus::Pending.is_terminal());
        assert!(!ApprovalStatus::Approved.is_terminal());
        assert!(ApprovalStatus::Denied.is_terminal());
        assert!(ApprovalStatus::TimedOut.is_terminal());
        assert!(ApprovalStatus::Pending.is_approvable());
        assert!(!ApprovalStatus::Approved.is_approvable());
        assert!(!ApprovalStatus::Denied.is_approvable());
        assert!(!ApprovalStatus::TimedOut.is_approvable());
    }

    #[test]
    fn unknown_session_propose_fails() {
        let mut d = new_dispatcher();
        let result = d.propose_action("no-such-session", "cmd".into());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn get_session_returns_correct_data() {
        let mut d = new_dispatcher();
        let session = d.new_session(TerminalMode::Ai, CapsuleId(42));
        let fetched = d.get_session(&session.session_id).expect("session should exist");
        assert_eq!(fetched.mode, TerminalMode::Ai);
        assert_eq!(fetched.capsule_id, CapsuleId(42));
        assert!(fetched.active);
    }
}
