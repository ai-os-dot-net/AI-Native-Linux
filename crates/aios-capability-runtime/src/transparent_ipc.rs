//! QNX / Plan 9 -inspired transparent distributed IPC.
//!
//! ## OS Research Provenance
//!
//! QNX's microkernel (BlackBerry, ISO 26262 ASIL‑D) introduced the tightest
//! IPC + scheduling coupling in production:
//!
//! 1. **MsgSend** — the caller blocks and the kernel *transfers the CPU
//!    directly* to the receiver.  No intermediate kernel buffering, no
//!    scheduler run-queue insertion.  If the receiver is already waiting on
//!    `MsgReceive`, the CPU jumps to the receiver's thread in O(1).
//! 2. **MsgReply** / **MsgError** — the receiver unblocks the original
//!    sender with a response (or error code).
//! 3. **MsgSendPulse** — a non-blocking one-way notification (no reply
//!    expected).  Pulses carry a small fixed-size payload (8 bits of code).
//! 4. **Transparent distributed IPC** — QNX's network manager (Qnet)
//!    extends MsgSend across machines.  The sender never knows whether the
//!    receiver is local or remote.
//!
//! Plan 9 from Bell Labs contributed the **9P** protocol — every resource is
//! accessed through a message-oriented protocol, and the client never knows
//! whether the server is on the same machine or across the network.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | QNX / Plan 9 concept     | AIOS equivalent                              |
//! |---------------------------|----------------------------------------------|
//! | `MsgSend`                 | [`MsgType::Request`] (synchronous RPC)       |
//! | `MsgReply` / `MsgError`   | [`MsgType::Reply`] / [`MsgType::Error`]       |
//! | `MsgSendPulse`            | [`MsgType::Pulse`] (non-blocking notification)|
//! | Transparent Qnet          | [`CapsuleAddr`] — local or remote endpoint   |
//! | Thread receiver (rcvid)   | [`CapsuleIPC`] channel pair (mpsc + oneshot) |
//! | 9P connection / fid       | [`MsgId`] — unique per-request identifier    |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-IPC-001 (Uniqueness):** Every request [`MsgId`] is globally
//!   unique (monotonically increasing).
//! - **INV-IPC-002 (Request-reply pairing):** A [`MsgType::Reply`] must
//!   reference a valid, outstanding [`MsgType::Request`].
//! - **INV-IPC-003 (No double-reply):** Once a request has been replied to,
//!   it cannot be replied to again.
//! - **INV-IPC-004 (Pulse independence):** A [`MsgType::Pulse`] requires no
//!   reply and cannot be replied to.
//! - **INV-IPC-005 (Source consistency):** The `reply_to` field of a reply
//!   must match the `msg_id` of the original request, and the `source` /
//!   `target` fields are swapped.
//! - **INV-IPC-006 (Transparent addressing):** A [`CapsuleAddr`] can be
//!   either [`CapsuleAddr::Local`] or [`CapsuleAddr::Remote`]; the router
//!   resolves both uniformly without leaking the distinction to callers.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Re-use the capsule identifier and path model from sibling modules.
use super::capsule_namespace::{CapsuleId, NamespacePath};

// ---------------------------------------------------------------------------
// MsgId — unique per-message identifier
// ---------------------------------------------------------------------------

/// Global unique identifier for every message in the IPC system.
///
/// This is the AIOS analogue of QNX's `rcvid` (receive identifier) — it
/// links every reply/pulse/error back to its originating request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsgId(u64);

impl MsgId {
    /// Raw numeric value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msg-{}", self.0)
    }
}

static NEXT_MSG_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh, globally-unique [`MsgId`].
#[must_use]
pub fn next_msg_id() -> MsgId {
    MsgId(NEXT_MSG_ID.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// MsgType — QNX message type classification
// ---------------------------------------------------------------------------

/// The type of a capsule message, modeling QNX's three IPC primitives.
///
/// | Variant     | QNX equivalent     | Blocks sender? | Expects reply? |
/// |-------------|--------------------|----------------|-----------------|
/// | `Request`   | `MsgSend`          | Yes            | Yes             |
/// | `Reply`     | `MsgReply`         | No             | No (unblocks)   |
/// | `Pulse`     | `MsgSendPulse`     | No             | No              |
/// | `Error`     | `MsgError`         | No             | No (unblocks)   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    /// Synchronous RPC — sender blocks until receiver replies.
    Request,
    /// Successful reply to a `Request`.
    Reply,
    /// Non-blocking, one-way notification with no response expected.
    Pulse,
    /// Error reply to a `Request` (carries an error code instead of payload).
    Error,
}

impl MsgType {
    /// Whether this message type expects a reply.
    #[must_use]
    pub const fn expects_reply(self) -> bool {
        matches!(self, Self::Request)
    }

    /// Whether this message type IS a reply (success or error).
    #[must_use]
    pub const fn is_reply(self) -> bool {
        matches!(self, Self::Reply | Self::Error)
    }
}

// ---------------------------------------------------------------------------
// CapsuleAddr — transparent endpoint (QNX Qnet / Plan 9 9P)
// ---------------------------------------------------------------------------

/// A transparent network endpoint for a capsule.
///
/// The sender never needs to know whether the destination is local or remote
/// (QNX Qnet semantics).  The router resolves the address uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleAddr {
    /// Local capsule — reached via in-process channel (no serialisation).
    Local {
        /// The target capsule identifier.
        capsule_id: CapsuleId,
    },
    /// Remote capsule — reached via Unix domain socket or TCP.
    Remote {
        /// The remote capsule identifier.
        capsule_id: CapsuleId,
        /// URI-style endpoint, e.g. `unix:/run/a.sock` or `tcp://192.168.1.10:9009`.
        endpoint: String,
    },
}

impl CapsuleAddr {
    /// Create a local address.
    #[must_use]
    pub const fn local(capsule_id: CapsuleId) -> Self {
        Self::Local { capsule_id }
    }

    /// Create a remote address with a given endpoint URI.
    #[must_use]
    pub const fn remote(capsule_id: CapsuleId, endpoint: String) -> Self {
        Self::Remote {
            capsule_id,
            endpoint,
        }
    }

    /// The capsule ID regardless of locality.
    #[must_use]
    pub const fn capsule_id(&self) -> CapsuleId {
        match self {
            Self::Local { capsule_id } | Self::Remote { capsule_id, .. } => *capsule_id,
        }
    }

    /// Whether this address is local (no network hop required).
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// The endpoint URI, if remote.
    #[must_use]
    pub const fn endpoint(&self) -> Option<&str> {
        match self {
            Self::Remote { endpoint, .. } => Some(endpoint.as_str()),
            Self::Local { .. } => None,
        }
    }
}

impl fmt::Display for CapsuleAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local { capsule_id } => write!(f, "local://{capsule_id}"),
            Self::Remote {
                capsule_id: _,
                endpoint,
            } => write!(f, "{endpoint}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CapsuleMessage — the IPC envelope
// ---------------------------------------------------------------------------

/// A single message passed between capsules, modeled after QNX's message
/// structure (`_msg_info`, `MsgSend`, `MsgReply`).
///
/// # Fields
///
/// | Field       | QNX equivalent                  |
/// |-------------|---------------------------------|
/// | `msg_id`    | `rcvid` + kernel tracking       |
/// | `msg_type`  | `_IO_READ` / `_IO_WRITE` / pulse|
/// | `source`    | sender pid (QNX `_msg_info.nd`)  |
/// | `target`    | receiver pid                     |
/// | `payload`   | data payload                     |
/// | `reply_to`  | `rcvid` for Reply/Error          |
/// | `namespace` | 9P-style resource path           |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleMessage {
    /// Globally unique identifier for this message (INV-IPC-001).
    pub msg_id: MsgId,
    /// The type of message (Request, Reply, Pulse, Error).
    pub msg_type: MsgType,
    /// Sender capsule.
    pub source: CapsuleId,
    /// Intended recipient capsule.
    pub target: CapsuleId,
    /// Opaque payload.
    pub payload: Vec<u8>,
    /// For Reply / Pulse / Error — the [`MsgId`] of the original Request
    /// that this message responds to.
    pub reply_to: Option<MsgId>,
    /// Plan 9-style resource path this message addresses
    /// (e.g. `/ml/inference/gpt4`, `/data/sessions`).
    pub namespace: Option<NamespacePath>,
}

impl CapsuleMessage {
    /// Create a new [`MsgType::Request`].
    #[must_use]
    pub fn request(
        source: CapsuleId,
        target: CapsuleId,
        payload: Vec<u8>,
        namespace: Option<NamespacePath>,
    ) -> Self {
        Self {
            msg_id: next_msg_id(),
            msg_type: MsgType::Request,
            source,
            target,
            payload,
            reply_to: None,
            namespace,
        }
    }

    /// Create a [`MsgType::Reply`] to a previous request.
    ///
    /// The `source` / `target` fields are automatically swapped and
    /// `reply_to` is set to the original request's `msg_id` (INV-IPC-005).
    #[must_use]
    pub fn reply_to(request: &Self, payload: Vec<u8>) -> Self {
        Self {
            msg_id: next_msg_id(),
            msg_type: MsgType::Reply,
            source: request.target,
            target: request.source,
            payload,
            reply_to: Some(request.msg_id),
            namespace: request.namespace.clone(),
        }
    }

    /// Create a [`MsgType::Error`] response.
    #[must_use]
    pub fn error_to(request: &Self, error_payload: Vec<u8>) -> Self {
        Self {
            msg_id: next_msg_id(),
            msg_type: MsgType::Error,
            source: request.target,
            target: request.source,
            payload: error_payload,
            reply_to: Some(request.msg_id),
            namespace: request.namespace.clone(),
        }
    }

    /// Create a non-blocking [`MsgType::Pulse`].
    #[must_use]
    pub fn pulse(
        source: CapsuleId,
        target: CapsuleId,
        code: u8,
        namespace: Option<NamespacePath>,
    ) -> Self {
        Self {
            msg_id: next_msg_id(),
            msg_type: MsgType::Pulse,
            source,
            target,
            payload: vec![code],
            reply_to: None,
            namespace,
        }
    }

    /// Whether this message is still awaiting a reply.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.msg_type.expects_reply()
    }
}

// ---------------------------------------------------------------------------
// PendingRequest — tracking an outstanding request (QNX rcvid)
// ---------------------------------------------------------------------------

/// An entry in the outstanding-request table.  The router uses this to match
/// replies back to their originating requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// The ID of the originating request.
    pub msg_id: MsgId,
    /// The capsule that sent the request.
    pub sender: CapsuleId,
    /// The capsule that received the request.
    pub receiver: CapsuleId,
    /// Whether the request has been replied to (INV-IPC-003 guard).
    pub replied: bool,
}

impl PendingRequest {
    /// Create a new pending-request entry.
    #[must_use]
    pub const fn new(msg_id: MsgId, sender: CapsuleId, receiver: CapsuleId) -> Self {
        Self {
            msg_id,
            sender,
            receiver,
            replied: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MessageRouter — transparent routing table (QNX Qnet + 9P)
// ---------------------------------------------------------------------------

/// Central routing table that maps capsule addresses and tracks outstanding
/// requests.
///
/// This is the AIOS analogue of:
/// - QNX's internal thread table (which maps `rcvid` → sender thread)
/// - Qnet's distributed routing (which forwards `MsgSend` across nodes)
/// - Plan 9's 9P connection multiplexer
///
/// The router is **transparent** — callers use [`CapsuleId`] regardless of
/// whether the destination is local or remote (INV-IPC-006).
#[derive(Debug, Default, Clone)]
pub struct MessageRouter {
    /// Capsule ID → addressing info.
    address_book: HashMap<CapsuleId, CapsuleAddr>,
    /// Outstanding requests awaiting reply (rcvid table).
    pending: HashMap<MsgId, PendingRequest>,
}

impl MessageRouter {
    /// Create an empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            address_book: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// ---------- register / unregister --------------------------------------
    ///
    /// Register a capsule's address.
    ///
    /// If the capsule is already registered, the address is **replaced**
    /// (e.g., after migration from local to remote).
    pub fn register(&mut self, addr: CapsuleAddr) {
        self.address_book.insert(addr.capsule_id(), addr);
    }

    /// Remove a capsule from the routing table (teardown).
    ///
    /// All outstanding requests for this capsule are cleaned up.
    pub fn unregister(&mut self, capsule_id: CapsuleId) -> usize {
        let removed_addr = self.address_book.remove(&capsule_id).is_some();
        let pending_before = self.pending.len();
        self.pending
            .retain(|_k, v| v.sender != capsule_id && v.receiver != capsule_id);
        let removed_pending = pending_before - self.pending.len();
        if removed_addr {
            1 + removed_pending
        } else {
            removed_pending
        }
    }

    /// Look up a capsule's address.
    #[must_use]
    pub fn resolve(&self, capsule_id: CapsuleId) -> Option<&CapsuleAddr> {
        self.address_book.get(&capsule_id)
    }

    /// Whether a capsule is registered.
    #[must_use]
    pub fn is_registered(&self, capsule_id: CapsuleId) -> bool {
        self.address_book.contains_key(&capsule_id)
    }

    /// ---------- request lifecycle -----------------------------------------
    ///
    /// Record an outstanding request after sending it.
    ///
    /// Returns `false` if the request ID is already present in the pending
    /// table (INV-IPC-001 violation — duplicate `MsgId`).
    pub fn track_request(&mut self, msg_id: MsgId, sender: CapsuleId, receiver: CapsuleId) -> bool {
        if self.pending.contains_key(&msg_id) {
            return false;
        }
        self.pending
            .insert(msg_id, PendingRequest::new(msg_id, sender, receiver));
        true
    }

    /// Look up a pending request by its message ID.
    #[must_use]
    pub fn get_pending(&self, msg_id: MsgId) -> Option<&PendingRequest> {
        self.pending.get(&msg_id)
    }

    /// Mark a pending request as replied (INV-IPC-003 guard).
    ///
    /// Returns `false` if:
    /// - The request doesn't exist.
    /// - The request was already replied to.
    /// - The reply source doesn't match the expected receiver.
    pub fn mark_replied(&mut self, reply_to: MsgId, replier: CapsuleId) -> bool {
        match self.pending.get_mut(&reply_to) {
            Some(entry) if !entry.replied && entry.receiver == replier => {
                entry.replied = true;
                true
            }
            _ => false,
        }
    }

    /// Clean up a single completed request.
    ///
    /// Returns the removed [`PendingRequest`], or `None` if not found.
    pub fn complete_request(&mut self, msg_id: MsgId) -> Option<PendingRequest> {
        self.pending.remove(&msg_id)
    }

    /// Number of outstanding (unreplied) requests.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.values().filter(|e| !e.replied).count()
    }

    /// Total entries in the pending table (including replied-but-not-cleaned).
    #[must_use]
    pub fn pending_table_size(&self) -> usize {
        self.pending.len()
    }

    /// Number of registered capsules.
    #[must_use]
    pub fn capsule_count(&self) -> usize {
        self.address_book.len()
    }

    /// Whether the router has zero registered capsules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.address_book.is_empty() && self.pending.is_empty()
    }
}

// ===========================================================================
// Tests — INV-IPC-001 through INV-IPC-006
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // MsgId uniqueness (INV-IPC-001)
    // -----------------------------------------------------------------------

    #[test]
    fn msg_ids_are_monotonically_increasing() {
        let a = next_msg_id();
        let b = next_msg_id();
        let c = next_msg_id();
        assert!(a < b);
        assert!(b < c);
    }

    // -----------------------------------------------------------------------
    // CapsuleMessage construction
    // -----------------------------------------------------------------------

    #[test]
    fn request_has_no_reply_to_and_expects_reply() {
        let src = CapsuleId(1);
        let tgt = CapsuleId(2);
        let msg = CapsuleMessage::request(src, tgt, vec![1, 2, 3], None);
        assert_eq!(msg.source, src);
        assert_eq!(msg.target, tgt);
        assert_eq!(msg.msg_type, MsgType::Request);
        assert!(msg.reply_to.is_none());
        assert!(msg.is_pending());
        assert_eq!(msg.payload, vec![1, 2, 3]);
    }

    #[test]
    fn reply_swaps_source_and_target_and_sets_reply_to() {
        let req = CapsuleMessage::request(CapsuleId(1), CapsuleId(2), vec![], None);
        let req_id = req.msg_id;

        let reply = CapsuleMessage::reply_to(&req, vec![4, 5]);
        assert_eq!(reply.msg_type, MsgType::Reply);
        assert_eq!(reply.source, CapsuleId(2)); // swapped
        assert_eq!(reply.target, CapsuleId(1)); // swapped
        assert_eq!(reply.reply_to, Some(req_id));
        assert!(!reply.is_pending()); // replies don't expect replies
    }

    #[test]
    fn error_swaps_source_and_target() {
        let req = CapsuleMessage::request(CapsuleId(1), CapsuleId(2), vec![], None);
        let err = CapsuleMessage::error_to(&req, b"timeout".to_vec());
        assert_eq!(err.msg_type, MsgType::Error);
        assert_eq!(err.source, CapsuleId(2));
        assert_eq!(err.target, CapsuleId(1));
        assert!(err.reply_to.is_some());
    }

    #[test]
    fn pulse_is_nonblocking_no_reply() {
        let pulse = CapsuleMessage::pulse(CapsuleId(1), CapsuleId(2), 42, None);
        assert_eq!(pulse.msg_type, MsgType::Pulse);
        assert!(pulse.reply_to.is_none());
        assert!(!pulse.is_pending());
        assert_eq!(pulse.payload, vec![42]);
    }

    #[test]
    fn namespace_is_preserved_in_reply() {
        let ns = NamespacePath::new("/ml/inference/gpt4").unwrap();
        let req = CapsuleMessage::request(CapsuleId(1), CapsuleId(2), vec![], Some(ns.clone()));

        let reply = CapsuleMessage::reply_to(&req, vec![]);
        assert_eq!(
            reply.namespace.as_ref().map(|p| p.as_str()),
            Some("/ml/inference/gpt4")
        );

        let err = CapsuleMessage::error_to(&req, vec![]);
        assert_eq!(
            err.namespace.as_ref().map(|p| p.as_str()),
            Some("/ml/inference/gpt4")
        );
    }

    // -----------------------------------------------------------------------
    // MsgType predicates
    // -----------------------------------------------------------------------

    #[test]
    fn only_request_expects_reply() {
        assert!(MsgType::Request.expects_reply());
        assert!(!MsgType::Reply.expects_reply());
        assert!(!MsgType::Pulse.expects_reply());
        assert!(!MsgType::Error.expects_reply());
    }

    #[test]
    fn reply_and_error_are_replies() {
        assert!(MsgType::Reply.is_reply());
        assert!(MsgType::Error.is_reply());
        assert!(!MsgType::Request.is_reply());
        assert!(!MsgType::Pulse.is_reply());
    }

    // -----------------------------------------------------------------------
    // CapsuleAddr — transparent addressing (INV-IPC-006)
    // -----------------------------------------------------------------------

    #[test]
    fn local_address_is_local() {
        let addr = CapsuleAddr::local(CapsuleId(7));
        assert!(addr.is_local());
        assert!(addr.endpoint().is_none());
        assert_eq!(addr.capsule_id(), CapsuleId(7));
    }

    #[test]
    fn remote_address_has_endpoint() {
        let addr = CapsuleAddr::remote(CapsuleId(7), "unix:/run/capsule-007.sock".into());
        assert!(!addr.is_local());
        assert_eq!(addr.endpoint(), Some("unix:/run/capsule-007.sock"));
        assert_eq!(addr.capsule_id(), CapsuleId(7));
    }

    #[test]
    fn display_formats_addr() {
        let local = CapsuleAddr::local(CapsuleId(3));
        assert_eq!(format!("{}", local), "local://capsule-3");
        let remote = CapsuleAddr::remote(CapsuleId(5), "tcp://10.0.0.1:9009".into());
        assert_eq!(format!("{}", remote), "tcp://10.0.0.1:9009");
    }

    // -----------------------------------------------------------------------
    // MessageRouter — register / resolve / unregister
    // -----------------------------------------------------------------------

    #[test]
    fn router_starts_empty() {
        let r = MessageRouter::new();
        assert_eq!(r.capsule_count(), 0);
    }

    #[test]
    fn register_and_resolve_capsule() {
        let mut r = MessageRouter::new();
        let id = CapsuleId(1);
        r.register(CapsuleAddr::local(id));
        assert!(r.is_registered(id));
        assert_eq!(r.capsule_count(), 1);

        let resolved = r.resolve(id).unwrap();
        assert!(resolved.is_local());
        assert_eq!(resolved.capsule_id(), id);
    }

    #[test]
    fn register_replaces_existing_address() {
        let mut r = MessageRouter::new();
        let id = CapsuleId(1);
        r.register(CapsuleAddr::local(id));
        assert!(r.resolve(id).unwrap().is_local());

        // Migrate to remote.
        r.register(CapsuleAddr::remote(id, "tcp://10.0.0.1:9009".into()));
        assert_eq!(r.capsule_count(), 1); // still one entry
        assert!(!r.resolve(id).unwrap().is_local());
    }

    #[test]
    fn unregister_removes_capsule_and_cleans_pending() {
        let mut r = MessageRouter::new();
        let a = CapsuleId(1);
        let b = CapsuleId(2);
        r.register(CapsuleAddr::local(a));
        r.register(CapsuleAddr::local(b));

        // Add a pending request.
        let msg_id = next_msg_id();
        assert!(r.track_request(msg_id, a, b));
        assert_eq!(r.pending_count(), 1);

        // Unregister b — should clean the pending request too.
        let removed = r.unregister(b);
        assert!(removed > 0);
        assert!(!r.is_registered(b));
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn unregister_nonexistent_returns_zero() {
        let mut r = MessageRouter::new();
        assert_eq!(r.unregister(CapsuleId(999)), 0);
    }

    // -----------------------------------------------------------------------
    // INV-IPC-002: request-reply pairing
    // -----------------------------------------------------------------------

    #[test]
    fn track_request_succeeds_for_new_id() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        assert!(r.track_request(msg_id, CapsuleId(1), CapsuleId(2)));
        assert_eq!(r.pending_count(), 1);
    }

    #[test]
    fn track_request_fails_for_duplicate_id() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        assert!(r.track_request(msg_id, CapsuleId(1), CapsuleId(2)));
        // INV-IPC-001: duplicate MsgId must be rejected.
        assert!(!r.track_request(msg_id, CapsuleId(3), CapsuleId(4)));
        assert_eq!(r.pending_count(), 1);
    }

    #[test]
    fn get_pending_returns_correct_entry() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        r.track_request(msg_id, CapsuleId(1), CapsuleId(2));

        let entry = r.get_pending(msg_id).unwrap();
        assert_eq!(entry.msg_id, msg_id);
        assert_eq!(entry.sender, CapsuleId(1));
        assert_eq!(entry.receiver, CapsuleId(2));
        assert!(!entry.replied);
    }

    #[test]
    fn get_pending_returns_none_for_unknown() {
        let r = MessageRouter::new();
        assert!(r.get_pending(MsgId(999)).is_none());
    }

    // -----------------------------------------------------------------------
    // INV-IPC-003: no double-reply
    // -----------------------------------------------------------------------

    #[test]
    fn mark_replied_succeeds_once() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        r.track_request(msg_id, CapsuleId(1), CapsuleId(2));

        // First reply from the correct receiver.
        assert!(r.mark_replied(msg_id, CapsuleId(2)));
        assert!(r.get_pending(msg_id).unwrap().replied);

        // Second reply attempt must fail.
        assert!(!r.mark_replied(msg_id, CapsuleId(2)));
    }

    #[test]
    fn wrong_replier_cannot_mark_replied() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        r.track_request(msg_id, CapsuleId(1), CapsuleId(2));

        // CapsuleId(3) is not the receiver — should be rejected.
        assert!(!r.mark_replied(msg_id, CapsuleId(3)));
    }

    #[test]
    fn mark_replied_fails_for_unknown_id() {
        let mut r = MessageRouter::new();
        assert!(!r.mark_replied(MsgId(999), CapsuleId(2)));
    }

    // -----------------------------------------------------------------------
    // INV-IPC-004: Pulse independence
    // -----------------------------------------------------------------------

    #[test]
    fn pulse_has_no_reply_to_and_cannot_be_replied_to() {
        let pulse = CapsuleMessage::pulse(CapsuleId(1), CapsuleId(2), 0, None);
        assert!(pulse.reply_to.is_none());
        // A reply referencing a pulse would be nonsensical — pulses have no
        // reply_to, so mark_replied with a pulse's msg_id should always fail.
        let mut r = MessageRouter::new();
        assert!(!r.mark_replied(pulse.msg_id, CapsuleId(2)));
    }

    // -----------------------------------------------------------------------
    // INV-IPC-005: Source consistency on reply
    // -----------------------------------------------------------------------

    #[test]
    fn reply_source_matches_original_target() {
        let req = CapsuleMessage::request(CapsuleId(1), CapsuleId(2), vec![], None);
        let reply = CapsuleMessage::reply_to(&req, vec![]);
        assert_eq!(reply.source, req.target);
        assert_eq!(reply.target, req.source);
        assert_eq!(reply.reply_to, Some(req.msg_id));
    }

    #[test]
    fn error_source_matches_original_target() {
        let req = CapsuleMessage::request(CapsuleId(1), CapsuleId(2), vec![], None);
        let err = CapsuleMessage::error_to(&req, vec![]);
        assert_eq!(err.source, req.target);
        assert_eq!(err.target, req.source);
        assert_eq!(err.reply_to, Some(req.msg_id));
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn complete_request_removes_from_pending() {
        let mut r = MessageRouter::new();
        let msg_id = next_msg_id();
        r.track_request(msg_id, CapsuleId(1), CapsuleId(2));

        let entry = r.complete_request(msg_id).unwrap();
        assert_eq!(entry.msg_id, msg_id);
        assert_eq!(r.pending_table_size(), 0);
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn complete_request_returns_none_for_unknown() {
        let mut r = MessageRouter::new();
        assert!(r.complete_request(MsgId(999)).is_none());
    }

    #[test]
    fn pending_count_only_counts_unreplied() {
        let mut r = MessageRouter::new();
        let m1 = next_msg_id();
        let m2 = next_msg_id();
        r.track_request(m1, CapsuleId(1), CapsuleId(2));
        r.track_request(m2, CapsuleId(3), CapsuleId(4));

        assert_eq!(r.pending_count(), 2);
        assert!(r.mark_replied(m1, CapsuleId(2)));
        assert_eq!(r.pending_count(), 1); // only m2 is still unreplied
        assert_eq!(r.pending_table_size(), 2); // both still in table
    }

    #[test]
    fn display_formats_msg_id() {
        let msg_id = MsgId(42);
        assert_eq!(format!("{}", msg_id), "msg-42");
        assert_eq!(msg_id.raw(), 42);
    }
}
