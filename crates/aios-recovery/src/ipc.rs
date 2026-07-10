//! MINIX-inspired message-passing IPC for healing commands.
//!
//! Components receive structured [`HealCommand`] messages through a
//! [`HealCommandChannel`], giving them a chance to clean up state before
//! termination — mirroring MINIX's message-passing IPC between the
//! process manager and drivers.
//!
//! ## Architecture
//!
//! ```text
//! HealCommandChannel              ← bidirectional channel (sender + receiver)
//!   ├── HealCommand               ← structured command (Shutdown, Restart, ...)
//!   └── HealCommandResponse       ← component response (Ack, Nack, Timeout)
//! ```
//!
//! The driver owns the sender half (stored in a per-component `HashMap`).
//! Components own the receiver half and respond via a `oneshot` channel
//! embedded in each command envelope.

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Command types
// ---------------------------------------------------------------------------

/// Commands sent by the self-healing driver to a component before taking action.
///
/// Each variant maps to a MINIX message type: Shutdown ≈ SIGTERM with grace
/// period, `RestartInstant` ≈ `RS_RESTART`, Isolate ≈ `RS_ISOLATE`, and Checkpoint
/// ≈ `RS_CHECKPOINT` (state preservation before reincarnation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealCommand {
    /// Graceful shutdown request with an optional grace period.
    ///
    /// The component has `grace_period_seconds` to flush buffers, close
    /// connections, and persist state before the driver force-terminates.
    Shutdown {
        /// Seconds the component has to clean up before force termination.
        grace_period_seconds: u64,
    },
    /// Immediate restart — component should checkpoint and exit immediately.
    RestartInstant,
    /// Isolate this component from the service mesh.
    ///
    /// Traffic is redirected to the specified target (if any). The component
    /// stays alive but is disconnected from its peers.
    Isolate {
        /// Optional target to redirect traffic to during isolation.
        #[serde(default)]
        redirect_target: Option<String>,
    },
    /// Checkpoint current state and report the hash back.
    ///
    /// The component serializes its config, computes a BLAKE3 hash, and
    /// returns it in the Ack response. The driver uses this hash for
    /// crash-loop detection during reincarnation.
    Checkpoint {
        /// Expected state hash for verification (BLAKE3 hex).
        state_hash: String,
    },
}

/// Response from a component after processing a [`HealCommand`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealCommandResponse {
    /// Component acknowledged the command and will comply.
    ///
    /// The string payload may carry additional context (e.g. checkpoint hash,
    /// remaining connection count, etc.).
    Ack(String),
    /// Component refused the command with a reason.
    Nack {
        /// Human-readable reason for refusal.
        reason: String,
    },
    /// Component did not respond within the timeout window.
    #[default]
    Timeout,
}

// ---------------------------------------------------------------------------
// Internal envelope
// ---------------------------------------------------------------------------

/// Internal message envelope sent through the `mpsc` channel.
///
/// Each command carries a oneshot response channel so the driver can await
/// the component's acknowledgment without polling.
type CommandEnvelope = (HealCommand, oneshot::Sender<HealCommandResponse>);

// ---------------------------------------------------------------------------
// HealCommandChannel
// ---------------------------------------------------------------------------

/// A bidirectional channel for sending healing commands to a component.
///
/// The driver creates the channel, stores the sender half in its
/// per-component `HashMap`, and hands the receiver half to the component.
/// Each command includes a oneshot response channel so the driver can
/// synchronously await the component's acknowledgment.
pub struct HealCommandChannel {
    /// Sender half — owned by the self-healing driver.
    tx: mpsc::Sender<CommandEnvelope>,
    /// Receiver half — owned by the target component.
    rx: mpsc::Receiver<CommandEnvelope>,
}

impl HealCommandChannel {
    /// Create a new channel with the given buffer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self { tx, rx }
    }

    /// Build a channel from an existing sender/receiver pair.
    ///
    /// Used by the self-healing driver when it creates the channel internally
    /// and hands the receiver to the component while keeping the sender.
    #[must_use]
    pub const fn from_raw(
        tx: mpsc::Sender<CommandEnvelope>,
        rx: mpsc::Receiver<CommandEnvelope>,
    ) -> Self {
        Self { tx, rx }
    }

    /// Send a command to the component and wait for its response.
    ///
    /// Returns `None` if the component's receiver has been dropped
    /// (component exited or channel closed).
    pub async fn send_command(&self, command: HealCommand) -> Option<HealCommandResponse> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx.send((command, response_tx)).await.ok()?;
        response_rx.await.ok()
    }

    /// Try to receive a command from the driver (non-blocking).
    ///
    /// Returns `None` if no command is currently pending. This is the
    /// component-side polling interface — components call this in their
    /// main loop to check for driver commands.
    pub fn try_receive(&mut self) -> Option<(HealCommand, oneshot::Sender<HealCommandResponse>)> {
        self.rx.try_recv().ok()
    }

    /// Close the channel by dropping both halves.
    ///
    /// After calling this, no more commands can be sent or received.
    /// Any pending `send_command` calls will return `None`.
    pub fn close(self) {
        drop(self);
    }

    /// Return a clone of the sender for sharing across tasks.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<CommandEnvelope> {
        self.tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heal_command_shutdown_serializes_to_snake_case() {
        let cmd = HealCommand::Shutdown {
            grace_period_seconds: 30,
        };
        let json = serde_json::to_value(&cmd).expect("serialize");
        assert_eq!(json["shutdown"]["grace_period_seconds"], 30);
    }

    #[test]
    fn heal_command_isolate_defaults_redirect_to_none() {
        let json = serde_json::json!({
            "isolate": {
                "redirect_target": null
            }
        });
        let cmd: HealCommand = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            cmd,
            HealCommand::Isolate {
                redirect_target: None
            }
        );
    }

    #[test]
    fn heal_command_isolate_with_redirect_target() {
        let json = serde_json::json!({
            "isolate": {
                "redirect_target": "standby-01.local"
            }
        });
        let cmd: HealCommand = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            cmd,
            HealCommand::Isolate {
                redirect_target: Some("standby-01.local".to_owned())
            }
        );
    }

    #[test]
    fn heal_command_response_ack_serializes_to_screaming_snake() {
        let resp = HealCommandResponse::Ack("checkpoint=abc123".to_owned());
        let json = serde_json::to_value(&resp).expect("serialize");
        assert!(
            json.as_object().unwrap().contains_key("ACK"),
            "Ack variant key must be ACK"
        );
    }

    #[test]
    fn heal_command_response_nack_serializes_to_screaming_snake() {
        let resp = HealCommandResponse::Nack {
            reason: "still draining".to_owned(),
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        let obj = json.as_object().expect("Nack must be an object");
        assert!(obj.contains_key("NACK"));
    }

    #[test]
    fn heal_command_response_timeout_serializes_to_screaming_snake() {
        let resp = HealCommandResponse::Timeout;
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json.as_str().unwrap(), "TIMEOUT");
    }

    #[test]
    fn heal_command_response_default_is_timeout() {
        assert_eq!(HealCommandResponse::default(), HealCommandResponse::Timeout);
    }

    #[test]
    fn heal_command_response_serde_round_trip_all_variants() {
        // Ack
        let ack = HealCommandResponse::Ack("done".to_owned());
        let json = serde_json::to_value(&ack).expect("serialize");
        let rt: HealCommandResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(rt, ack);

        // Nack
        let nack = HealCommandResponse::Nack {
            reason: "busy".to_owned(),
        };
        let json = serde_json::to_value(&nack).expect("serialize");
        let rt: HealCommandResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(rt, nack);

        // Timeout
        let timeout = HealCommandResponse::Timeout;
        let json = serde_json::to_value(&timeout).expect("serialize");
        let rt: HealCommandResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(rt, timeout);
    }

    #[tokio::test]
    async fn channel_send_receive_round_trip() {
        let mut channel = HealCommandChannel::new(4);
        let sender = channel.sender();

        // Spawn a task that sends a command and checks the response
        let handle = tokio::spawn(async move {
            let response = HealCommandChannel {
                tx: sender,
                rx: mpsc::channel(1).1, // dummy rx — not needed for send
            }
            .send_command(HealCommand::Shutdown {
                grace_period_seconds: 10,
            })
            .await;
            response
        });

        // Yield to let the spawned task execute its send
        tokio::task::yield_now().await;

        // Receive the command on the component side
        let (cmd, response_tx) = channel.try_receive().expect("should receive command");
        assert_eq!(
            cmd,
            HealCommand::Shutdown {
                grace_period_seconds: 10
            }
        );

        // Respond with Ack
        response_tx
            .send(HealCommandResponse::Ack("shutting down".to_owned()))
            .expect("send response");

        let response = handle.await.expect("task should complete");
        assert_eq!(
            response,
            Some(HealCommandResponse::Ack("shutting down".to_owned()))
        );
    }

    #[tokio::test]
    async fn try_receive_returns_none_when_empty() {
        let mut channel = HealCommandChannel::new(4);
        assert!(channel.try_receive().is_none());
    }

    #[tokio::test]
    async fn send_command_returns_none_when_receiver_dropped() {
        let channel = HealCommandChannel::new(4);
        drop(channel); // drops both tx and rx
                       // We need a new channel to test with a dropped rx
        let (tx, rx) = mpsc::channel::<CommandEnvelope>(1);
        drop(rx);
        let channel = HealCommandChannel {
            tx,
            rx: mpsc::channel::<CommandEnvelope>(1).1, // placeholder
        };
        let result = channel.send_command(HealCommand::RestartInstant).await;
        assert!(result.is_none(), "send should fail when rx is dropped");
    }
}
