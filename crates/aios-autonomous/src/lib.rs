//! AIOS Rev.10 — Autonomous Fleet Operations
//!
//! Autonomous fleet healing, cross-machine cognition, distributed consensus,
//! and constitutional governance at scale. The daemon that says "I will now
//! heal this fleet autonomously."

#![forbid(unsafe_code)]

// ── Autonomy core ──
pub mod autonomy_engine;
pub mod cross_machine_healing;
pub mod distributed_cognition;
pub mod governance;

// ── Orchestration ──
pub mod failover;
pub mod orchestrator;

// ── Integration ──
pub mod bridge;
pub mod evidence_sync;

// ── Vocabulary ──
pub mod enums;
pub mod error;

pub use autonomy_engine::AutonomyEngine;
pub use bridge::FleetCognitionBridge;
pub use cross_machine_healing::CrossMachineHealing;
pub use distributed_cognition::DistributedCognitiveRouter;
pub use error::AutonomousError;
pub use evidence_sync::CrossMachineEvidenceSync;
pub use failover::AutonomousFailoverEngine;
pub use governance::FleetConstitution;
pub use orchestrator::AutonomousOrchestrator;
