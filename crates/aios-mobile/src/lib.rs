//! `aios-mobile` — typed core skeleton for S23 Mobile Renderer and Touch Shell.
//!
//! This crate provides the type surface for AIOS mobile/voice approval
//! surfaces: mobile surface profiles, offline approval tokens, QR-based
//! recovery pairing, pocket node shard holders, voice intent classification,
//! and the mobile approval request FSM.

#![forbid(unsafe_code)]

pub mod approval;
pub mod component_render;
pub mod enums;
pub mod offline_token;
pub mod pocket_node;
pub mod qr_pairing;
pub mod surface;
pub mod voice;

pub use approval::{MobileApprovalRequest, MobileApprovalState};
pub use enums::{
    ApprovalRiskBand, MobileFormFactor, MobileSurfaceMode, MobileTransport, VoiceIntent,
};
pub use offline_token::OfflineApprovalToken;
pub use pocket_node::{PocketNode, PocketNodeRole};
pub use qr_pairing::RecoveryPairingQr;
pub use surface::MobileSurface;
pub use voice::VoiceSurface;
