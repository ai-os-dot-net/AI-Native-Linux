//! Closed enumerations for the S23 mobile/voice surface domain.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// The rendering mode of a mobile surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MobileSurfaceMode {
    /// Full AIOS mobile renderer (native compositor surface).
    AiOSMobileRenderer,
    /// Phone edition renderer with telephony integration.
    AiOSPhoneEdition,
}

/// Transport mechanism for the mobile surface connection to the AIOS host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MobileTransport {
    /// Direct LAN connection (same subnet, zero relay).
    LanDirect,
    /// Authenticated relay through the AIOS host.
    RelayAuthenticated,
    /// Offline token-based approval (no live connection).
    OfflineToken,
    /// QR code pairing for initial trust bootstrap.
    QrPairing,
}

/// Physical form factor of the mobile device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MobileFormFactor {
    /// Standard smartphone form factor.
    Phone,
    /// Tablet-sized device.
    Tablet,
    /// Handheld or wearable form factor.
    Handheld,
    /// Watch or glance-sized display surface.
    WatchGlance,
}

/// Risk band assigned to a mobile approval request.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalRiskBand {
    /// Low risk — routine approval.
    Low,
    /// Medium risk — requires surface-specific confirmation.
    Medium,
    /// High risk — requires multi-factor or visual confirmation.
    High,
    /// Critical risk — requires emergency stop capability.
    Critical,
}

/// Lifecycle state of a voice intent on a voice surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceIntent {
    /// Voice audio received, awaiting classification.
    Received,
    /// Voice intent classified into a typed action domain.
    Classified,
    /// Voice intent mapped to a concrete typed action request.
    MappedToTypedAction,
    /// Voice intent rejected as unsafe or unclassifiable.
    RejectedAsUnsafe,
}
