//! Recovery pairing via QR code — establishes initial trust between a
//! mobile surface and the AIOS host through an in-person pairing channel.

use chrono::{DateTime, Duration, Utc};

/// Base32 encoding alphabet per RFC 4648.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes `data` as a base32 string (RFC 4648, no padding).
fn encode_base32(data: &[u8]) -> String {
    let mut output = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;

    for &byte in data {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let idx = (buffer >> bits) as usize & 0x1F;
            output.push(BASE32_ALPHABET[idx] as char);
        }
    }

    if bits > 0 {
        let idx = (buffer << (5 - bits)) as usize & 0x1F;
        output.push(BASE32_ALPHABET[idx] as char);
    }

    output
}

/// A QR-based recovery pairing session used to bootstrap trust between a
/// mobile surface and the AIOS host over an in-person channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPairingQr {
    /// Unique pairing identifier (format `rpqr_<ULID>`).
    pub pairing_id: String,
    /// Single-use host nonce encoded in base32.
    pub host_nonce: String,
    /// Host public key for the pairing session.
    pub host_pubkey: String,
    /// Pairing channel — always `"IN_PERSON"`.
    pub pairing_channel: String,
    /// Time after which this pairing session expires.
    pub expires_at: DateTime<Utc>,
}

impl RecoveryPairingQr {
    /// Creates a new recovery pairing QR session with a freshly generated
    /// single-use nonce.
    #[must_use]
    pub fn new(host_pubkey: String, validity_seconds: i64) -> Self {
        let pairing_id = format!("rpqr_{}", ulid::Ulid::new());
        let nonce_ulid = ulid::Ulid::new();
        let host_nonce = encode_base32(&nonce_ulid.to_bytes());
        let now = Utc::now();
        let expires_at = now + Duration::seconds(validity_seconds);
        Self {
            pairing_id,
            host_nonce,
            host_pubkey,
            pairing_channel: "IN_PERSON".to_string(),
            expires_at,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn constructor_generates_valid_pairing() {
        let qr = RecoveryPairingQr::new("pubkey_abc123".to_string(), 600);
        assert!(qr.pairing_id.starts_with("rpqr_"));
        assert!(!qr.host_nonce.is_empty());
        assert_eq!(qr.pairing_channel, "IN_PERSON");
    }

    #[test]
    fn nonce_is_unique_per_creation() {
        let qr1 = RecoveryPairingQr::new("pk1".to_string(), 600);
        let qr2 = RecoveryPairingQr::new("pk2".to_string(), 600);
        assert_ne!(qr1.host_nonce, qr2.host_nonce);
        assert_ne!(qr1.pairing_id, qr2.pairing_id);
    }

    #[test]
    fn base32_encoding_is_deterministic() {
        let input = b"hello";
        let enc1 = encode_base32(input);
        let enc2 = encode_base32(input);
        assert_eq!(enc1, enc2);
        assert!(!enc1.is_empty());
    }

    #[test]
    fn expiry_is_in_the_future() {
        let qr = RecoveryPairingQr::new("pk".to_string(), 3600);
        assert!(qr.expires_at > Utc::now());
    }
}
