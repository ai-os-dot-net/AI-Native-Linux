use std::fmt::Debug;
use std::sync::Mutex;

use aios_evidence::{EvidenceReceipt, ReceiptBuilder, ReceiptChain, RecordType, RetentionClass};

use crate::error::WaydroidError;

pub trait WaydroidEvidenceEmitter: Send + Sync {
    fn emit(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<EvidenceReceipt, WaydroidError>;
}

impl Debug for dyn WaydroidEvidenceEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaydroidEvidenceEmitter")
            .finish_non_exhaustive()
    }
}

pub struct InMemoryWaydroidEvidenceEmitter {
    pub chain: Mutex<ReceiptChain>,
}

impl InMemoryWaydroidEvidenceEmitter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain: Mutex::new(ReceiptChain::new()),
        }
    }
}

impl Default for InMemoryWaydroidEvidenceEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl WaydroidEvidenceEmitter for InMemoryWaydroidEvidenceEmitter {
    fn emit(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<EvidenceReceipt, WaydroidError> {
        let subject = String::from("aios-waydroid");

        let builder = ReceiptBuilder::new(record_type, RetentionClass::Standard24M, subject)
            .with_payload(payload);

        let previous = {
            let chain = self.chain.lock().map_err(|e| {
                WaydroidError::waydroid_not_found(format!("chain lock poisoned: {e}"))
            })?;
            chain.receipts().last().cloned()
        };

        let receipt = builder.seal(previous.as_ref()).map_err(|e| {
            WaydroidError::waydroid_not_found(format!("evidence build failed: {e}"))
        })?;

        let mut chain = self
            .chain
            .lock()
            .map_err(|e| WaydroidError::waydroid_not_found(format!("chain lock poisoned: {e}")))?;

        chain
            .append(receipt.clone())
            .map_err(|e| WaydroidError::waydroid_not_found(format!("chain append failed: {e}")))?;

        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitter_creates_and_appends_receipt() {
        let emitter = InMemoryWaydroidEvidenceEmitter::new();
        let payload = serde_json::json!({"container_id": "wdrd_01ABCDEF", "action": "init"});
        let result = emitter.emit(RecordType::ActionReceived, payload);
        assert!(result.is_ok());
        let receipt = result.expect("emit");
        assert_eq!(receipt.record_type(), RecordType::ActionReceived);
    }

    #[test]
    fn emitter_chain_grows() {
        let emitter = InMemoryWaydroidEvidenceEmitter::new();

        let r1 = emitter
            .emit(
                RecordType::ActionReceived,
                serde_json::json!({"app": "com.example.one"}),
            )
            .expect("emit 1");
        let r2 = emitter
            .emit(
                RecordType::ActionReceived,
                serde_json::json!({"app": "com.example.two"}),
            )
            .expect("emit 2");

        assert_ne!(r1.receipt_id(), r2.receipt_id());
        let chain = emitter.chain.lock().expect("lock");
        assert_eq!(chain.receipts().len(), 2);
    }
}
