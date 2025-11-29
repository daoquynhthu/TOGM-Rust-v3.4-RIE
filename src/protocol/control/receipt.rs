//! Receipt Management.
//!
//! Handles delivery and read receipts for messages.

use crate::protocol::ProtocolError;

/// Manages message receipts.
pub struct ReceiptManager;

impl ReceiptManager {
    /// Sends a receipt for a received message.
    pub fn send_receipt() -> Result<(), ProtocolError> {
        Err(ProtocolError::Unimplemented)
    }
}
