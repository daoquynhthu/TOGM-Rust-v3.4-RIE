//! Threshold Signing.
//!
//! Implements threshold signature generation for group authentication.

use crate::protocol::ProtocolError;

/// Handles threshold signing operations.
pub struct ThresholdSigner;

impl ThresholdSigner {
    /// Generates a signature share.
    pub fn sign() -> Result<(), ProtocolError> {
        Err(ProtocolError::Unimplemented)
    }
}
