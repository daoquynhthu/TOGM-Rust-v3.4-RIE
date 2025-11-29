//! Device Linking.
//!
//! Protocol for linking a new device to an existing identity.

use crate::protocol::ProtocolError;

/// Handles device linking logic.
pub struct DeviceLinker;

impl DeviceLinker {
    /// Initiates the device linking process.
    pub fn link_device() -> Result<(), ProtocolError> {
        Err(ProtocolError::Unimplemented)
    }
}
