//! Device Roster.
//!
//! Maintains the list of authorized devices for a user.

use crate::protocol::ProtocolError;

/// Manages the device roster.
pub struct DeviceRoster;

impl DeviceRoster {
    /// Retrieves the list of devices.
    pub fn get_devices() -> Result<(), ProtocolError> {
        Err(ProtocolError::Unimplemented)
    }
}
