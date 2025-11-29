//! Member Extension Protocol.
//!
//! Handles the addition of a new member to an existing group using Proactive Secret Sharing (PSS).
//!
//! # Whitepaper Compliance
//! - Section 6: 30s join new member.

use crate::protocol::ProtocolError;

/// Configuration for member extension.
pub struct MemberExtensionConfig {
    /// Timeout for the extension process in seconds.
    pub timeout_seconds: u64,
}

impl Default for MemberExtensionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
        }
    }
}

/// Orchestrates the protocol to add a new member.
pub struct MemberExtensionProtocol {
    _config: MemberExtensionConfig,
    _is_initiator: bool,
}

impl MemberExtensionProtocol {
    /// Creates a new member extension protocol instance.
    pub fn new(config: MemberExtensionConfig, is_initiator: bool) -> Self {
        Self {
            _config: config,
            _is_initiator: is_initiator,
        }
    }

    /// Starts the extension process.
    pub fn start(&self) -> Result<(), ProtocolError> {
        // In a real implementation, this would trigger the MPC PSS flow.
        Err(ProtocolError::Unimplemented)
    }
}
