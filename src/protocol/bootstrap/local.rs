//! Local Bootstrap.
//!
//! Handles face-to-face group joining or creation, typically via QR codes or local network.
//!
//! # Whitepaper Compliance
//! - Section 7.2: Face-to-face 20s group joining (30s Noise XX).

use crate::protocol::ProtocolError;
use zeroize::Zeroizing;

/// Configuration for local bootstrap.
pub struct LocalBootstrapConfig {
    /// Timeout for the handshake in seconds.
    pub timeout_seconds: u64,
}

impl Default for LocalBootstrapConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 20,
        }
    }
}

/// Manages the local bootstrap session.
pub struct LocalBootstrapSession {
    _config: LocalBootstrapConfig,
    /// Ephemeral session key for the handshake.
    session_key: Zeroizing<[u8; 32]>,
}

impl LocalBootstrapSession {
    /// Creates a new local bootstrap session.
    pub fn new(config: LocalBootstrapConfig) -> Self {
        Self {
            _config: config,
            session_key: Zeroizing::new([0u8; 32]), // In real impl, generate random
        }
    }

    /// Generates the payload to be shared (e.g., via QR code).
    pub fn generate_payload(&self) -> Vec<u8> {
        // Placeholder: Protocol version + Ephemeral Public Key
        let mut payload = Vec::new();
        payload.push(1); // Version
        payload.extend_from_slice(&*self.session_key); // In real impl, public key
        payload
    }

    /// Processes a received payload from a peer.
    pub fn process_payload(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        if payload.len() < 2 {
            return Err(ProtocolError::AuthenticationFailed);
        }
        // Verify version
        if payload[0] != 1 {
             return Err(ProtocolError::AuthenticationFailed);
        }
        // Process key...
        Ok(())
    }
}
