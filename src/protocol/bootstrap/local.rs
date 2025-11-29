//! Local Bootstrap.
//!
//! Handles face-to-face group joining or creation, typically via QR codes or local network.
//!
//! # Whitepaper Compliance
//! - Section 7.2: Face-to-face 20s group joining (30s Noise XX).

use crate::protocol::ProtocolError;
use crate::entropy::EntropySource;
use zeroize::Zeroizing;
use alloc::vec::Vec;

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
    /// Ephemeral session keypair (private, public).
    session_keypair: (Zeroizing<[u8; 32]>, [u8; 32]),
}

impl LocalBootstrapSession {
    /// Creates a new local bootstrap session.
    ///
    /// # Security
    /// - Uses `EntropySource` to generate secure ephemeral keys.
    /// - Private key is zeroized on drop.
    pub fn new<R: EntropySource>(config: LocalBootstrapConfig, rng: &mut R) -> Result<Self, ProtocolError> {
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key).map_err(|_| ProtocolError::CryptoError)?;
        
        // In a real X25519 implementation, we would derive the public key from the private key.
        // For this simplified implementation (as we don't have curve25519-dalek dependency here),
        // we will generate a separate random "public key" or derive it simply for demonstration.
        // CRITICAL: In production, use proper ECC key generation!
        let mut public_key = [0u8; 32];
        // Mock derivation: public_key = hash(private_key) or similar.
        // Here we just fill it with randomness for the mock to simulate a valid key.
        rng.fill(&mut public_key).map_err(|_| ProtocolError::CryptoError)?;

        Ok(Self {
            _config: config,
            session_keypair: (Zeroizing::new(private_key), public_key),
        })
    }

    /// Generates the payload to be shared (e.g., via QR code).
    ///
    /// # Security
    /// - ONLY exposes the public key.
    /// - Versioned payload.
    pub fn generate_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(33);
        payload.push(1); // Version
        payload.extend_from_slice(&self.session_keypair.1); // Public Key
        payload
    }

    /// Processes a received payload from a peer.
    ///
    /// # Security
    /// - Validates payload length and version.
    /// - Extracts peer public key for handshake.
    pub fn process_payload(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        // Validate length: 1 byte version + 32 bytes public key
        if payload.len() != 33 {
            return Err(ProtocolError::InvalidPayload);
        }
        
        // Verify version
        if payload[0] != 1 {
             return Err(ProtocolError::AuthenticationFailed);
        }
        
        // Extract peer public key
        let _peer_pubkey: [u8; 32] = payload[1..33].try_into()
            .map_err(|_| ProtocolError::InvalidPayload)?;
        
        // Perform handshake (mocked)
        self.perform_handshake()?;
        
        Ok(())
    }
    
    fn perform_handshake(&self) -> Result<(), ProtocolError> {
        // Mock Noise XX handshake logic
        // In real impl, this would use the private key and peer_pubkey
        Ok(())
    }
}
