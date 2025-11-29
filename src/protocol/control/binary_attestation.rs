//! Distance-Bounding Authentication Protocol (DBAP).
//! 
//! Used for physical proximity verification during group formation or maintenance.
//! Implements a simplified challenge-response mechanism compliant with TOGM Whitepaper Section 8.

use alloc::vec::Vec;
use crate::protocol::ProtocolError;
use crate::entropy::EntropySource;

/// DBAP Session State.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbapState {
    /// Initial state.
    Idle,
    /// Verifier has sent a challenge, waiting for response.
    ChallengeSent {
        nonce: [u8; 32],
        #[cfg(feature = "std")]
        timestamp: std::time::Instant,
    },
    /// Prover has received a challenge, ready to respond.
    ChallengeReceived {
        nonce: [u8; 32],
    },
    /// Verification successful.
    Verified,
    /// Verification failed (timeout or invalid response).
    Failed,
}

/// Handles binary attestation logic.
pub struct BinaryAttestation {
    state: DbapState,
    max_rtt_millis: u64,
}

impl BinaryAttestation {
    /// Creates a new DBAP session.
    /// 
    /// # Arguments
    /// * `max_rtt_millis` - Maximum allowed Round Trip Time in milliseconds (e.g., 200ms for BLE).
    pub fn new(max_rtt_millis: u64) -> Self {
        Self {
            state: DbapState::Idle,
            max_rtt_millis,
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> &DbapState {
        &self.state
    }

    /// Initiates the DBAP as a Verifier.
    /// Generates a random challenge nonce.
    pub fn initiate<R: EntropySource>(&mut self, rng: &mut R) -> Result<Vec<u8>, ProtocolError> {
        if self.state != DbapState::Idle {
            return Err(ProtocolError::InvalidState);
        }

        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).map_err(|_| ProtocolError::CryptoError)?;

        self.state = DbapState::ChallengeSent {
            nonce,
            #[cfg(feature = "std")]
            timestamp: std::time::Instant::now(),
        };

        Ok(nonce.to_vec())
    }

    /// Handles a received challenge as a Prover.
    /// Returns the response (e.g., HMAC(session_key, nonce)).
    pub fn handle_challenge(&mut self, challenge: &[u8], session_key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if self.state != DbapState::Idle {
            return Err(ProtocolError::InvalidState);
        }
        if challenge.len() != 32 {
            return Err(ProtocolError::InvalidPayload);
        }

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(challenge);

        self.state = DbapState::ChallengeReceived { nonce };

        // Response = BLAKE3_Keyed(SessionKey, Nonce)
        // Note: SessionKey should be 32 bytes for BLAKE3 keyed mode.
        // If not, we should hash it first or use derive_key.
        // Assuming 32 bytes for simplicity here, or we use KDF.
        
        let mut key_bytes = [0u8; 32];
        if session_key.len() == 32 {
            key_bytes.copy_from_slice(session_key);
        } else {
            // If key is not 32 bytes, derive a 32-byte key
             let mut hasher = blake3::Hasher::new_derive_key("TOGM_DBAP_KEY");
             hasher.update(session_key);
             key_bytes = hasher.finalize().into();
        }

        let response = blake3::Hasher::new_keyed(&key_bytes)
            .update(&nonce)
            .finalize();
            
        Ok(response.as_bytes().to_vec())
    }

    /// Verifies the response as a Verifier.
    pub fn verify_response(&mut self, response: &[u8], session_key: &[u8]) -> Result<(), ProtocolError> {
        match &self.state {
            DbapState::ChallengeSent { nonce, .. } => {
                #[cfg(feature = "std")]
                {
                    // Check RTT
                    match &self.state {
                        DbapState::ChallengeSent { timestamp, .. } => {
                             if timestamp.elapsed().as_millis() as u64 > self.max_rtt_millis {
                                 self.state = DbapState::Failed;
                                 return Err(ProtocolError::Timeout);
                             }
                        }
                        _ => {}
                    }
                }

                // Verify Content
                let mut key_bytes = [0u8; 32];
                if session_key.len() == 32 {
                    key_bytes.copy_from_slice(session_key);
                } else {
                     let mut hasher = blake3::Hasher::new_derive_key("TOGM_DBAP_KEY");
                     hasher.update(session_key);
                     key_bytes = hasher.finalize().into();
                }

                let expected = blake3::Hasher::new_keyed(&key_bytes)
                    .update(nonce)
                    .finalize();
                
                // Constant-time comparison
                if !constant_time_eq(response, expected.as_bytes()) {
                    self.state = DbapState::Failed;
                    return Err(ProtocolError::AuthenticationFailed);
                }

                self.state = DbapState::Verified;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidState),
        }
    }
    
    /// Resets the session.
    pub fn reset(&mut self) {
        self.state = DbapState::Idle;
    }
}

// Constant-time comparison helper
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct MockEntropy;
    impl EntropySource for MockEntropy {
        fn name(&self) -> &'static str { "Mock" }
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), crate::entropy::EntropyError> {
            for (i, b) in dest.iter_mut().enumerate() { *b = i as u8; }
            Ok(())
        }
        fn entropy_estimate(&self) -> f64 { 1.0 }
    }

    #[test]
    fn test_dbap_flow() {
        let mut verifier = BinaryAttestation::new(1000);
        let mut prover = BinaryAttestation::new(1000);
        let mut rng = MockEntropy;
        let session_key = b"test_session_key_32_bytes_needed"; // 32 bytes

        // 1. Verifier initiates
        let challenge = verifier.initiate(&mut rng).unwrap();
        assert!(matches!(verifier.state(), DbapState::ChallengeSent { .. }));

        // 2. Prover handles challenge
        let response = prover.handle_challenge(&challenge, session_key).unwrap();
        assert!(matches!(prover.state(), DbapState::ChallengeReceived { .. }));

        // 3. Verifier verifies response
        verifier.verify_response(&response, session_key).unwrap();
        assert_eq!(verifier.state(), &DbapState::Verified);
    }
    
    #[test]
    fn test_dbap_invalid_response() {
        let mut verifier = BinaryAttestation::new(1000);
        let mut rng = MockEntropy;
        verifier.initiate(&mut rng).unwrap();
        let session_key = b"test_session_key_32_bytes_needed";
        
        let bad_response = vec![0u8; 32];
        assert_eq!(verifier.verify_response(&bad_response, session_key), Err(ProtocolError::AuthenticationFailed));
        assert_eq!(verifier.state(), &DbapState::Failed);
    }
    
    #[test]
    fn test_dbap_wrong_key() {
        let mut verifier = BinaryAttestation::new(1000);
        let mut prover = BinaryAttestation::new(1000);
        let mut rng = MockEntropy;
        let session_key = b"test_session_key_32_bytes_needed";
        let wrong_key = b"wrong_session_key_32_bytes_needed";

        let challenge = verifier.initiate(&mut rng).unwrap();
        let response = prover.handle_challenge(&challenge, wrong_key).unwrap();
        
        assert_eq!(verifier.verify_response(&response, session_key), Err(ProtocolError::AuthenticationFailed));
    }
}
