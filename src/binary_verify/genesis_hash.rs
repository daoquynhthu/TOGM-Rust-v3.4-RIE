use super::VerificationError;
use blake3::Hasher;

pub struct GenesisHash {
    expected_hash: [u8; 32],
}

impl GenesisHash {
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self { expected_hash }
    }

    pub fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        if *hash.as_bytes() == self.expected_hash {
            Ok(())
        } else {
            Err(VerificationError::HashMismatch)
        }
    }
}
