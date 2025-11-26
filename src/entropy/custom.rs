//! Custom User-Provided Entropy Source.
//!
//! Allows injecting entropy from external events (e.g., UI interactions, network packets).

extern crate alloc;
use alloc::vec::Vec;
use super::{EntropyError, EntropySource};

/// Source that buffers user-injected entropy.
pub struct CustomSource {
    buffer: Vec<u8>,
}

impl CustomSource {
    /// Creates a new empty CustomSource.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Add entropy bytes to the pool.
    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }
}

impl Default for CustomSource {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for CustomSource {
    fn name(&self) -> &'static str {
        "CustomInput"
    }

    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        if self.buffer.len() < dest.len() {
            return Err(EntropyError::Exhausted);
        }
        
        // Drain required bytes
        let drained: Vec<u8> = self.buffer.drain(0..dest.len()).collect();
        dest.copy_from_slice(&drained);
        Ok(())
    }

    fn entropy_estimate(&self) -> f64 {
        // Conservative estimate: assume 2.0 bits of entropy per byte if not specified
        // Warning: User input entropy quality is unknown.
        2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_source() {
        let mut source = CustomSource::new();
        source.add_bytes(&[0x01, 0x02, 0x03, 0x04]);

        let mut buf = [0u8; 2];
        assert!(source.fill(&mut buf).is_ok());
        assert_eq!(buf, [0x01, 0x02]);

        assert!(source.fill(&mut buf).is_ok());
        assert_eq!(buf, [0x03, 0x04]);

        assert_eq!(source.fill(&mut buf), Err(EntropyError::Exhausted));
    }
}
