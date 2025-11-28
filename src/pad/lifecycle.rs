//! Master Pad Lifecycle Management.
//!
//! This module handles the creation, storage, rotation, and access control for the Master Pad.
//! It serves as the primary interface for interacting with the OTP key material.
//!
//! # Security
//! - **Zeroization**: All key material is stored in `Zeroizing` containers.
//! - **Usage Enforcement**: All access is mediated by `UsageTracker`.
//! - **Rotation**: Securely burns old material before replacement.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use zeroize::Zeroizing;
use crate::entropy::EntropySource;
use super::{PadError, usage_stats::UsageTracker, burn::burn_slice};

/// Represents the Master Pad containing the OTP key material.
pub struct MasterPad {
    /// The actual key material, protected by Zeroizing.
    data: Zeroizing<Vec<u8>>,
    /// Tracks usage to prevent key reuse.
    usage: UsageTracker,
    /// Unique identifier for this pad instance (for auditing/integrity).
    id: [u8; 16],
}

impl MasterPad {
    /// Creates a new Master Pad with the specified size, seeded from the provided entropy source.
    ///
    /// # Arguments
    /// * `size` - The size of the pad in bytes.
    /// * `entropy` - A source of cryptographically secure randomness.
    pub fn new(size: usize, entropy: &mut dyn EntropySource) -> Result<Self, PadError> {
        // Allocate zeroed memory
        let mut data = Zeroizing::new(vec![0u8; size]);
        
        // Fill with high-quality entropy
        entropy.fill(&mut data).map_err(|_| PadError::CryptoError)?;
        
        // Generate a random ID
        let mut id = [0u8; 16];
        entropy.fill(&mut id).map_err(|_| PadError::CryptoError)?;

        Ok(Self {
            data,
            usage: UsageTracker::new(size as u64),
            id,
        })
    }

    /// Reserves and returns a slice of the pad for encryption.
    ///
    /// This updates the internal usage counter.
    ///
    /// # Errors
    /// * `PadError::Exhausted` if there are not enough bytes remaining.
    pub fn get_slice(&mut self, len: usize) -> Result<&[u8], PadError> {
        let offset = self.usage.consume(len as u64)?;
        let start = offset as usize;
        let end = start + len;
        
        // Defense-in-depth bounds check
        if end > self.data.len() {
             return Err(PadError::OutOfBounds);
        }

        Ok(&self.data[start..end])
    }
    
    /// Rotates the pad by overwriting it with new random data.
    ///
    /// This securely burns the old data and resets the usage counter.
    pub fn rotate(&mut self, entropy: &mut dyn EntropySource) -> Result<(), PadError> {
        // Securely burn the old data first
        burn_slice(&mut self.data);
        
        // Fill with new entropy
        entropy.fill(&mut self.data).map_err(|_| PadError::CryptoError)?;
        
        // Generate new ID
        entropy.fill(&mut self.id).map_err(|_| PadError::CryptoError)?;
        
        // Reset usage tracker
        self.usage.reset(self.data.len() as u64);
        
        Ok(())
    }

    /// Returns the unique ID of the pad.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
    
    /// Returns the remaining capacity in bytes.
    pub fn remaining(&self) -> u64 {
        self.usage.available()
    }
    
    /// Returns the total capacity in bytes.
    pub fn total_capacity(&self) -> u64 {
        self.usage.total_capacity
    }
}

#[cfg(feature = "std")]
impl MasterPad {
    /// Loads a pad from a file.
    ///
    /// The file format is: `[ID (16 bytes)] [Used Bytes (8 bytes, LE)] [Data (...)]`
    ///
    /// # Security Warning
    /// This method assumes the file is trusted or stored on an encrypted filesystem.
    /// For untrusted storage, use `share_encrypt` to encrypt shares instead.
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, PadError> {
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(path).map_err(|_| PadError::StorageError)?;
        let metadata = file.metadata().map_err(|_| PadError::StorageError)?;
        let len = metadata.len();
        
        // Minimum size: 16 (ID) + 8 (Used Bytes)
        if len < 24 {
            return Err(PadError::IntegrityFailure);
        }
        
        let data_len = (len - 24) as usize;
        
        let mut id = [0u8; 16];
        file.read_exact(&mut id).map_err(|_| PadError::StorageError)?;
        
        let mut used_bytes_buf = [0u8; 8];
        file.read_exact(&mut used_bytes_buf).map_err(|_| PadError::StorageError)?;
        let used_bytes = u64::from_le_bytes(used_bytes_buf);
        
        let mut data = Zeroizing::new(vec![0u8; data_len]);
        file.read_exact(&mut data).map_err(|_| PadError::StorageError)?;
        
        let mut usage = UsageTracker::new(data_len as u64);
        usage.used_bytes = used_bytes;
        
        // Sanity check
        if usage.used_bytes > usage.total_capacity {
            return Err(PadError::IntegrityFailure);
        }

        Ok(Self {
            data,
            usage,
            id,
        })
    }

    /// Saves the pad to a file.
    ///
    /// The file format is: `[ID (16 bytes)] [Used Bytes (8 bytes, LE)] [Data (...)]`
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), PadError> {
        use std::fs::File;
        use std::io::Write;
        
        let mut file = File::create(path).map_err(|_| PadError::StorageError)?;
        
        file.write_all(&self.id).map_err(|_| PadError::StorageError)?;
        file.write_all(&self.usage.used_bytes.to_le_bytes()).map_err(|_| PadError::StorageError)?;
        file.write_all(&self.data).map_err(|_| PadError::StorageError)?;
        
        file.sync_all().map_err(|_| PadError::StorageError)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyError;

    // Mock Entropy Source for testing
    struct MockEntropy {
        counter: u8,
    }

    impl MockEntropy {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    impl EntropySource for MockEntropy {
        fn name(&self) -> &'static str { "Mock" }
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for byte in dest.iter_mut() {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
        fn entropy_estimate(&self) -> f64 { 8.0 }
    }

    #[test]
    fn test_pad_creation() {
        let mut entropy = MockEntropy::new();
        let pad = MasterPad::new(100, &mut entropy).unwrap();
        
        assert_eq!(pad.total_capacity(), 100);
        assert_eq!(pad.remaining(), 100);
        // ID should be filled with counter (0..16)
        // Data should be filled with counter (16..116)
        
        // Verify ID is not all zeros
        assert_ne!(pad.id(), &[0u8; 16]);
    }

    #[test]
    fn test_pad_consumption() {
        let mut entropy = MockEntropy::new();
        let mut pad = MasterPad::new(100, &mut entropy).unwrap();
        
        let slice1 = pad.get_slice(10).unwrap().to_vec();
        assert_eq!(slice1.len(), 10);
        assert_eq!(pad.remaining(), 90);
        
        let slice2 = pad.get_slice(20).unwrap().to_vec();
        assert_eq!(slice2.len(), 20);
        assert_eq!(pad.remaining(), 70);
        
        // Ensure slices are different (based on our mock pattern)
        assert_ne!(slice1, slice2);
    }

    #[test]
    fn test_pad_exhaustion() {
        let mut entropy = MockEntropy::new();
        let mut pad = MasterPad::new(50, &mut entropy).unwrap();
        
        pad.get_slice(50).unwrap();
        assert_eq!(pad.remaining(), 0);
        
        let err = pad.get_slice(1);
        assert_eq!(err, Err(PadError::Exhausted));
    }

    #[test]
    fn test_pad_rotation() {
        let mut entropy = MockEntropy::new();
        let mut pad = MasterPad::new(50, &mut entropy).unwrap();
        
        let old_id = *pad.id();
        pad.get_slice(10).unwrap();
        assert_eq!(pad.remaining(), 40);
        
        pad.rotate(&mut entropy).unwrap();
        
        assert_ne!(*pad.id(), old_id);
        assert_eq!(pad.remaining(), 50); // Should be reset
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_save_load() {
        
        let mut entropy = MockEntropy::new();
        let mut pad = MasterPad::new(100, &mut entropy).unwrap();
        pad.get_slice(10).unwrap(); // Consume some bytes
        
        let dir = std::env::temp_dir();
        let path = dir.join("test_pad.bin");
        
        // Save
        pad.save_to_file(&path).unwrap();
        
        // Load
        let loaded_pad = MasterPad::load_from_file(&path).unwrap();
        
        assert_eq!(loaded_pad.id(), pad.id());
        assert_eq!(loaded_pad.total_capacity(), pad.total_capacity());
        assert_eq!(loaded_pad.remaining(), pad.remaining());
        
        // Cleanup
        let _ = std::fs::remove_file(path);
    }
}
