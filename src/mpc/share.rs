//! Secret Share Definition.
//!
//! A share is a point $(x, y)$ on the polynomial used to hide the secret.
//! - $x$ (identifier): A non-zero byte unique to each participant.
//! - $y$ (value): The evaluation of the polynomial at $x$.
//!
//! # Security
//! - Implements `Zeroize` and `ZeroizeOnDrop` to wipe sensitive data from memory.
//! - `Debug` implementation redacts the actual value.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};
use core::fmt;
use super::MpcError;

/// A share of a secret.
///
/// Contains the x-coordinate (identifier) and the y-coordinate (value).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// The x-coordinate (1..=255).
    /// Public information (who owns the share).
    #[zeroize(skip)]
    pub identifier: u8,
    
    /// The y-coordinates (one per byte of the secret).
    /// Highly sensitive information.
    pub value: Vec<u8>,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("identifier", &self.identifier)
            .field("length", &self.value.len())
            .field("value", &"***SENSITIVE***")
            .finish()
    }
}

impl Share {
    /// Creates a new share with validation.
    ///
    /// # Arguments
    /// * `identifier` - The x-coordinate (must be non-zero).
    /// * `value` - The y-coordinate vector (must not be empty).
    ///
    /// # Returns
    /// * `Ok(Share)` if valid.
    /// * `Err(MpcError)` if invalid.
    pub fn new(identifier: u8, value: Vec<u8>) -> Result<Self, MpcError> {
        if identifier == 0 {
            return Err(MpcError::InvalidShareIndex);
        }
        if value.is_empty() {
            return Err(MpcError::EmptyShare);
        }
        Ok(Self { identifier, value })
    }

    /// Returns a reference to the value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let s = Share::new(1, alloc::vec![10, 20]).unwrap();
        assert_eq!(s.identifier, 1);
        assert_eq!(s.value, &[10, 20]);
    }

    #[test]
    fn test_share_validation() {
        assert_eq!(Share::new(0, alloc::vec![1]), Err(MpcError::InvalidShareIndex));
        assert_eq!(Share::new(1, alloc::vec![]), Err(MpcError::EmptyShare));
    }

    #[test]
    fn test_debug_redaction() {
        let s = Share::new(5, alloc::vec![0xFF; 32]).unwrap();
        let debug_str = alloc::format!("{:?}", s);
        assert!(debug_str.contains("identifier: 5"));
        assert!(debug_str.contains("length: 32"));
        assert!(debug_str.contains("***SENSITIVE***"));
        assert!(!debug_str.contains("255")); // 0xFF shouldn't appear
    }
}
