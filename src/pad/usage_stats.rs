//! Pad Usage Statistics and Enforcement.
//!
//! This module tracks the consumption of the Master Pad to ensure that
//! key material is strictly "One-Time". It prevents reuse of OTP bytes
//! by maintaining a monotonic counter of used bytes.
//!
//! # Security
//! - **Monotonicity**: The `used_bytes` counter must never decrease (except on reset/rotation).
//! - **Bounds Checking**: strictly enforces `used_bytes <= total_capacity`.
//!
//! # Whitepaper Compliance
//! - Section 3: Usage Tracking.

use super::PadError;

/// Tracks usage of the Master Pad.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageTracker {
    /// Total capacity of the pad in bytes.
    pub total_capacity: u64,
    /// Number of bytes already consumed.
    pub used_bytes: u64,
}

impl UsageTracker {
    /// Creates a new usage tracker with a specific capacity.
    pub fn new(total_capacity: u64) -> Self {
        Self {
            total_capacity,
            used_bytes: 0,
        }
    }

    /// Returns the number of available bytes.
    pub fn available(&self) -> u64 {
        self.total_capacity.saturating_sub(self.used_bytes)
    }

    /// Attempts to reserve `amount` bytes.
    ///
    /// If successful, advances the `used_bytes` counter and returns the *start* offset
    /// for the reserved chunk.
    ///
    /// # Errors
    /// Returns `PadError::Exhausted` if there are not enough bytes remaining.
    pub fn consume(&mut self, amount: u64) -> Result<u64, PadError> {
        if amount == 0 {
            return Ok(self.used_bytes);
        }

        let new_usage = self.used_bytes.checked_add(amount).ok_or(PadError::Exhausted)?;

        if new_usage > self.total_capacity {
            return Err(PadError::Exhausted);
        }

        let start_offset = self.used_bytes;
        self.used_bytes = new_usage;

        Ok(start_offset)
    }

    /// Resets usage (e.g., after pad rotation).
    ///
    /// # Safety
    /// This should only be called when the underlying pad material has been strictly
    /// replaced or rotated.
    pub fn reset(&mut self, new_capacity: u64) {
        self.total_capacity = new_capacity;
        self.used_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_basic() {
        let mut tracker = UsageTracker::new(100);
        assert_eq!(tracker.available(), 100);

        // Consume 10 bytes
        let offset = tracker.consume(10).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(tracker.used_bytes, 10);
        assert_eq!(tracker.available(), 90);

        // Consume 20 more
        let offset = tracker.consume(20).unwrap();
        assert_eq!(offset, 10);
        assert_eq!(tracker.used_bytes, 30);
        assert_eq!(tracker.available(), 70);
    }

    #[test]
    fn test_tracker_exhaustion() {
        let mut tracker = UsageTracker::new(50);
        
        // Consume all
        tracker.consume(50).unwrap();
        assert_eq!(tracker.available(), 0);

        // Try consume more
        assert_eq!(tracker.consume(1), Err(PadError::Exhausted));
    }

    #[test]
    fn test_tracker_partial_exhaustion() {
        let mut tracker = UsageTracker::new(50);
        tracker.consume(40).unwrap();
        
        // Try consume 11 (only 10 left)
        assert_eq!(tracker.consume(11), Err(PadError::Exhausted));
        
        // State should remain unchanged
        assert_eq!(tracker.used_bytes, 40);
    }
}
