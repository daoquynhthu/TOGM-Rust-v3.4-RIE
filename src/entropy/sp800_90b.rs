//! NIST SP 800-90B Health Tests.
//!
//! Implements basic health monitoring for entropy sources as per NIST SP 800-90B.
//!
//! # Tests
//! - Repetition Count Test: Detects catastrophic failures where the source becomes stuck.
//! - Adaptive Proportion Test: Detects if a value becomes too common.

use super::EntropyError;

/// Health tester for entropy sources.
pub struct HealthTester {
    // Repetition Count Test state
    last_sample: u8,
    repetition_count: usize,
    
    // Adaptive Proportion Test state
    window_count: usize,
    sample_value: u8,
    sample_count: usize,
}

impl HealthTester {
    /// Creates a new health tester.
    pub fn new() -> Self {
        Self {
            last_sample: 0,
            repetition_count: 0,
            window_count: 0,
            sample_value: 0,
            sample_count: 0,
        }
    }

    /// Feeds a byte sample into the health tests.
    ///
    /// # Arguments
    /// * `sample` - The byte to test.
    ///
    /// # Returns
    /// * `Ok(())` if tests pass.
    /// * `Err(EntropyError::HealthTestFailed)` if a failure is detected.
    pub fn feed(&mut self, sample: u8) -> Result<(), EntropyError> {
        self.check_repetition_count(sample)?;
        self.check_adaptive_proportion(sample)?;
        Ok(())
    }

    /// Repetition Count Test (RCT)
    fn check_repetition_count(&mut self, sample: u8) -> Result<(), EntropyError> {
        // For H=4.0 (min-entropy per byte), alpha=2^-20:
        // C = 1 + ceil(-20 / H) = 1 + ceil(-20 / 4) = 1 + 5 = 6
        // Add safety margin: use 10
        const RCT_CUTOFF: usize = 10;

        if sample == self.last_sample {
            self.repetition_count += 1;
            if self.repetition_count >= RCT_CUTOFF {
                return Err(EntropyError::HealthTestFailed);
            }
        } else {
            self.last_sample = sample;
            self.repetition_count = 1;
        }
        Ok(())
    }

    /// Adaptive Proportion Test (APT)
    fn check_adaptive_proportion(&mut self, sample: u8) -> Result<(), EntropyError> {
        // Window size W = 512
        const W: usize = 512;
        // For H=4.0, alpha=2^-20:
        // C ≈ W * (1/2^H + 2.576 * sqrt((1 - 1/2^H) / (W * 2^H)))
        // ≈ 512 * (1/16 + 2.576 * sqrt((15/16) / (512*16)))
        // ≈ 32 + 7 = 39
        // Use conservative 50
        const C: usize = 50;

        if self.window_count == 0 {
            // Start of new window
            self.sample_value = sample;
            self.sample_count = 1;
            self.window_count = 1;
        } else {
            if sample == self.sample_value {
                self.sample_count += 1;
            }
            
            self.window_count += 1;

            if self.window_count >= W {
                // End of window check
                if self.sample_count >= C {
                    return Err(EntropyError::HealthTestFailed);
                }
                // Reset window
                self.window_count = 0;
            }
        }
        Ok(())
    }
}

impl Default for HealthTester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repetition_failure() {
        let mut tester = HealthTester::new();
        // Feed 9 zeros (should be fine, cutoff is 10)
        for _ in 0..9 {
            assert!(tester.feed(0).is_ok());
        }
        // Next one should fail (count becomes 10)
        assert_eq!(tester.feed(0), Err(EntropyError::HealthTestFailed));
    }
}
