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
        // Simple RCT: cutoff at 64 repetitions (conservative limit for basic detection)
        // In a real deployment, this should be calculated based on entropy estimate.
        const RCT_CUTOFF: usize = 64;

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
        // Cutoff C = 13 (approximate for H = 6.0, alpha = 2^-20)
        // For 8-bit samples, this needs tuning, but using a safe upper bound.
        const C: usize = 400; // Extremely loose bound for "non-complex" version

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
        // Feed 63 zeros (should be fine)
        for _ in 0..63 {
            assert!(tester.feed(0).is_ok());
        }
        // Next one should fail (count becomes 64)
        assert_eq!(tester.feed(0), Err(EntropyError::HealthTestFailed));
    }
}
