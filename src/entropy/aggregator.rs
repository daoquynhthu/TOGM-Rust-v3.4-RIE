//! Entropy Aggregator.
//!
//! Combines multiple entropy sources into a unified stream.

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use zeroize::Zeroizing;
use super::{EntropySource, EntropyError};

/// Aggregator that collects from multiple sources.
pub struct EntropyAggregator {
    sources: Vec<Box<dyn EntropySource + Send + Sync>>,
}

impl EntropyAggregator {
    /// Creates a new empty aggregator.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Adds a source to the aggregator.
    pub fn add_source<S>(&mut self, source: S)
    where
        S: EntropySource + Send + Sync + 'static,
    {
        self.sources.push(Box::new(source));
    }

    /// Fills the destination buffer by collecting from all sources and XORing the results.
    ///
    /// This ensures that if any single source is good, the result is good (assuming independent sources).
    ///
    /// This implementation attempts to be constant-time regarding the success/failure of individual sources.
    /// It includes retry logic to ensure robustness against transient failures.
    pub fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        if self.sources.is_empty() {
            return Err(EntropyError::InitFailed);
        }

        const MAX_RETRIES: usize = 5;
        let mut retry_count = 0;

        loop {
            // Initialize dest with zeros so we can XOR into it
            for b in dest.iter_mut() {
                *b = 0;
            }

            let mut temp_buf = Zeroizing::new(alloc::vec![0u8; dest.len()]);
            let mut any_success = 0u8;

            for source in &mut self.sources {
                // Always fill, always XOR, use mask to handle failures
                let result = source.fill(&mut temp_buf);
                let success_mask = (result.is_ok() as u8).wrapping_neg(); // 0xFF or 0x00
                any_success |= success_mask;
                
                // XOR into dest (always execute, mask handles failures)
                for (d, s) in dest.iter_mut().zip(temp_buf.iter()) {
                    *d ^= *s & success_mask;
                }
                
                // Clear temp buffer for next source (prevent data leakage between sources)
                for b in temp_buf.iter_mut() {
                    *b = 0;
                }
            }

            if any_success != 0 {
                return Ok(());
            }

            retry_count += 1;
            if retry_count >= MAX_RETRIES {
                return Err(EntropyError::CollectionFailed);
            }
            
            // Hint to CPU that we are in a spin-wait loop
            core::hint::spin_loop();
        }
    }
}

impl Default for EntropyAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for EntropyAggregator {
    fn name(&self) -> &'static str {
        "Aggregator"
    }

    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        self.fill(dest)
    }

    fn entropy_estimate(&self) -> f64 {
        let sum: f64 = self.sources.iter().map(|s| s.entropy_estimate()).sum();
        sum.min(8.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::custom::CustomSource;

    #[test]
    fn test_aggregator_mixing() {
        let mut agg = EntropyAggregator::new();
        
        let mut s1 = CustomSource::new();
        s1.add_bytes(&[0xAA, 0xAA]);
        agg.add_source(s1);

        let mut s2 = CustomSource::new();
        s2.add_bytes(&[0x55, 0x55]);
        agg.add_source(s2);

        let mut buf = [0u8; 2];
        assert!(agg.fill(&mut buf).is_ok());
        
        // AA ^ 55 = FF
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn test_aggregator_partial_failure() {
        let mut agg = EntropyAggregator::new();
        
        let s1 = CustomSource::new();
        // Empty source, will fail to fill
        agg.add_source(s1);

        let mut s2 = CustomSource::new();
        s2.add_bytes(&[0x01, 0x02]);
        agg.add_source(s2);

        let mut buf = [0u8; 2];
        assert!(agg.fill(&mut buf).is_ok());
        
        // 00 ^ 0102 = 0102
        assert_eq!(buf, [0x01, 0x02]);
    }
}
